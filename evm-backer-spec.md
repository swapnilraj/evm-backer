# EVM Ledger Registrar Backer for KERI
### Draft Specification

---

## Abstract

This document specifies an Ethereum Virtual Machine (EVM) implementation of a KERI Ledger Registrar Backer. A ledger registrar backer is a type of KERI backer that cross-anchors a controller's key event commitments on an external shared ledger, using that ledger's total ordering and finality as a source of duplicity protection in place of a witness consensus pool.

This spec follows the ledger registrar backer model described in the KERI specification (KID0009) and Sam Smith's proposal in [decentralized-identity/keri#149](https://github.com/decentralized-identity/keri/issues/149), and is modelled on the existing Cardano backer implementation at [WebOfTrust/cardano-backer](https://github.com/WebOfTrust/cardano-backer).

---

## 1. Background

### 1.1 Backer Types in KERI

KERI's `b` field in inception and rotation events designates a set of **backers** — entities that provide secondary roots of trust for a controller's key state. The `bt` (TOAD) field specifies how many backers must acknowledge an event for the controller to be held accountable.

Two backer types exist in the KERI specification:

**Witness Backers** (currently implemented):
- Ephemeral, non-transferable AIDs; no inception event needed
- Participate in KAACE (Byzantine consensus among witnesses)
- Sign `rct` (receipt) messages with their own Ed25519 key
- Duplicity protection via witness pool consensus and first-seen policy

**Ledger Registrar Backers** (this document):
- Non-ephemeral, non-transferable AIDs; require their own inception event
- Do NOT participate in KAACE
- Cross-anchor controller key event commitments on a shared ledger
- Duplicity protection via the ledger's total ordering (impossible to present conflicting events at the same sequence number once anchored)
- The entire ledger network appears as a single backer from KERI's perspective

### 1.2 Why Ethereum

The Cardano backer (the only existing ledger backer implementation) stores KERI event bytes as Cardano transaction metadata. An Ethereum backer offers:

- A **smart contract** as the anchor point, providing a queryable on-chain state that other smart contracts can read directly — enabling on-chain vLEI credential verification without an oracle bridge
- Integration with Ethereum's DeFi and tokenization ecosystem (ERC-3643, ERC-FIX, etc.)
- L2 deployability (Arbitrum, Optimism, Base) for lower anchoring costs
- EVM equivalence across hundreds of chains

---

## 2. Backer AID

### 2.1 Key Type

The EVM backer uses an **Ed25519** signing key. This is the same key type used by standard KERI witnesses and by the Cardano backer. The same Ed25519 seed deterministically generates both:

1. The backer's KERI AID (via the standard KERI derivation)
2. The backer's Ethereum signing address (via the derivation described in §2.3)

### 2.2 Non-Ephemeral, Non-Transferable AID

Unlike witness backers (ephemeral AIDs, no inception event), the EVM backer uses a **non-ephemeral but non-transferable** AID:

- Uses a **transferable derivation code** → an inception event is required
- The inception event's `n` (next key digest) field is **empty** → rotation is impossible
- The backer's `b` (backers) field is **empty** → backers cannot have backers (prevents infinite regress)

In keripy, this is created with:

```python
hab = hby.makeHab(name=alias, transferable=False)
```

The resulting inception event:

```json
{
  "v": "KERI10JSON0000ef_",
  "t": "icp",
  "d": "<SAID>",
  "i": "<backer AID prefix>",
  "s": "0",
  "kt": "1",
  "k":  ["<Ed25519 public key, qb64>"],
  "nt": "0",
  "n":  [],
  "bt": "0",
  "b":  [],
  "c":  [],
  "a":  [
    { "d": "<SAID of EVM configuration metadata>" }
  ]
}
```

The `a` (anchors) field contains a seal whose digest is the SAID of the backer's EVM configuration metadata (see §4). This binds the ledger connection information to the backer's inception event immutably.

### 2.3 Ethereum Address Derivation

The Ethereum signing address is derived deterministically from the same salt used to generate the KERI AID, using a domain-separated derivation path. This ensures a single secret (the salt) recovers both identities:

```
KERI AID:    derive_ed25519(salt, domain="keri")   → Ed25519 keypair → KERI prefix
ETH address: derive_secp256k1(salt, domain="eth")  → secp256k1 keypair → Ethereum address
```

The domain separation prevents the same raw key material being used for two different algorithms. The Ethereum address is the `keccak256` of the secp256k1 public key, last 20 bytes, per standard Ethereum derivation.

This address is the `msg.sender` for all transactions the backer submits to the `KERIBacker` smart contract.

### 2.4 OOBI

The backer publishes an OOBI (Out-of-Band Introduction) URL so controllers and validators can resolve its AID and KEL:

```
http://<backer-host>:<port>/oobi/<backer-AID>/controller
```

Controllers include this OOBI in their inception event configuration so validators know how to contact the backer.

---

## 3. Smart Contract

The `KERIBacker` contract is the on-chain anchor point. It stores a mapping of anchored events, enforces the first-seen policy immutably, and emits events that chain crawlers can index.

### 3.1 Interface

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

interface IKERIBacker {

    /// @notice Emitted when a KERI key event is anchored on-chain.
    /// @param  prefix     Controller AID prefix (first 32 bytes of qb64, zero-padded)
    /// @param  sn         Sequence number of the anchored event
    /// @param  eventSAID  SAID (self-addressing identifier digest) of the event
    /// @param  raw        Full CESR-encoded event bytes (for reconstruction without a witness server)
    event KERIEventAnchored(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32 indexed eventSAID,
        bytes           raw
    );

    /// @notice Emitted when a duplicate event is detected at a sequence number already anchored.
    event DuplicityDetected(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32         firstSeenSAID,
        bytes32         conflictingSAID
    );

    struct AnchorRecord {
        bytes32 eventSAID;      // SAID of the anchored event
        uint64  blockNumber;    // Block at which it was anchored
        uint32  sn;             // Sequence number
        bool    exists;         // Existence flag
    }

    /// @notice Anchor a KERI key event on-chain.
    /// @dev    Enforces first-seen policy: once an event is anchored at (prefix, sn),
    ///         no subsequent call can overwrite it.
    ///         Emits DuplicityDetected if a conflicting SAID is submitted.
    ///         Only callable by the authorized backer address.
    /// @param  prefix     Controller AID prefix (bytes32)
    /// @param  sn         Event sequence number
    /// @param  eventSAID  SAID of the event being anchored
    /// @param  raw        Full CESR-encoded event bytes
    function anchorEvent(
        bytes32 prefix,
        uint64  sn,
        bytes32 eventSAID,
        bytes calldata raw
    ) external;

    /// @notice Anchor multiple events in a single transaction (gas efficient).
    function anchorBatch(Anchor[] calldata anchors) external;

    /// @notice Returns the anchor record for a given (prefix, sn) pair.
    function getAnchor(bytes32 prefix, uint64 sn)
        external view returns (AnchorRecord memory);

    /// @notice Returns true if an event with the given SAID is anchored at (prefix, sn).
    function isAnchored(bytes32 prefix, uint64 sn, bytes32 eventSAID)
        external view returns (bool);

    struct Anchor {
        bytes32 prefix;
        uint64  sn;
        bytes32 eventSAID;
        bytes   raw;
    }
}
```

### 3.2 Implementation

```solidity
contract KERIBacker is IKERIBacker {

    /// @dev The authorized backer Ethereum address (derived from backer salt, §2.3)
    address public immutable backer;

    /// @dev prefix → sn → AnchorRecord
    mapping(bytes32 => mapping(uint64 => AnchorRecord)) private _anchors;

    constructor(address _backer) {
        backer = _backer;
    }

    modifier onlyBacker() {
        require(msg.sender == backer, "KERIBacker: unauthorized");
        _;
    }

    function anchorEvent(
        bytes32 prefix,
        uint64  sn,
        bytes32 eventSAID,
        bytes calldata raw
    ) external onlyBacker {
        _anchor(prefix, sn, eventSAID, raw);
    }

    function anchorBatch(Anchor[] calldata anchors) external onlyBacker {
        for (uint256 i = 0; i < anchors.length; i++) {
            _anchor(
                anchors[i].prefix,
                anchors[i].sn,
                anchors[i].eventSAID,
                anchors[i].raw
            );
        }
    }

    function _anchor(
        bytes32 prefix,
        uint64  sn,
        bytes32 eventSAID,
        bytes calldata raw
    ) internal {
        AnchorRecord storage rec = _anchors[prefix][sn];

        if (rec.exists) {
            // First-seen policy: do not overwrite
            if (rec.eventSAID != eventSAID) {
                emit DuplicityDetected(prefix, sn, rec.eventSAID, eventSAID);
            }
            return;
        }

        // First time seen: anchor it
        rec.eventSAID   = eventSAID;
        rec.blockNumber = uint64(block.number);
        rec.sn          = uint32(sn);
        rec.exists      = true;

        emit KERIEventAnchored(prefix, sn, eventSAID, raw);
    }

    function getAnchor(bytes32 prefix, uint64 sn)
        external view returns (AnchorRecord memory)
    {
        return _anchors[prefix][sn];
    }

    function isAnchored(bytes32 prefix, uint64 sn, bytes32 eventSAID)
        external view returns (bool)
    {
        AnchorRecord storage rec = _anchors[prefix][sn];
        return rec.exists && rec.eventSAID == eventSAID;
    }
}
```

### 3.3 Prefix Encoding

KERI AID prefixes are qb64-encoded strings (e.g., `"EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"`). The contract works with `bytes32`. Conversion:

```python
import base64, struct

def prefix_to_bytes32(qb64_prefix: str) -> bytes:
    """Convert qb64 AID prefix to bytes32 for contract storage."""
    # Strip derivation code (first 1-4 chars depending on type)
    # then base64url decode and left-pad to 32 bytes
    raw = base64.urlsafe_b64decode(qb64_prefix + "==")
    return raw[:32].ljust(32, b'\x00')
```

### 3.4 SAID Encoding

KERI SAIDs are also qb64-encoded Blake3 digests. They decode to exactly 32 bytes, making direct `bytes32` storage natural.

---

## 4. Configuration Metadata

The backer's inception event anchor seal commits to a SAID of the following JSON metadata document. This document is published alongside the inception event as a CESR attachment, and stored locally by validators indexed by `(controller_prefix, backer_prefix)` — the "virtual TEL" pattern from Issue #149.

```json
{
  "v": "BACKER10JSON_",
  "d": "<SAID of this document>",
  "t": "ethereum",
  "chains": [
    {
      "name": "mainnet",
      "chainId": 1,
      "contract": "0x<KERIBacker contract address>",
      "rpc": [
        "https://eth.lava.build",
        "https://ethereum-rpc.publicnode.com"
      ],
      "confirmationDepth": 12,
      "gasPriceStrategy": "eip1559"
    },
    {
      "name": "sepolia",
      "chainId": 11155111,
      "contract": "0x<testnet contract address>",
      "rpc": ["https://sepolia.drpc.org"],
      "confirmationDepth": 6,
      "gasPriceStrategy": "eip1559"
    }
  ],
  "batchSize": 20,
  "batchIntervalSeconds": 10,
  "fundingMinimumWei": "100000000000000000"
}
```

`chains` may contain multiple networks. A validator resolves which network to query by matching the `chainId` against the chain it is operating on (or checking all listed chains).

---

## 5. Protocol

### 5.1 Overview

The EVM backer runs a standard keripy HTTP endpoint — identical to a KERI witness server. Controllers submit their key events to the backer's OOBI-resolved endpoint using the standard KERI HTTP protocol. The backer validates events using keripy's `Kevery`/`Tevery` pipeline, queues them, and submits batched Ethereum transactions to the `KERIBacker` contract.

```
Controller
    │
    │  POST /events  (CESR-encoded key event)
    ▼
EVM Backer HTTP endpoint  (standard KERI witness interface)
    │
    │  keripy Parser → Kevery / Tevery validation
    ▼
Event Queue
    │
    │  batch every N seconds or M events
    ▼
Ethereum Transaction  →  KERIBacker.anchorBatch([...])
    │
    │  wait CONFIRMATION_DEPTH blocks
    ▼
Receipt returned to controller
    │
    │  Validator queries KERIBacker.isAnchored(prefix, sn, said)
    ▼
On-chain verification (no oracle required)
```

### 5.2 Event Reception

The backer exposes a standard KERI witness HTTP interface. Key events arrive as CESR-encoded HTTP POST requests. keripy's `httping.parseCesrHttpRequest()` parses the request; the resulting message is passed to the processing pipeline.

Accepted event types: `icp`, `rot`, `ixn`, `dip`, `drt`, `vcp`, `vrt`, `iss`, `rev`.

### 5.3 Validation

The backer uses keripy's standard components:

- **`Kevery`** — validates key establishment events (`icp`, `rot`, `ixn`, `dip`, `drt`)
- **`Tevery`** — validates TEL events (`vcp`, `vrt`, `iss`, `rev`) for credential issuance/revocation
- **`Parser`** — streams events through Kevery/Tevery

Validation checks:
1. Event signature is valid (controller's current signing key)
2. Event is correctly chained (prior event digest matches)
3. Sequence number is next in order for this prefix

Events that pass validation enter the queue. Out-of-order events are held in keripy's standard escrow until predecessors arrive.

### 5.4 Endorsement Policy

Per the KERI specification (Issue #149):

> **"Backers may only endorse something previously committed to via a seal in the KEL."**

Concretely: the backer only anchors events that are themselves valid key events (i.e., events the backer has received and validated via keripy). The backer does not independently verify seals in the controller's KEL before anchoring — keripy's `Kevery` performs this validation as part of standard event processing. An event that passes keripy validation is by definition a valid commitment by the controller.

### 5.5 Queuing and Batching

The `Queuer` runs on a configurable interval (default: 10 seconds). At each tick it:

1. Drains the pending event queue up to `batchSize` events
2. Constructs an `Anchor[]` array from queued events
3. Calls `KERIBacker.anchorBatch(anchors)` in a single Ethereum transaction
4. Stores the transaction hash + pending event list in the local database

Batching amortizes the fixed per-transaction overhead (gas base cost ~21,000) across many events.

### 5.6 Transaction Submission

Transactions use EIP-1559 (type 2) fee pricing:

```python
tx = {
    "to":                   CONTRACT_ADDRESS,
    "data":                 contract.encodeABI("anchorBatch", [anchors]),
    "maxFeePerGas":         fee_oracle.max_fee(),
    "maxPriorityFeePerGas": fee_oracle.priority_fee(),
    "gas":                  estimate_gas(anchors),
    "nonce":                w3.eth.get_transaction_count(backer_address),
    "chainId":              CHAIN_ID,
}
signed = w3.eth.account.sign_transaction(tx, private_key=eth_private_key)
tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
```

### 5.7 Confirmation

The `Crawler` monitors the Ethereum chain using a polling loop against the configured RPC endpoints. For each pending transaction:

1. Call `eth_getTransactionReceipt(tx_hash)`
2. If `None` → still pending, continue polling (interval: 1 block ≈ 12 seconds)
3. If receipt returned → compute `confirmations = current_block - receipt.blockNumber`
4. If `confirmations >= CONFIRMATION_DEPTH` → mark confirmed, emit receipt
5. If `confirmations` not reached after `TIMEOUT_DEPTH` blocks → requeue events, retry with new transaction

Default values:
- `CONFIRMATION_DEPTH = 12` (≈ 2.5 minutes on mainnet; configurable)
- `TIMEOUT_DEPTH = 32` (≈ 6 minutes; if not confirmed, retry)

The Crawler also handles chain reorganizations: if a previously confirmed block number is no longer in the canonical chain (detected by `eth_getBlockByNumber` returning a different block hash), affected events are requeued.

---

## 6. Receipt

Once an event batch is confirmed on-chain, the backer sends receipts back to the controller. The receipt uses the standard KERI `rct` message format, extended with an EVM-specific attestation attachment.

### 6.1 Receipt Message

```json
{
  "v": "KERI10JSON000091_",
  "t": "rct",
  "d": "<SAID of this receipt>",
  "i": "<controller AID prefix>",
  "s": "<hex sequence number of receipted event>",
  "p": "<SAID of receipted event>"
}
```

### 6.2 EVM Attestation Attachment (CESR)

Attached to the `rct` message as a CESR attachment. This is the EVM-specific analogue of a witness Ed25519 receipt signature:

```json
{
  "t": "evm",
  "cid": 1,
  "ca":  "0x<KERIBacker contract address>",
  "tx":  "0x<transaction hash>",
  "bn":  19500000,
  "bc":  12,
  "bs":  "<backer AID prefix>"
}
```

| Field | Description |
|---|---|
| `t` | Attestation type: `"evm"` |
| `cid` | EIP-155 chain ID |
| `ca` | `KERIBacker` contract address |
| `tx` | Ethereum transaction hash containing the anchor |
| `bn` | Block number of the anchoring transaction |
| `bc` | Number of confirmations at time of receipt |
| `bs` | Backer AID prefix (to resolve backer's inception event) |

### 6.3 Validator Verification

A validator receiving this receipt:

1. Resolves `bs` (backer AID) → reads backer's inception event → extracts `chains` metadata (contract address, chain ID, RPC)
2. Calls `KERIBacker.isAnchored(prefix, sn, eventSAID)` on the specified contract → `true` = confirmed
3. Optionally fetches the transaction by `tx` hash to verify `bn` and `bc`
4. Optionally checks current confirmations: `current_block - bn >= CONFIRMATION_DEPTH`

Step 2 is a pure on-chain read. No oracle, no trust in the backer server — only the Ethereum chain.

---

## 7. keripy Integration

The EVM backer reuses keripy's entire core stack. The Ethereum-specific code is a thin layer on top.

### 7.1 Initialization (mirrors Cardano backer)

```python
from keri.app import habbing, keeping
from keri.core import eventing

def setup_evm_backer(name: str, base: str, bran: str, alias: str):
    hby = habbing.Habery(name=name, base=base, bran=bran)

    hab = hby.habByName(name=alias)
    if hab is None:
        # Creates non-transferable inception event (transferable=False → empty nxt)
        hab = hby.makeHab(name=alias, transferable=False)

    return hby, hab
```

### 7.2 Main Doers (async event loop)

Following the Cardano backer pattern exactly:

```python
doers = [
    habbing.HaberyDoer(hby=hby),          # keripy core
    backering.BackerStart(hby, hab, ...),  # EVM-specific handler
    eventing.Kevery(...),                  # key event processor
    Queuer(queue, eth_client),             # EVM batch submitter
    Crawler(eth_client, db),               # EVM confirmation monitor
]
directing.runController(doers=doers, limit=limit)
```

### 7.3 HTTP Endpoint

The backer exposes the same HTTP interface as a KERI witness. Controllers configure the backer's OOBI exactly as they would a witness OOBI. No protocol changes needed on the controller side.

---

## 8. Differences from Cardano Backer

| Aspect | Cardano Backer | EVM Backer |
|---|---|---|
| **On-chain data format** | Transaction metadata (raw CESR bytes in 64-byte chunks, label `13456`) | Smart contract storage + event logs |
| **On-chain queryability** | Requires chain indexer (Ogmios + crawler) | Direct contract call (`isAnchored`) — readable by other smart contracts |
| **Chain connection** | Blockfrost API | Web3 RPC (any standard JSON-RPC endpoint) |
| **Confirmation depth** | 16 blocks (default) | 12 blocks (default); configurable per chain |
| **Reorg handling** | Ogmios signals rollbacks explicitly | Crawler detects via block hash mismatch |
| **Address derivation** | Ed25519 seed → Cardano address (same key type) | Ed25519 seed → secp256k1 → Ethereum address (different algorithm) |
| **Transaction fees** | ADA (UTXO model) | ETH / EIP-1559 (account model) |
| **Multi-chain** | Mainnet + preprod testnet | Any EVM chain (mainnet, L2s, testnets) |
| **Smart contract** | None — metadata only | `KERIBacker.sol` — stores (prefix, sn) → (SAID, blockNumber) |
| **Composability** | Not directly readable by smart contracts | Readable by any EVM contract via `isAnchored()` |

The composability difference is the key architectural advantage of the EVM backer: because anchors live in contract storage, any smart contract (ERC-FIX token, ERC-3643 compliance module, DeFi protocol) can verify KERI key event state with a single `staticcall` — no oracle, no external dependency.

---

## 9. Deployment

### 9.1 Environment Variables

```bash
# Required
BACKER_SALT="<qb64 salt — same salt generates both KERI AID and ETH address>"
BACKER_NAME="evm-backer"
BACKER_ALIAS="evm-backer-alias"

# Storage
BACKER_STORE_DIR="/data/evm-backer/store"
BACKER_CONFIG_DIR="/data/evm-backer/config"

# Networking
BACKER_PORT=8080
BACKER_URL="http://backer.example.com:8080"

# EVM (at least one chain required)
ETH_CHAIN_ID=1
ETH_CONTRACT_ADDRESS="0x..."
ETH_RPC_URLS="https://eth.lava.build,https://ethereum-rpc.publicnode.com"
ETH_CONFIRMATION_DEPTH=12
ETH_TIMEOUT_DEPTH=32

# Optional: L2 (can run multiple chains simultaneously)
ARB_CHAIN_ID=42161
ARB_CONTRACT_ADDRESS="0x..."
ARB_RPC_URLS="https://arb1.arbitrum.io/rpc"
ARB_CONFIRMATION_DEPTH=20

# Operational
QUEUE_DURATION=10
BATCH_SIZE=20
FUNDING_MINIMUM_WEI=100000000000000000
```

### 9.2 Commands

```bash
# Show backer AID, Ethereum address, and configuration
evm-backer info

# Query whether an event is anchored on-chain
evm-backer query --prefix <controller-AID> --sn <sequence-number>

# Start the backer service
evm-backer start
```

### 9.3 Funding

The backer's Ethereum address must hold ETH to pay for anchoring transactions. Estimated costs at 30 gwei:

| Scenario | Gas | Cost (30 gwei) |
|---|---|---|
| Single event anchor | ~80,000 | ~0.0024 ETH |
| Batch of 20 events | ~300,000 | ~0.009 ETH |
| Batch of 20 on Arbitrum | ~300,000 | ~$0.03 USD |

L2 deployment (Arbitrum, Optimism, Base) reduces costs by ~100x and is recommended for production.

---

## 10. Open Questions

1. **CESR attestation type code**: The `"evm"` attestation type in §6.2 requires a new CESR code. Should this be proposed as a KERI spec extension, or handled as an implementation-specific attachment type?

2. **Ed25519 → secp256k1 derivation**: The domain-separated derivation in §2.3 (same salt → two different key types) needs to be standardised. The Cardano backer uses the same Ed25519 key for both KERI and Cardano (possible because Cardano supports Ed25519 natively). Ethereum requires secp256k1. What is the canonical derivation path?

3. **Multi-chain backer identity**: If the backer anchors on both Ethereum mainnet and Arbitrum, does it have one AID with two chain configurations in its metadata, or a separate AID per chain? Single AID with multiple `chains` entries (as specified in §4) seems simpler and consistent with the Cardano backer's single-AID approach.

4. **TOAD and mixed backer sets**: If a controller uses both witness backers and this EVM ledger backer in the same `b` list, how should TOAD be interpreted? Witnesses produce Ed25519 receipts; the EVM backer produces an EVM attestation. Should TOAD count them equivalently? Probably yes — both prove the controller committed to the event.

5. **keripy changes required**: Does keripy's `makeHab` with `transferable=False` produce exactly the inception event in §2.2? Specifically, does it omit the `n` field or set it to an empty list? And does keripy's `Kevery` correctly process events from a controller that has an EVM backer in its `b` list (i.e., does it skip trying to get an Ed25519 receipt from the EVM backer)?

---

## Appendix: Relation to ERC-FIX vLEI Integration

The EVM backer is the enabling primitive for on-chain vLEI verification in ERC-FIX tokens (see `proposal-vlei-erc-fix.md`). Specifically:

- A QVI (Qualified vLEI Issuer) configures the EVM backer as one of its KERI backers
- When the QVI issues a vLEI LE credential (anchored in its KEL via an `ixn` event), the EVM backer anchors that `ixn` event on-chain
- An ERC-FIX token's `isVleiValid()` function calls `KERIBacker.isAnchored(qviPrefix, sn, eventSAID)`
- Valid return → the credential issuance event is confirmed on Ethereum → credential is live
- The `DuplicityDetected` event on the contract is the on-chain proof that the QVI attempted to fork its key state

This replaces the oracle relay (Phase 2 of the ERC-FIX proposal) with a native KERI protocol primitive.
