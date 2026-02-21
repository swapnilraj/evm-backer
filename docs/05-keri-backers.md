# KERI Backers and Ledger Registrar Backers

## What is a Backer?

"Backer" is the general term in KERI for any entity designated in a controller's `b` field to provide a secondary source of truth about that controller's key state. Every witness is a backer, but not every backer is a witness.

The purpose of any backer is the same: **prevent equivocation** — make it impossible for a controller to show two different key states to different verifiers. Backers achieve this through different mechanisms depending on their type.

### The `b` and `bt` Fields

```json
{
  "t": "icp",
  "b":  ["<backer-1 AID>", "<backer-2 AID>", ...],
  "bt": "3"
}
```

- **`b`**: The backer set — array of backer AIDs
- **`bt`**: TOAD (Threshold of Accountable Duplicity) — minimum number of backers that must acknowledge an event for the controller to be considered accountable for it

---

## Backer Type 1: Witness (Currently Implemented)

### AID Structure
- **Ephemeral, non-transferable** AID
- The public key IS the identifier — no inception event required
- Uses dedicated derivation codes for ephemeral non-transferable identifiers

### How It Works
1. Controller publishes a key event to the witness's HTTP endpoint
2. Witness validates the event (signature, chaining)
3. Witness signs a **`rct` (receipt) message** with its own Ed25519 key
4. Witness stores the event in its KERL (Key Event Receipt Log)
5. Witness serves the KERL to validators on request
6. Multiple witnesses participate in **KAACE** (Byzantine consensus algorithm) to agree on what they've seen

### Duplicity Protection
The witness pool's consensus plus the **first-seen policy** (a witness will not receipt a conflicting event at the same sequence number once it has receipted one) makes forking the KEL detectable. A validator seeing two different receipted versions of the same event knows the controller equivocated.

### Receipt Format (`rct`)
```json
{
  "v": "KERI10JSON000091_",
  "t": "rct",
  "d": "<SAID of this receipt>",
  "i": "<controller AID>",
  "s": "<sequence number hex>",
  "p": "<SAID of receipted event>"
}
```
Coupled with an indexed Ed25519 signature from the witness's key.

---

## Backer Type 2: Ledger Registrar Backer (Specified, Partially Implemented)

Proposed by Samuel M. Smith in [decentralized-identity/keri#149](https://github.com/decentralized-identity/keri/issues/149) (2021). Supported in principle in KID0009:

> *"more sophisticated witnesses may be used such as witnesses that are oracles to a distributed consensus ledger (i.e. a blockchain). In this case, the pool of nodes supporting the ledger may appear as one witness from the perspective of KERI."*

### AID Structure
- **Non-ephemeral, non-transferable** AID
- Requires its own **inception event** (unlike witness backers)
- The inception event's `n` (next key digest) field is **empty** → rotation impossible
- The inception event's `b` (backers) field is **empty** → backers cannot have backers (prevents infinite regress)
- The inception event's `a` (anchors) field contains a seal whose digest is the SAID of the backer's ledger configuration metadata

```json
{
  "v": "KERI10JSON0000ef_",
  "t": "icp",
  "d": "<SAID>",
  "i": "<backer AID prefix>",
  "s": "0",
  "kt": "1",
  "k":  ["<Ed25519 public key qb64>"],
  "nt": "0",
  "n":  [],
  "bt": "0",
  "b":  [],
  "c":  [],
  "a":  [{ "d": "<SAID of ledger configuration metadata>" }]
}
```

In keripy, this is created with `hby.makeHab(name=alias, transferable=False)`.

### How It Works
1. Controller publishes key event to backer's HTTP endpoint (same interface as a witness)
2. Backer validates via keripy's `Kevery`/`Tevery` pipeline
3. Backer **cross-anchors the event commitment on the ledger** (instead of signing an Ed25519 receipt)
4. The ledger's total ordering and immutability provide the duplicity protection
5. Validators query the ledger directly to verify the event is anchored

### Endorsement Policy (Critical)
Per the KERI spec:
> *"Backers may only endorse something previously committed to via a seal in the KEL."*

A ledger backer only anchors events that have passed keripy's standard validation pipeline. Validators may discard any backer endorsement not anchored in the controller's prior KEL.

### Duplicity Protection
A controller cannot present two different events at sequence number N because:
- Once anchored on the ledger, the event is immutable
- The ledger's total ordering makes any second version of the same sequence number provably later
- The ledger emits a duplicity event if the same (prefix, sn) is submitted with a different digest

This is actually **stronger** than witness-pool-based protection: a witness server can be compromised; an immutable smart contract cannot.

---

## Comparison Table

| Aspect | Witness Backer | Ledger Registrar Backer |
|---|---|---|
| AID type | Ephemeral, non-transferable | Non-ephemeral, non-transferable |
| Inception event | None required | Required (with empty `n`) |
| Consensus model | KAACE (Byzantine agreement) | Ledger immutability |
| Receipt mechanism | Ed25519-signed `rct` message | Ledger transaction + attestation |
| Duplicity protection | Witness pool + first-seen | Ledger total ordering |
| Configuration | Implicit | Published in inception event anchors |
| Query method | HTTP to witness server | Chain query or smart contract call |
| Composability | Not directly on-chain | Smart contract version: queryable by other contracts |
| Cost | Operational (witness nodes) | Transaction fees |
| Finality | Eventual (KAACE rounds) | Ledger-dependent |

---

## The Cardano Backer — Reference Implementation

[WebOfTrust/cardano-backer](https://github.com/WebOfTrust/cardano-backer) (also [cardano-foundation/cardano-backer](https://github.com/cardano-foundation/cardano-backer)) is the only existing ledger registrar backer implementation. It was built by RootsID with support from the Cardano Foundation and GLEIF Project Catalyst funding.

### Architecture

```
Controller
    │  POST /events (standard KERI HTTP)
    ▼
HTTP Endpoint  (standard keripy witness interface)
    │
    │  keripy Parser → Kevery / Tevery
    ▼
Event Queue  (Queuer — 10-second intervals)
    │
    │  batch of events
    ▼
Cardano Transaction  (Cardaning module)
    │  raw CESR bytes as tx metadata
    │  64-byte chunks, label 13456 (KEL) or 13457 (schema)
    ▼
Ogmios / Blockfrost  →  Cardano blockchain
    │
    │  Crawler monitors chain
    │  TRANSACTION_SECURITY_DEPTH = 16 blocks
    │  TRANSACTION_TIMEOUT_DEPTH = 32 blocks
    ▼
Receipt sent to controller
```

### Key Implementation Details

**Source modules** (`src/backer/`):
- `backering.py` — Main keripy integration; `BackerStart` doer with `msgDo`, `escrowDo`, `cueDo`
- `cardaning.py` — Cardano transaction construction via PyCardano + Ogmios; event chunking
- `queueing.py` — `Queuer` class; time-based batching every 10s (configurable via `QUEUE_DURATION`)
- `crawling.py` — `Crawler` monitors chain for confirmation; `Pruner` maintains checkpoint history
- `cli/commands/start.py` — Initialisation; `hby.makeHab(name=alias, transferable=False)`

**keripy components used** (unchanged from standard keripy):
- `habbing.Habery` — manages identifiers and operational contexts
- `Kevery` — validates key establishment events
- `Tevery` — validates TEL events (credential issuance/revocation)
- `Parser` — streams events through Kevery/Tevery
- `httping.parseCesrHttpRequest()` — parses incoming CESR HTTP requests

**AID and address derivation**:
- Same Ed25519 seed → KERI AID prefix AND Cardano spending address (possible because Cardano natively supports Ed25519)
- `BACKER_SALT` (qualified base64) enables deterministic regeneration

**On-chain data**: Raw CESR-encoded event bytes split into 64-byte chunks stored as Cardano transaction metadata. Not directly queryable by smart contracts — requires chain indexer (Ogmios + Crawler).

**Limitations noted in source**:
- If one cycle generates more events than fit in one transaction, excess wait until next flush
- Failed publishes lack automatic retry — manual intervention or next scheduled cycle

### Configuration (environment variables)

```bash
BACKER_SALT="<qb64 salt>"            # Required — derives both AID and Cardano address
BLOCKFROST_API_KEY="..."              # Required — Cardano chain access
BACKER_CONFIG_DIR="/etc/backer"      # Configuration files
BACKER_STORE_DIR="/data/backer"      # Database and keystore
BACKER_URL="http://..."              # OOBI resolution URL
BACKER_PORT=8080                     # HTTP service port
QUEUE_DURATION=10                    # Batching interval (seconds)
```

---

## Prior Art and Community Discussions

| Source | Content |
|---|---|
| [KERI Spec KID0009](https://identity.foundation/keri/kids/kid0009.html) | Ledger oracle witnesses mentioned as a supported backer type |
| [Issue #149 — decentralized-identity/keri](https://github.com/decentralized-identity/keri/issues/149) | Sam Smith's original ledger registrar backer proposal (2021); Ethereum and Bitcoin named explicitly |
| [WebOfTrust/cardano-backer](https://github.com/WebOfTrust/cardano-backer) | First and only existing implementation |
| [keripy Issue #184](https://github.com/decentralized-identity/keripy/issues/133) | TEL registrar design discussion |
| [Key State Capital Report](https://www.keystate.capital/post/verifiable-smart-contracts-vlei-on-chain) | GLEIF + Cardano Foundation + Key State Capital on vLEI on-chain (June 2025) |
| [Chainlink ACE](https://blog.chain.link/automated-compliance-engine/) | Oracle-based vLEI on-chain verification (different approach — not a native KERI backer) |

**Notable gap**: There is no EVM/Ethereum ledger registrar backer implementation. The Cardano implementation is the only one.

---

## References

- [KID0009 — Indirect Mode & Witnesses](https://identity.foundation/keri/kids/kid0009.html)
- [Issue #149 — Ledger Registrar Backers](https://github.com/decentralized-identity/keri/issues/149)
- [WebOfTrust/cardano-backer](https://github.com/WebOfTrust/cardano-backer)
- [cardano-foundation/cardano-backer](https://github.com/cardano-foundation/cardano-backer)
- [KERI Community — Discord](https://discord.gg/YEyTH5TfuB)
