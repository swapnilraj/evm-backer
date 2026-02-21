# evm-backer

An EVM Ledger Registrar Backer for KERI. Anchors KERI key events on Ethereum so any smart contract can verify vLEI credential state without an oracle.

## What it does

Controllers submit key events to this service exactly as they would a KERI witness. The backer:

1. Validates events via keripy (signature verification, sequence ordering, key chaining)
2. Returns a signed `rct` receipt immediately
3. Batches accepted events and anchors their SAIDs on `KERIBacker.sol`
4. Monitors the chain for confirmation and handles reorgs

Any EVM contract can then call `isAnchored(prefix, sn, said)` to verify a controller's key state — no oracle, no off-chain dependency.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- [Foundry](https://book.getfoundry.sh/) (`forge`, `anvil`, `cast`)
- Rust (for the SP1 ZK prover — optional, only needed for the ZK anchoring path)

## Installation

```bash
git clone --recurse-submodules https://github.com/your-org/evm-backer.git
cd evm-backer
uv sync
```

## Usage

```bash
# Show backer AID, Ethereum address, and configuration
uv run evm-backer info

# Start the backer service
uv run evm-backer start

# Query whether an event is anchored on-chain
uv run evm-backer query --prefix <AID> --sn <sequence-number>
```

## Configuration

All configuration is via environment variables:

| Variable | Description | Default |
|---|---|---|
| `BACKER_SALT` | qb64 salt — derives the backer's KERI AID | required |
| `BACKER_NAME` | Habery name | `evm-backer` |
| `BACKER_PORT` | HTTP service port | `8080` |
| `ETH_RPC_URL` | Ethereum JSON-RPC endpoint (comma-separated for multi-RPC failover) | required |
| `ETH_CONTRACT_ADDRESS` | Deployed `KERIBacker` contract address | required |
| `ETH_CHAIN_ID` | EIP-155 chain ID | required |
| `ETH_PRIVATE_KEY` | Backer's Ethereum private key | required |
| `QUEUE_DURATION` | Seconds between batch submissions | `10` |
| `BATCH_SIZE` | Max events per transaction | `20` |
| `ETH_CONFIRMATION_DEPTH` | Blocks required for confirmation | `12` |
| `ETH_TIMEOUT_DEPTH` | Blocks before unconfirmed tx is requeued | `32` |

## Deploying the contracts

`KERIBacker` is a single global contract shared by all QVIs. `Ed25519Verifier` is GLEIF-operated and holds the approved set of backer pubkeys. Deploy order:

```bash
cd contracts
forge build

# Set env vars
export OWNER_ADDRESS=<GLEIF multisig or AID-controlled address>
export BACKER_PUBKEY=<backer Ed25519 pubkey as 0x-prefixed bytes32>

forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast
```

The script deploys `Ed25519Verifier`, approves the first backer pubkey, deploys `KERIBacker`, and wires them together. The deployed `KERIBacker` address goes in `ETH_CONTRACT_ADDRESS`.

To add a new QVI backer after initial deployment:

```bash
cast send $ED25519_VERIFIER "approveBacker(bytes32)" $NEW_BACKER_PUBKEY \
    --private-key $OWNER_KEY --rpc-url $ETH_RPC_URL
```

## SP1 ZK Proof path

`KERIBacker.sol` supports two anchoring paths via the `IKERIVerifier` interface:

- **Standard** (`Ed25519Verifier`): Ed25519 signature verified on-chain (~692k gas). No extra tooling required.
- **ZK** (`SP1KERIVerifier`): Ed25519 verification runs inside the [SP1 zkVM](https://github.com/succinctlabs/sp1); a Groth16 proof is verified by `SP1VerifierGroth16` (~275k gas). Key computation moves entirely off-chain.

Both paths use the same `anchorEvent(prefix, sn, said, verifier, proof)` and `anchorBatch(anchors, verifier, proof)` interface — the verifier address selects the path.

### Deploying SP1KERIVerifier

```bash
# Deploy SP1VerifierGroth16 (from sp1-contracts)
SP1_VERIFIER=$(forge create lib/sp1-contracts/contracts/src/v6.0.0/SP1VerifierGroth16.sol:SP1Verifier \
    --rpc-url $ETH_RPC_URL --private-key $OWNER_KEY --broadcast | grep "Deployed to:" | awk '{print $3}')

# Deploy SP1KERIVerifier with the real program vkey (printed by sp1-prover on first run)
SP1_KERI=$(forge create src/SP1KERIVerifier.sol:SP1KERIVerifier \
    --constructor-args $SP1_VERIFIER $SP1_VKEY $OWNER_ADDRESS \
    --rpc-url $ETH_RPC_URL --private-key $OWNER_KEY --broadcast | grep "Deployed to:" | awk '{print $3}')

# Approve the backer pubkey on SP1KERIVerifier
cast send $SP1_KERI "approveBacker(bytes32)" $BACKER_PUBKEY \
    --private-key $OWNER_KEY --rpc-url $ETH_RPC_URL

# Register SP1KERIVerifier with KERIBacker
cast send $KERI_BACKER "approveVerifier(address)" $SP1_KERI \
    --private-key $OWNER_KEY --rpc-url $ETH_RPC_URL
```

For local development with Anvil, `SP1MockVerifier` (from sp1-contracts) accepts empty proof bytes and can be used without any SP1 toolchain.

### Building the SP1 prover (required for real ZK proofs)

```bash
# Install SP1 toolchain (one-time)
curl -L https://sp1up.succinct.xyz | bash
sp1up

# Build the guest ELF (compiles to RISC-V)
cd sp1-guest && cargo prove build

# Build the host prover binary
cargo build --release -p sp1-prover

# Generate a real Groth16 proof (downloads ~8 GB of circuit files on first run)
SP1_PROVER=cpu ./target/release/sp1-prover <pubkey_hex> <msg_hex> <sig_hex>
```

The `sp1-prover` CLI outputs a JSON line on stdout:
```json
{"proof": "0x...", "publicValues": "0x...", "vkey": "0x..."}
```

### Running the real Groth16 integration test

```bash
# Requires SP1 toolchain + ~8 GB circuit artifacts in ~/.sp1/circuits/groth16/v6.0.0/
# Takes ~7 minutes on an Apple M-series CPU.
REAL_SP1_PROOF=1 uv run pytest tests/test_zk_real.py -v -s
```

## Architecture

```
Controller
  │  POST /events  (raw CESR bytes, same interface as a KERI witness)
  ▼
http_server.py  (Falcon WSGI, port 8080)
  │
  ▼
backer.py  (keripy Kevery + Tevery + Parser)
  │  validates signatures, chaining, sequence numbers
  │  checks controller has designated this backer in their b field
  │
  ├─► receipt bytes → Controller  (immediate, before on-chain anchoring)
  │
  └─► event_queue.py  (Queuer)
        │  batches events for 10s or until 20 events accumulate
        ▼
      transactions.py  (EIP-1559 tx construction + Ed25519 signing)
        │  builds proof = abi.encode(pubKey, r, s)
        ▼
      KERIBacker.sol  anchorBatch(anchors, verifier, proof)
        │  calls IKERIVerifier(verifier).verify(messageHash, proof)
        │  stores (keccak256(prefix), sn) → (keccak256(said), blockNumber, verifier)
        ▼
      crawler.py  (Crawler)
        │  waits 12 confirmations, detects reorgs, requeues on revert/timeout
        ▼
      confirmed — any EVM contract can call isAnchored(prefix, sn, said)
```

## Source layout

```
src/evm_backer/
  backer.py        — keripy integration (Kevery, Tevery, Parser, receipt signing)
  transactions.py  — EIP-1559 tx construction and Ed25519 signing
  event_queue.py   — time-based event batching
  crawler.py       — confirmation monitoring, reorg and revert detection
  rpc.py           — multi-RPC provider with exponential backoff failover
  http_server.py   — Falcon WSGI HTTP endpoint
  service.py       — main service loop wiring all modules together
  cli.py           — evm-backer CLI entry point
  proofs.py        — SP1 ZK proof generation (generate_sp1_proof / make_mock_sp1_proof)

contracts/
  src/KERIBacker.sol         — on-chain anchor contract; owner governs verifier registry
  src/IKERIVerifier.sol      — verifier interface: verify(bytes32, bytes)
  src/Ed25519Verifier.sol    — GLEIF-operated Ed25519 verifier with approvedBackers set
  src/SP1KERIVerifier.sol    — GLEIF-operated SP1 ZK verifier with approvedBackers set
  src/Ed25519.sol            — Solidity Ed25519 signature verifier (primitive)
  lib/sp1-contracts/         — Succinct SP1 verifier contracts
  lib/forge-std/             — Foundry test helpers
  script/Deploy.s.sol        — forge deployment script (Ed25519Verifier + KERIBacker)
  test/KERIBacker.t.sol      — Foundry tests (30 tests)

sp1-guest/               — SP1 guest program (Ed25519 verify inside zkVM)
sp1-prover/              — SP1 host prover CLI
```

## Testing

```bash
# Python tests — spins up anvil automatically
uv run pytest tests/ -q

# Contract tests
forge test --root contracts -v

# Real Groth16 end-to-end (slow — ~7 min, requires SP1 toolchain)
REAL_SP1_PROOF=1 uv run pytest tests/test_zk_real.py -v -s
```

## Key design decisions

**Modular verifier registry** — `KERIBacker` delegates all signature verification to registered `IKERIVerifier` contracts. GLEIF governs which verifiers are approved via `approveVerifier`/`revokeVerifier`. This means one global `KERIBacker` serves the whole ecosystem; QVIs need no on-chain setup beyond GLEIF adding their pubkey to `Ed25519Verifier` as part of accreditation.

**Ed25519 on-chain verification** — `Ed25519Verifier` verifies Ed25519 signatures directly via a Solidity verifier. The backer uses one key for both KERI identity and Ethereum authorization, giving tight cryptographic binding per the KERI spec.

**Receipt-first** — Receipts are returned immediately after keripy validation, before on-chain confirmation. This matches standard KERI witness behaviour. On-chain anchoring is asynchronous.

**SAID-only storage** — The contract stores only the SAID (a `keccak256` of the event's qb64 SAID string), not raw event bytes. Raw events are served by the backer's HTTP endpoint. This keeps gas costs low while still enabling `isAnchored()` verification.

**First-seen policy** — Once an event is anchored at `(prefix, sn)`, no conflicting SAID can overwrite it. The `DuplicityDetected` event is emitted if a second SAID is submitted for the same slot.

**SP1 ZK integration** — The ZK path moves Ed25519 verification off-chain into the SP1 zkVM. The on-chain verifier (`SP1VerifierGroth16`) checks a succinct Groth16 proof, reducing gas from ~692k to ~275k. The guest program is ~10 lines of Rust; no custom ZK circuit is needed.

## Background

- `evm-backer-spec.md` — full technical specification
- `docs/06-design-challenges.md` — design decisions and resolved issues
- `docs/03-vlei-technical-stack.md` — KERI, ACDC, CESR background

## License

Apache-2.0 — see [LICENSE](LICENSE).
