# evm-backer

An EVM Ledger Registrar Backer for KERI. Anchors KERI key events on Ethereum so any smart contract can verify vLEI credential state without an oracle.

## What it does

Controllers submit key events to this service exactly as they would a KERI witness. The backer:

1. Validates events via keripy (signature verification, sequence ordering, key chaining)
2. Returns a signed `rct` receipt immediately
3. Generates an SP1 ZK proof of the full KERI Key Event Log (KEL)
4. Anchors the event on `KERIBacker.sol` with the ZK proof
5. Monitors the chain for confirmation and handles reorgs

Any EVM contract can then call `isAnchored(prefix, sn, said)` to verify a controller's key state — no oracle, no off-chain dependency.

TEL (Transaction Event Log) credential events (iss/rev) can also be anchored via `SP1TELVerifier`, which checks the TEL proof and verifies the anchor KEL event is already on-chain.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- [Foundry](https://book.getfoundry.sh/) (`forge`, `anvil`, `cast`)
- Rust + [SP1 toolchain](https://docs.succinct.xyz/getting-started/install.html) (for ZK proof generation)

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

`KERIBacker` is a single global contract shared by all QVIs. `SP1KERIVerifier` is permissionless — one deployment per SP1 program version (vkey). Deploy order:

```bash
cd contracts
forge build

# Deploy SP1VerifierGroth16 (from sp1-contracts)
SP1_VERIFIER=$(forge create lib/sp1-contracts/contracts/src/v6.0.0/SP1VerifierGroth16.sol:SP1Verifier \
    --rpc-url $ETH_RPC_URL --private-key $OWNER_KEY | grep "Deployed to:" | awk '{print $3}')

# Set env vars
export OWNER_ADDRESS=<GLEIF multisig or AID-controlled address>
export SP1_VERIFIER_ADDRESS=$SP1_VERIFIER
export SP1_VKEY=<vkey printed by sp1-prover on first run>

forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast
```

The script deploys `SP1KERIVerifier`, deploys `KERIBacker`, and calls `approveVerifier`. The deployed `KERIBacker` address goes in `ETH_CONTRACT_ADDRESS`.

To deploy `SP1TELVerifier` for TEL credential anchoring:

```bash
KERI_BACKER=<deployed KERIBacker address>
SP1_TEL_VKEY=<vkey printed by sp1-tel-prover on first run>

SP1_TEL=$(forge create src/SP1TELVerifier.sol:SP1TELVerifier \
    --constructor-args $SP1_VERIFIER $SP1_TEL_VKEY $KERI_BACKER \
    --rpc-url $ETH_RPC_URL --private-key $OWNER_KEY | grep "Deployed to:" | awk '{print $3}')

cast send $KERI_BACKER "approveVerifier(address)" $SP1_TEL \
    --private-key $OWNER_KEY --rpc-url $ETH_RPC_URL
```

## SP1 ZK Proof

All anchoring uses the [SP1 zkVM](https://github.com/succinctlabs/sp1). The guest program proves the complete KERI KEL inside the zkVM — no on-chain Ed25519 verifier needed. Correctness is enforced by the Groth16 proof alone.

**KEL proof** (`sp1-guest`): Verifies every event's SAID (blake3), chain (p fields), Ed25519 signatures (M-of-N threshold), pre-rotation commitments, and delegation seals for dip/drt events. Supports all five KERI KEL event types (`icp`, `ixn`, `rot`, `dip`, `drt`) and integer M-of-N signing thresholds.

**TEL proof** (`sp1-tel-guest`): Verifies a TEL event's SAID and that the anchor seal appears in the controller's KEL event. `SP1TELVerifier` then checks on-chain that the referenced KEL event is anchored.

### Building the SP1 provers

```bash
# Install SP1 toolchain (one-time)
curl -L https://sp1up.succinct.xyz | bash
sp1up

# Build KEL guest ELF (compiles to RISC-V)
cd sp1-guest && cargo prove build

# Build TEL guest ELF
cd sp1-tel-guest && cargo prove build

# Build host prover binaries
cargo build --release -p sp1-prover -p sp1-tel-prover
```

### Generating proofs

```bash
# KEL proof (SP1_PROVER=mock for dev, cpu for real Groth16)
SP1_PROVER=cpu ./target/release/sp1-prover <kel_input_hex>

# TEL proof
SP1_PROVER=cpu ./target/release/sp1-tel-prover <tel_input_hex>
```

Both CLIs output a JSON line on stdout:
```json
{"proof": "0x...", "publicValues": "0x...", "vkey": "0x..."}
```

### Running the real Groth16 integration test

```bash
# Requires SP1 toolchain + ~8 GB circuit artifacts in ~/.sp1/circuits/groth16/v6.0.0/
# Takes ~7 minutes on an Apple M-series CPU.
REAL_SP1_PROOF=1 SP1_PROVER=cpu uv run pytest tests/test_zk_real.py::TestRealGroth16Proof -v -s
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
      proofs.py  (build_kel_input → generate_sp1_proof)
        │  runs sp1-prover binary, produces Groth16 proof
        ▼
      transactions.py  (EIP-1559 tx construction)
        │  builds proof = abi.encode(publicValues, proofBytes)
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
  transactions.py  — EIP-1559 tx construction
  event_queue.py   — time-based event batching
  crawler.py       — confirmation monitoring, reorg and revert detection
  rpc.py           — multi-RPC provider with exponential backoff failover
  http_server.py   — Falcon WSGI HTTP endpoint
  service.py       — main service loop wiring all modules together
  cli.py           — evm-backer CLI entry point
  proofs.py        — SP1 ZK proof generation (KEL + TEL)

contracts/
  src/KERIBacker.sol         — on-chain anchor; owner governs verifier registry
  src/IKERIVerifier.sol      — verifier interface: verify(bytes32, bytes)
  src/IKERIBacker.sol        — minimal interface for isAnchored() (used by TEL verifier)
  src/SP1KERIVerifier.sol    — permissionless SP1 ZK verifier for KEL anchoring
  src/SP1TELVerifier.sol     — SP1 ZK verifier for TEL credential anchoring
  lib/sp1-contracts/         — Succinct SP1 verifier contracts
  lib/forge-std/             — Foundry test helpers
  script/Deploy.s.sol        — forge deployment script (SP1KERIVerifier + KERIBacker)
  test/KERIBacker.t.sol      — Foundry tests (25 tests)
  test/SP1TELVerifier.t.sol  — Foundry tests (3 tests)

sp1-guest/               — SP1 guest: full KERI KEL verification (icp/ixn/rot/dip/drt, M-of-N sigs)
sp1-prover/              — SP1 host prover CLI for KEL proofs
sp1-tel-guest/           — SP1 guest: TEL event SAID + anchor seal verification
sp1-tel-prover/          — SP1 host prover CLI for TEL proofs
```

## Testing

```bash
# Python tests — spins up anvil automatically (149 pass, 3 skipped)
uv run pytest tests/ -q

# Contract tests (28 pass)
forge test --root contracts -v

# Rust unit tests (23 pass)
cargo test -p sp1-guest -p sp1-tel-guest

# Fast ZK path (real binary, mock proving — no Groth16 artifacts needed)
uv run pytest tests/test_zk_real.py::TestRealProverBinaryFast tests/test_zk_real.py::TestTELProverBinaryFast -v -s

# Multi-sig threshold tests (mock proof, no binary needed)
uv run pytest tests/test_zk_real.py::TestMultiSigKEL -v -s

# Real Groth16 end-to-end (slow — ~7 min, requires SP1 toolchain + ~8 GB artifacts)
REAL_SP1_PROOF=1 SP1_PROVER=cpu uv run pytest tests/test_zk_real.py::TestRealGroth16Proof -v -s
```

## Key design decisions

**SP1 ZK only** — The only anchoring path is `SP1KERIVerifier`. The guest program proves the complete KEL inside the zkVM, so no on-chain Ed25519 verifier or per-backer pubkey registry is needed. Any controller whose KEL is proveable can anchor events without GLEIF pre-approval.

**Multi-sig threshold signing** — The guest verifies integer M-of-N signing thresholds (`kt`/`nt` fields). Each event carries a `KeriSig` per signer; the guest asserts `verified_count >= kt`. Weighted fractional thresholds are not supported. Enterprise QVIs using 2-of-3 or similar schemes are fully supported.

**Modular verifier registry** — `KERIBacker` delegates all verification to registered `IKERIVerifier` contracts. GLEIF governs which verifiers are approved via `approveVerifier`/`revokeVerifier`. One global `KERIBacker` serves the whole ecosystem.

**Permissionless verifiers** — `SP1KERIVerifier` and `SP1TELVerifier` have no owner; security comes from the SP1 proof. A new verifier deployment (e.g. for a new guest version) requires only GLEIF registering it with `KERIBacker`.

**TEL anchoring** — `SP1TELVerifier` proves a TEL event SAID is correct and its anchor seal exists in a controller KEL event, then calls `KERIBacker.isAnchored()` to confirm that KEL event is on-chain. The TEL proof does not re-verify the full KEL inside the zkVM.

**Receipt-first** — Receipts are returned immediately after keripy validation, before on-chain confirmation. This matches standard KERI witness behaviour. On-chain anchoring is asynchronous.

**SAID-only storage** — The contract stores only `keccak256(said_qb64)`, not raw event bytes. Raw events are served by the backer's HTTP endpoint. This keeps gas costs low while still enabling `isAnchored()` verification.

**First-seen policy** — Once an event is anchored at `(prefix, sn)`, no conflicting SAID can overwrite it. The `DuplicityDetected` event is emitted if a second SAID is submitted for the same slot.

## Background

- `evm-backer-spec.md` — full technical specification
- `docs/06-design-challenges.md` — design decisions and resolved issues
- `docs/03-vlei-technical-stack.md` — KERI, ACDC, CESR background

## License

Apache-2.0 — see [LICENSE](LICENSE).
