# CLAUDE.md

This project implements an EVM Ledger Registrar Backer for KERI — a service that anchors KERI key events on Ethereum, enabling any smart contract to verify vLEI credential state without an oracle.

## Tooling

- **Python**: [uv](https://docs.astral.sh/uv/) — use `uv` for all Python dependency and environment management, never `pip` directly
- **Contracts**: [Foundry](https://book.getfoundry.sh/) — use `forge` for build/test/deploy, `cast` for chain interaction, `anvil` for local node
- **Rust**: SP1 zkVM guest + prover binaries (`sp1-guest`, `sp1-prover`, `sp1-tel-guest`, `sp1-tel-prover`)

## Key commands

```bash
# Python service
uv sync                          # install dependencies
uv run evm-backer info           # show backer AID, Ethereum address, config
uv run evm-backer start          # run the backer service
uv run evm-backer query --prefix <AID> --sn <seq> [--said <SAID>]

# Contracts (run from contracts/)
forge build                      # compile all contracts
forge test --root contracts      # run contract tests (28 tests)
forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast
anvil                            # local EVM node for development
cast call $CONTRACT "isAnchored(bytes32,uint64,bytes32)" <args>

# Rust (SP1 provers)
cargo test -p sp1-guest -p sp1-tel-guest   # 23 unit tests
cargo build --release -p sp1-prover -p sp1-tel-prover
```

## Architecture

- `backer.py` — keripy integration (Kevery, Tevery, Parser, receipt signing)
- `transactions.py` — EIP-1559 tx construction and submission to `KERIBacker.sol`
- `event_queue.py` — time-based event batching (10s intervals, up to 20 events/tx)
- `crawler.py` — confirmation monitoring (default 12 blocks), reorg and revert detection
- `rpc.py` — multi-RPC provider with exponential backoff failover
- `http_server.py` — Falcon WSGI endpoint (`POST /events`, `GET /health`)
- `service.py` — main service loop wiring all modules together
- `cli.py` — `evm-backer` CLI entry point
- `proofs.py` — SP1 proof generation (`build_kel_input`, `generate_sp1_proof`, `make_mock_sp1_proof`, `build_tel_input`, `generate_tel_proof`, `make_mock_tel_proof`)
- `contracts/src/KERIBacker.sol` — on-chain anchor; `isAnchored(prefix, sn, said)` is the key function other contracts call
- `contracts/src/IKERIVerifier.sol` — verifier interface: `verify(bytes32 messageHash, bytes proof)`
- `contracts/src/IKERIBacker.sol` — minimal interface for `isAnchored()` used by TEL verifier
- `contracts/src/SP1KERIVerifier.sol` — permissionless SP1 ZK verifier for KEL anchoring; proof = `abi.encode(publicValues, proofBytes)`
- `contracts/src/SP1TELVerifier.sol` — SP1 ZK verifier for TEL credential anchoring; calls `KERIBacker.isAnchored()` for the anchor KEL event
- `sp1-guest/` — SP1 zkVM guest: verifies full KERI KEL (icp/ixn/rot/dip/drt), M-of-N Ed25519 sigs, SAIDs, pre-rotation commitments, delegation seals
- `sp1-tel-guest/` — SP1 zkVM guest: verifies TEL event SAID + anchor seal in controller's KEL event

## Critical decisions

- The backer's KERI AID is created with `hby.makeHab(name=alias, transferable=False)` — non-transferable inception event, empty `n` field. Do not change this.
- Events are stored in **contract storage** (not calldata/events only) so other EVM contracts can query them via `staticcall`.
- The backer exposes the standard KERI witness HTTP interface — controllers configure it exactly like a witness.
- **Receipt-first model**: the KERI receipt is returned to the controller immediately after keripy validation. On-chain anchoring is asynchronous.
- **SP1 ZK only**: the only anchoring path is `SP1KERIVerifier`. The guest proves the full KEL — every event's SAID, chain, Ed25519 signatures (M-of-N threshold), and pre-rotation commitments — inside the zkVM. No on-chain Ed25519 verifier; no separate approvedBackers registry.
- **Multi-sig threshold**: integer M-of-N signing is fully supported (`kt`/`nt` fields). The guest verifies that `verified_count >= kt` across the provided `KeriSig` entries. Weighted fractional thresholds are out of scope. `kel_store` entries use `"sigs": [(signer_idx, bytes64), ...]`; the Python `build_kel_input` passes all keys from the `k` field as `initial_keys_qb64`.
- **Modular verifier registry**: `KERIBacker` delegates verification to registered `IKERIVerifier` contracts. GLEIF governs which verifiers are approved via `approveVerifier`/`revokeVerifier`. One global `KERIBacker` serves the whole ecosystem.
- **Permissionless verifiers**: `SP1KERIVerifier` and `SP1TELVerifier` have no owner or access control — correctness is enforced by the SP1 proof itself.
- **TEL anchoring**: `SP1TELVerifier` verifies a ZK proof that a TEL event's SAID is correct and its anchor seal appears in a controller KEL event, then checks that event is already on-chain via `KERIBacker.isAnchored()`.
- **Prefix/SAID encoding**: `keccak256(qb64_string)` → `bytes32` for both AID prefix and SAID. Collision-resistant, handles arbitrary-length identifiers unambiguously.

## Open questions (resolve with KERI community before finalising)

See `evm-backer-spec.md` §10 for the full list. One that affects implementation:
- Whether keripy's validator handles mixed witness + ledger backer sets in the `b` field

## Background reading

- `evm-backer-spec.md` — full technical specification
- `docs/06-design-challenges.md` — devil's advocate review; tracks resolved vs open issues
- `docs/03-vlei-technical-stack.md` — KERI/ACDC/CESR background
