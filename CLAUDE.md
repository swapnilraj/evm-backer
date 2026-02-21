# CLAUDE.md

This project implements an EVM Ledger Registrar Backer for KERI — a service that anchors KERI key events on Ethereum, enabling any smart contract to verify vLEI credential state without an oracle.

## Tooling

- **Python**: [uv](https://docs.astral.sh/uv/) — use `uv` for all Python dependency and environment management, never `pip` directly
- **Contracts**: [Foundry](https://book.getfoundry.sh/) — use `forge` for build/test/deploy, `cast` for chain interaction, `anvil` for local node

## Key commands

```bash
# Python service
uv sync                          # install dependencies
uv run evm-backer info           # show backer AID, Ethereum address, config
uv run evm-backer start          # run the backer service
uv run evm-backer query --prefix <AID> --sn <seq> [--said <SAID>]

# Contracts (run from contracts/)
forge build                      # compile KERIBacker.sol
forge test                       # run contract tests
forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast
anvil                            # local EVM node for development
cast call $CONTRACT "isAnchored(bytes32,uint64,bytes32)" <args>
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
- `contracts/src/KERIBacker.sol` — on-chain anchor; `isAnchored(prefix, sn, said)` is the key function other contracts call

## Critical decisions

- The backer's KERI AID is created with `hby.makeHab(name=alias, transferable=False)` — non-transferable inception event, empty `n` field. Do not change this.
- Events are stored in **contract storage** (not calldata/events only) so other EVM contracts can query them via `staticcall`.
- The backer exposes the standard KERI witness HTTP interface — controllers configure it exactly like a witness.
- **Receipt-first model**: the Ed25519 receipt is returned to the controller immediately after keripy validation. On-chain anchoring is asynchronous.
- **Ed25519 on-chain verification**: the contract verifies Ed25519 signatures directly (via a Solidity verifier) so the backer uses one key for both KERI identity and Ethereum authorization — no separate secp256k1 key.
- **Prefix/SAID encoding**: `keccak256(qb64_string)` → `bytes32` for both AID prefix and SAID. Collision-resistant, handles arbitrary-length identifiers unambiguously.

## Open questions (resolve with KERI community before finalising)

See `evm-backer-spec.md` §10 for the full list. One that affects implementation:
- Whether keripy's validator handles mixed witness + ledger backer sets in the `b` field

## Background reading

- `evm-backer-spec.md` — full technical specification
- `docs/06-design-challenges.md` — devil's advocate review; tracks resolved vs open issues
- `docs/03-vlei-technical-stack.md` — KERI/ACDC/CESR background
