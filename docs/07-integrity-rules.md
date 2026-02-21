# Implementation Integrity Rules

Three rules govern all code and tests in this project. This document explains each rule, provides concrete examples of violations (drawn from the Cardano backer reference implementation), describes the conftest design, and lists red flags to watch for as the implementation progresses.

---

## Rule 1: No Mocks or Stubs

**Statement**: Every test must interact with real objects. No `unittest.mock`, no `MagicMock`, no monkeypatching of core logic, no `pytest-mock` for anything in the critical path.

**Acceptable test doubles**:
- A real local `anvil` node started as a subprocess
- Real keripy `Habery`/`Hab` objects with in-memory keystores (`temp=True`)
- Real compiled Solidity contracts deployed to anvil via `forge create`
- Real `web3.py` connections to anvil over JSON-RPC

### What the Cardano backer does right

The Cardano backer's `test_receipt.py` creates real keripy `Habery` and `Hab` objects, constructs real KERI inception events, and posts real CESR-encoded requests through the Falcon test client. The events are structurally valid — real key material, real signatures, real serialization. This is the pattern to replicate.

Specifically in `test_event_receipt_200`:
```python
test_hab = cls.hby.makeHab(name='test1', wits=[icp], toad=1, transferable=True)
test_serder, _, _ = test_hab.getOwnEvent(sn=0)
evt = test_hab.db.cloneEvtMsg(pre=test_serder.pre, fn=0, dig=test_serder.said)
```

This creates a real controller identity with the backer in its witness set, then extracts the real inception event bytes with real signatures. No mocking.

### What to avoid

If someone proposes testing `ethereuming.py` by mocking `web3.eth.send_raw_transaction` to return a fake transaction hash, reject it. The whole point of having anvil in the test suite is that we can send real transactions and get real receipts.

Similarly, if someone proposes testing the `Queuer` by replacing the Ethereum client with a stub that records calls, reject it. Start anvil, deploy the contract, send real batches, and verify the contract state.

### Violations to reject

| Pattern | Why it is wrong |
|---|---|
| `from unittest.mock import MagicMock` | Direct mock import |
| `monkeypatch.setattr("backer.ethereuming.Web3", ...)` | Replaces real web3 with fake |
| `@pytest.fixture def mock_contract(): ...` | Test double for the contract |
| `w3 = MagicMock(spec=Web3)` | Fake web3 connection |
| `mocker.patch("keri.core.eventing.Kevery.process")` | Bypasses real validation |
| `mocker.patch("keri.app.httping.parseCesrHttpRequest")` | Bypasses real CESR parsing |
| `mocker.patch("keri.vdr.eventing.Tevery")` | Bypasses real TEL validation |
| `mocker.patch("keri.core.parsing.Parser.parsator")` | Bypasses real event stream processing |

### What must be real (confirmed from Cardano backer source)

The spec-validator confirmed the exact keripy objects the Cardano backer uses in production. All of these must be real in our tests -- no exceptions:

- `eventing.Kevery(db=hby.db, lax=True, local=False, rvy=rvy, cues=cues)` -- note `lax=True`
- `Tevery(reger=verfer.reger, db=hby.db, local=False, cues=cues)`
- `parsing.Parser(framed=True, kvy=kvy, tvy=tvy, exc=exchanger, rvy=rvy)`
- `routing.Revery(db=hby.db, cues=cues)` with `registerReplyRoutes`
- `httping.parseCesrHttpRequest(req=req)` for parsing CESR HTTP requests
- `hab.receipt(serder)` for generating `NonTransReceiptCouples` receipts
- `subing.Suber(db=hab.db, subkey=...)` for database queues

The conftest provides `backer_kevery`, `backer_tevery`, and `backer_parser` fixtures that wire these together exactly as the Cardano backer does.

---

## Rule 2: No TODOs, No Placeholders

**Statement**: If a function exists, it must be complete. The following are all banned as function bodies:

- `pass`
- `raise NotImplementedError`
- `# TODO`
- `...` (Ellipsis)
- `raise NotImplementedError("implement later")`

If something is not ready to implement, do not write the function. Write a failing test for it instead. The test is the placeholder — it documents the expected behavior without pretending an implementation exists.

### What the Cardano backer does

The Cardano backer's `queueing.py` has a `# @TODO` comment:

```python
# @TODO - foconnor: If more than a tx-worth of events need to be written on-chain,
#   those events will not appear until the next flush. This could be improved.
```

This TODO documents a known limitation but does not block the current implementation — the function below it is complete. However, under our stricter rule, this should be a tracked issue or a failing test that demonstrates the batch overflow scenario, not a comment that will be forgotten.

### How to handle incomplete work

Instead of:
```python
def handle_reorg(self, block_number: int) -> None:
    # TODO: implement reorg detection
    pass
```

Write a test:
```python
def test_reorg_detection_requeues_events():
    """When a previously-confirmed block is no longer canonical,
    the crawler must requeue all events from that block."""
    pytest.fail("Not implemented: reorg detection")
```

The test communicates the requirement precisely. `grep -r "TODO"` across the codebase should return zero results.

### Violations to reject

| Pattern | Why it is wrong |
|---|---|
| `def encode_prefix(qb64: str) -> bytes: ...` | Ellipsis body — no implementation |
| `def verify_receipt(): pass` | Empty function |
| `# TODO: handle gas estimation` | Uncommitted work hidden in code |
| `raise NotImplementedError` | Placeholder pretending to be a function |

---

## Rule 3: No Premature Abstraction

**Statement**: Reject base classes with one subclass, protocols/ABCs defined for a single implementation, helper functions called exactly once, and configuration dataclasses wrapping two values.

The test: "Would this abstraction still exist if we had two concrete implementations?" If no, delete it.

### What the Cardano backer does right

The Cardano backer does NOT define a `LedgerBacker` abstract base class that `CardanoBacker` inherits from. There is no `ILedger` protocol. The code directly uses the `Cardano` class. The `Queuer` directly calls `self.ledger.publishEvents()` — it does not go through an indirection layer.

This is correct. There is exactly one ledger (Cardano). Adding an abstraction layer "so we can swap in Ethereum later" would have been premature — and indeed the EVM backer is a separate project, not a second implementation behind a shared interface.

### What to avoid in our implementation

Do NOT create:

- `class BaseLedgerClient(ABC):` with `class EthereumClient(BaseLedgerClient):` as the only subclass
- `class BackerConfig:` wrapping `contract_address: str` and `chain_id: int` when those two values are only used together once
- `Protocol` class `LedgerSubmitter` with one method `submit_batch` — just call the function directly
- `def _build_anchor_tuple(prefix, sn, said, raw):` if it is called exactly once from `anchorBatch` — inline it

### When abstraction IS justified

If we genuinely have two callers or two implementations, abstraction is fine. For example:
- If both `Queuer` and a CLI command need to submit transactions, a shared function is justified
- If we support both EIP-1559 and legacy gas pricing, a strategy pattern may be justified (but verify there are actually two strategies before adding the pattern)

### Violations to reject

| Pattern | Why it is wrong |
|---|---|
| `class LedgerClient(ABC):` with one subclass | Interface for one implementation |
| `class EthConfig(BaseModel):` wrapping two fields used once | Wrapper around two values |
| `def _validate_event(event): ...` called only from `process_event` | Helper called once — inline it |
| `class EventEncoder(Protocol):` with one implementor | Protocol for one class |

---

## Conftest Design

The conftest at `tests/conftest.py` provides shared fixtures for the entire test suite. Every fixture uses real infrastructure.

### Fixture: `anvil_process` (scope=session)

**What**: Starts a real `anvil` process as a subprocess with 1-second block times.

**Why session-scoped**: Starting anvil takes ~1 second. Starting it per-test would add significant overhead. A single anvil instance serves the entire test session. Tests that need clean state can deploy a fresh contract or use anvil's snapshot/revert RPC methods within function-scoped fixtures.

**Why 1-second block time**: Confirmation tests need blocks to advance. With `--block-time 1`, 12 confirmations take ~12 seconds. Without block-time, anvil only mines on transaction (auto-mine mode), which makes confirmation depth testing impossible.

**Teardown**: SIGTERM with a 5-second grace period, then SIGKILL. Ensures no zombie anvil processes.

**Failure mode**: If anvil does not respond to JSON-RPC within 10 seconds (port conflict, binary not found), `pytest.fail()` aborts the session immediately with a clear error message. This mirrors the Cardano backer's `conftest.py` which fails the session if Ogmios is unreachable.

### Fixture: `w3` (scope=session)

**What**: A real `web3.py` `Web3` instance connected to anvil over HTTP.

**Why session-scoped**: The connection is reusable. web3.py connections are stateless (just HTTP calls to the RPC endpoint).

**Depends on**: `anvil_process` — ensures anvil is running before any test tries to connect.

### Fixture: `deployed_contract` (scope=session)

**What**: Compiles `KERIBacker.sol` with `forge build` and deploys it to anvil with `forge create`. Returns the address, ABI, and a bound `web3.py` Contract instance.

**Why forge, not web3.py deployment**: Using `forge create` compiles from source and deploys in one step using the same Solidity compiler configuration as production. This avoids version drift between test and production artifacts. It also means the tests validate the real contract source, not a pre-compiled bytecode blob.

**Why session-scoped**: Contract deployment costs gas and takes time. A single deployment serves all tests that read contract state. Tests that modify state (anchoring events) should either use unique (prefix, sn) pairs to avoid collisions, or use function-scoped fixtures that deploy fresh contracts for isolation.

**Constructor arg**: `ANVIL_BACKER_ADDRESS` (account #1). Only this address can call `anchorEvent` and `anchorBatch` due to the `onlyBacker` modifier.

### Fixture: `keri_habery` (scope=session)

**What**: A real keripy `Habery` with `temp=True` (in-memory keystore and database).

**Why temp=True**: No disk I/O, no leftover state between test runs, no cleanup needed. keripy's temp mode stores everything in LMDB-backed memory databases that are destroyed on `.close()`.

**Why session-scoped**: The Habery is the root keripy object. Creating it initializes the keystore and database. Once initialized, many Habs (identifiers) can be created under it cheaply.

### Fixture: `backer_hab` (scope=session)

**What**: A real backer identity created with `hby.makeHab(name="test-backer", transferable=False)`.

**Why this matters**: This is the exact production code path. The resulting inception event has `n: []`, `b: []`, `kt: "1"`, and a single Ed25519 public key. Tests that inspect the backer's AID structure or inception event use this fixture.

### Fixture: `backer_kevery` (scope=session)

**What**: A real keripy `Kevery` wired with a `Revery` and shared cue deck, exactly as the Cardano backer initializes it.

**Why**: The Kevery is the core validation engine for key establishment events (icp, rot, ixn, dip, drt). The Cardano backer creates it with `lax=True, local=False` -- `lax=True` accepts events from any source, `local=False` means processing external events. The shared `cues` deck is how the Kevery signals receipt generation to the backer.

**Returns**: A dict with `kvy`, `rvy`, and `cues` -- tests that need to inspect validation state or trigger receipt generation access these directly.

### Fixture: `backer_tevery` (scope=session)

**What**: A real keripy `Tevery` with a `Reger` and `Verifier`, for processing TEL events (credential issuance/revocation).

**Why**: Credential events (vcp, vrt, iss, rev) flow through the Tevery. The Cardano backer creates a full TEL registry: `viring.Reger` -> `verifying.Verifier` -> `Tevery`. Our fixture mirrors this exactly so tests can exercise the full event pipeline including credential anchoring.

### Fixture: `backer_parser` (scope=session)

**What**: A real keripy `Parser` wired to the backer's Kevery and Tevery.

**Why**: The Parser is the entry point for all incoming CESR messages. It dispatches to Kevery or Tevery depending on the event type. The Cardano backer's `backering.py` creates exactly this: `parsing.Parser(framed=True, kvy=kvy, tvy=tvy, exc=exchanger, rvy=rvy)`. Tests that feed raw CESR bytes into the backer's processing pipeline use this fixture.

### Fixture: `controller_hab` (scope=session)

**What**: A real controller identity with the backer in its `b` (witness/backer) set.

**Why**: The Cardano backer's tests create controller Habs with `wits=[backer.pre]` and `toad=1`. This lets the tests generate valid KERI events that the backer would accept — real events with real signatures from a controller that genuinely lists this backer.

### Fixture: `backer_account` / `deployer_account` (scope=session)

**What**: Real `eth_account.Account` objects from anvil's deterministic keys.

**Why two accounts**: Separation of concerns. The deployer (account #0) deploys the contract. The backer (account #1) is the authorized `msg.sender` for `anchorEvent`/`anchorBatch`. This matches production where the deployer and the backer are different addresses.

---

## Red Flags to Watch For

As the implementation progresses, watch for these patterns and reject them:

### Testing red flags

1. **Import of `unittest.mock` anywhere in `tests/`** — immediate rejection
2. **Tests that pass without anvil running** — if a contract test passes when anvil is down, it is not testing the real contract
3. **Tests that hardcode transaction hashes or block numbers from a previous run** — anvil state is not persistent across sessions; tests must derive these values at runtime
4. **Tests that sleep for a fixed duration instead of polling** — `time.sleep(30)` is fragile; poll with a timeout instead
5. **Tests with `# noqa` or `# type: ignore` hiding real issues** — review each one individually
6. **Manual temp directory management** (`tempfile.mkdtemp`, `shutil.rmtree`) for keripy databases — keripy's `temp=True` mode and `openHby` context manager handle cleanup automatically; manual temp dirs are fragile and leave state between runs
7. **Mocking `httping.parseCesrHttpRequest`** — this is a real CESR parser that validates request structure; mocking it bypasses format validation and hides encoding bugs
8. **Constructing KERI events by hand (raw JSON dicts) instead of using real `makeHab` + `getOwnEvent`** — hand-constructed events may have invalid SAIDs, wrong version strings, or missing fields that real keripy objects would catch

### Implementation red flags

1. **Any `ABC` or `Protocol` import in the main source** — challenge it immediately; demand the second implementation that justifies it
2. **A `config.py` or `settings.py` module with dataclasses wrapping env vars** — environment variables should be read where they are used (or in one place at startup), not wrapped in a class
3. **A `utils.py` or `helpers.py` module** — every function in it should be examined for single-call usage
4. **`*args, **kwargs` passthrough in a function that always receives the same arguments** — premature generality
5. **Type aliases for `str` or `bytes`** — `Prefix = str` adds no safety and obscures the code
6. **An `EventEncoder` or `EventSerializer` class** — if it has one method and is used in one place, it should be a function; if it is a function called once, inline it

### Protocol red flags (from spec-validator findings)

1. **A custom `"evm"` CESR attachment type for receipts** — the receipt MUST use standard `NonTransReceiptCouples` (the backer signs the `rct` with its KERI key, exactly as the Cardano backer does via `hab.receipt(serder)`). The EVM attestation metadata (tx hash, block number, chain ID) is a separate out-of-band concern, not part of the KERI receipt. Any code that constructs a non-standard receipt attachment will cause TOAD satisfaction failures.
2. **A `BackerType` enum or registry dispatching between "witness receipt" and "ledger receipt"** — there is one receipt format (`NonTransReceiptCouples`), used identically by witnesses and ledger backers. No dispatch needed.

### Reorg testing (verified approach -- no mocks needed)

anvil's `evm_snapshot` + `evm_revert` RPC methods can simulate chain reorganizations without mocking. This was experimentally verified against anvil 1.2.1:

1. Snapshot at block N
2. Mine blocks N+1 through N+12, anchoring events in some of them
3. Record block hashes for these blocks
4. `evm_revert` to block N (chain is now shorter -- blocks N+1..N+12 are gone)
5. Mine NEW blocks N+1 through N+12 with different transactions
6. Block hashes at the same heights are now DIFFERENT

**Verified result**: Block 3 before revert had hash `0xbea6cd...`, after revert+remine had hash `0xf17598...`. anvil produces different block hashes when different transactions are included because the block hash depends on the transaction trie root, parent hash, and timestamp.

This is NOT mocking -- it is real EVM state manipulation using anvil's built-in RPC methods. The Crawler's reorg detection (comparing stored block hashes against current chain) can be fully tested this way. A mock RPC layer is NOT needed and would violate Rule 1.

**Known limitation**: This approach only simulates reorgs where different transactions are included in the alternate chain. In production Ethereum, reorgs can also produce blocks at the same height with the same transactions in a different order (MEV reordering), which also changes the block hash. For the Crawler's purposes this distinction does not matter -- any block hash change at a given height triggers requeue -- but it is worth noting that the test environment does not cover the MEV-reorder case.

### Batch failure testing (verified approaches -- no mocks needed)

Two rule-compliant approaches for testing batch transaction failures:

1. **Deliberate gas underestimation**: Set the `gas` parameter to a value too low for the batch size. The transaction reverts with out-of-gas on real anvil. Tests that the Queuer's retry logic correctly requeues events.

2. **Sabotaged test contract**: Deploy a modified KERIBacker contract (in `contracts/test/`) that reverts on the Nth `_anchor` call. The Queuer submits a real batch, the real transaction reverts, and the retry logic must handle it. This is a REAL contract with REAL execution -- it just has revert logic baked in for testing.

### Architecture red flags

1. **The `ethereuming.py` module importing from `backering.py`** — dependency should flow one way: `backering` -> `ethereuming`, not circular
2. **A `models.py` or `types.py` defining data classes that are only used as function arguments** — pass the values directly
3. **An event bus, observer pattern, or pub/sub system** — for a system with one producer and one consumer, direct function calls are simpler and debuggable
4. **Retry logic with configurable backoff strategies** — start with a simple loop; add complexity only when the simple version fails in production

---

## Summary: What to Replicate vs. What to Avoid from the Cardano Backer

### Replicate

- Real keripy objects in tests (Habery, Hab, Kevery, Parser, serdering)
- Real key events generated from real identities with real signatures
- Controller Habs that list the backer in their witness set
- Direct testing through the HTTP interface (Falcon test client)
- Queuing a real event and verifying it reaches the ledger
- Session-scoped infrastructure fixtures (Habery, chain connection)

### Avoid

- The Cardano conftest's hard dependency on a pre-running external process (Ogmios/devnet) — our conftest starts anvil itself as a subprocess, making tests self-contained
- TODO comments in implementation code (Cardano backer has at least one in `queueing.py`)
- The `TestBase` class hierarchy in Cardano's `helper.py` — a base test class with setup/teardown methods is unnecessary when pytest fixtures handle lifecycle; it is also a premature abstraction (one base class, one "subclass" pattern)
- The `is_process_running` check that shells out to `lsof` — fragile and platform-specific; our anvil fixture manages the process lifecycle directly
- Sleeping with `time.sleep(1)` in a polling loop without a maximum timeout — always use a deadline
