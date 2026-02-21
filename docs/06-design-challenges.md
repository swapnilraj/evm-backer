# EVM Backer Design Challenges

Devil's advocate review of `evm-backer-spec.md`. Issues ranked by severity: issues that would cause protocol incompatibility or security failures are listed first, followed by architectural concerns, then cost/efficiency problems.

---

## CRITICAL: Protocol Correctness

### C1. Ed25519 + secp256k1 dual-key derivation violates the KERI backer identity model

**Spec reference**: Section 2.3

**The problem**: The spec derives two independent keypairs from a single salt -- an Ed25519 keypair for KERI and a secp256k1 keypair for Ethereum -- using "domain separation." This fundamentally breaks the identity binding that Sam Smith described as essential in Issue #149:

> "The registrar's KERI identifier is derived from an inception event where the public key is a KERI formatted version of that registrar's access public key. This binding tightly the access identifier on the ledger to the KERI identifier used to designate that registrar as a backer."
>
> "For example bitcoin: Bitcoin address is a fingerprint of a EcDSA_secp_256_k1 public key. We put that public key in the inception event for that backer registrar and derive the resultant KERI identifier."

Smith explicitly says the public key in the KERI inception event should BE the ledger access key, not a different key derived from the same salt. The EVM backer cannot do this trivially because Ethereum requires secp256k1 while keripy defaults to Ed25519 for backers.

**Correction (from spec-validator source analysis)**: The Cardano backer does NOT actually use the same key for both KERI and Cardano. It loads the Cardano payment key from a separate environment variable (`WALLET_ADDRESS_CBORHEX`). Two different Ed25519 keys. So even the reference implementation does not follow Smith's ideal design from Issue #149. This weakens the argument that our spec is uniquely wrong -- both implementations deviate from the ideal.

**Why it matters**: With the current spec, a validator cannot derive the Ethereum address from the backer's KERI inception event alone. The validator must trust an out-of-band mapping (the configuration metadata) to link the KERI AID to the Ethereum address. This breaks the tight cryptographic binding Smith requires. If the salt is compromised, both keys are compromised simultaneously -- there is no independent recovery path. Worse, if the domain-separation derivation has any flaw (and no canonical standard for "Ed25519 seed -> secp256k1 key" exists), both identities are at risk.

**Proposed resolution**: The backer's KERI inception event should use a secp256k1 public key, not Ed25519. KERI supports secp256k1 via the `1AAA` derivation code. The KERI AID prefix would be derived from the same secp256k1 public key whose address is used on Ethereum. This is exactly what Smith described for Bitcoin. The backer would sign KERI receipts with secp256k1 instead of Ed25519 -- keripy supports this. This eliminates the dual-key problem entirely.

**Update (from spec-validator findings)**: The spec-validator confirmed that the Cardano backer uses Ed25519 for both KERI and Cardano (same key, same algorithm). The backer AID prefix starts with `B` (Ed25519N non-transferable). If we use secp256k1, the prefix derivation code changes. This is fine -- KERI supports multiple key types -- but the change must propagate through the entire codebase (receipt signing, OOBI format, AID resolution).

**Counter-argument to secp256k1 proposal**: The spec-validator notes that keripy expects `NonTransReceiptCouples` for backer receipts. If the backer uses secp256k1, the receipt signature would use secp256k1 CESR codes. This should work with keripy (it supports secp256k1 signatures) but is untested territory for backer receipts. The safer path might be to keep Ed25519 for KERI and accept the dual-key trade-off, while documenting the identity binding gap as a known limitation. **Needs KERI community input.**

**Implementation detail (from spec-validator keripy source analysis)**: `makeHab(transferable=False)` HARDCODES `code = coring.MtrDex.Ed25519N`. It ignores any `code=` parameter. To use secp256k1, you cannot use `makeHab` at all -- you must call `incept()` directly with `code=MtrDex.ECDSA_256k1N`. The `1AAA` derivation code exists in keripy, and `Signer(raw=seed, code=MtrDex.ECDSA_256k1_Seed)` works, but no one has used it for backer receipts. Receipt verification in `Kevery.processReceipt()` dispatches based on the verfer's derivation code -- it does NOT hardcode Ed25519 -- so secp256k1 receipts SHOULD work but needs a prototype test to confirm.

**Risk if not resolved**: The backer may be considered non-conforming by KERI validators that expect tight key binding per Issue #149.

---

### C2. The `rct` receipt with `"evm"` attestation type is not a valid KERI receipt

**Spec reference**: Section 6.2

**The problem**: The spec proposes attaching JSON metadata (`{"t": "evm", "cid": 1, ...}`) to the `rct` message. keripy's receipt processing expects either:

1. An indexed witness signature (for witness backers), or
2. A non-indexed signature (for non-transferable backers)

There is no CESR code for an "evm attestation type." keripy's `Kevery.processReceipt()` parses receipt attachments looking for signature groups. If it encounters an unknown attachment type, it will either ignore it or raise a parsing error. In neither case does the controller's keripy instance record the receipt as valid.

**Concrete failure mode (confirmed by spec-validator from keripy `parsing.py` source)**:

```python
# keripy parsing.py -- receipt handling
elif ilk in [Ilks.rct]:
    if not (exts['cigars'] or exts['wigers'] or exts['tsgs']):
        raise kering.ValidationError("Missing attached signatures on receipt msg...")
    kvy.processReceipt(**exts)
```

An "EVM attestation" would not parse into any of `cigars`, `wigers`, or `tsgs` (the CESR parser only recognizes standard attachment counter codes). All three would be empty/None, and `ValidationError` is raised. The receipt is rejected outright. TOAD never increments. A controller sends an event to the EVM backer, the backer anchors it on-chain, sends back a `rct` with an EVM attestation, and the controller's keripy raises `ValidationError`. The controller cannot publish subsequent events because it never accumulates enough backer acknowledgments.

**Why it matters**: This is a show-stopper. If the receipt format is wrong, the backer is useless -- controllers cannot use it.

**Proposed resolution**: The backer SHOULD sign the `rct` message with its KERI signing key (secp256k1 per C1, or Ed25519 if C1 is not adopted). This produces a standard non-transferable receipt that keripy already knows how to process. The EVM attestation (tx hash, block number, etc.) can be included as an additional out-of-band attachment or published via the backer's OOBI endpoint, but the core receipt MUST be a standard KERI signature. The Cardano backer does exactly this -- it signs a normal `rct` and the Cardano transaction metadata is a separate concern.

**Update (from spec-validator findings)**: The spec-validator confirmed the Cardano backer signs a standard `rct` with Ed25519 `NonTransReceiptCouples` and returns it IMMEDIATELY -- before the on-chain transaction is submitted. The on-chain anchoring happens asynchronously after the receipt. This is a critical design revelation: the receipt and the anchoring are decoupled.

**Risk if not resolved**: Complete protocol failure. No events will ever be receipted.

---

### C5. Receipt returned BEFORE on-chain anchoring creates a trust gap

**Spec reference**: Section 5.1, Section 6

**The problem** (surfaced by spec-validator): The Cardano backer returns the Ed25519-signed `rct` receipt immediately upon validation, then queues the event for on-chain publication asynchronously. The spec implies the receipt is sent after on-chain confirmation (Section 5.7: "wait CONFIRMATION_DEPTH blocks -> Receipt returned to controller"). These are contradictory models:

- **Receipt-first (Cardano model)**: Controller gets quick acknowledgment. But there is a window where the receipt exists but no on-chain anchor does. If the backer crashes, the controller has a receipt that no validator can verify on-chain.
- **Anchor-first (spec model)**: Controller waits minutes for on-chain confirmation. Slower, but the receipt is backed by on-chain evidence when issued.

**Why it matters**: If the backer issues a receipt and then crashes before anchoring, the controller believes its event is receipted. It may proceed to publish subsequent events that reference the receipted one. But validators checking the chain will find no anchor. The controller's KEL becomes unverifiable through the ledger backer path.

**Worse**: If the backer recovers and re-anchors, the event is eventually on-chain -- but during the gap, the controller was operating on a false assumption. If the backer never recovers, the controller has a signed receipt from a backer that never fulfilled its anchoring promise.

**Proposed resolution**: The spec must choose one model and document the trade-offs:

1. **Receipt-first** (match Cardano): Faster, but the receipt means "I validated and will anchor" not "I anchored." Validators who only check on-chain state may temporarily not see the event. This is acceptable if validators also accept the Ed25519 receipt as sufficient (falling back to on-chain for higher assurance).
2. **Anchor-first** (current spec): Slower, but the receipt is a stronger guarantee. This may cause timeout issues for controllers expecting quick witness-like responses.

The Cardano backer uses receipt-first. For compatibility, the EVM backer should too -- but the spec must clearly document the semantics.

---

### C6. The inception event `a` field cannot contain seals with `transferable=False`

**Spec reference**: Section 2.2

**The problem** (surfaced by spec-validator): keripy enforces that non-transferable identifiers (`transferable=False`) have an empty `a` (anchors) field. The spec proposes anchoring EVM configuration metadata as a seal in the `a` field:

```json
"a": [{ "d": "<SAID of EVM configuration metadata>" }]
```

This will not work with stock keripy. The `makeHab(transferable=False)` call produces an inception event with `"a": []`. Attempting to add an anchor seal would require modifying keripy's inception event generation, which violates the project's principle of reusing keripy unchanged.

The Cardano backer does not anchor any configuration metadata in its inception event -- it simply does not use the `a` field.

**Why it matters**: The configuration metadata binding described in Sections 2.2 and 4 is unimplementable without keripy modifications.

**Proposed resolution**: Follow the Cardano backer approach: do not anchor configuration metadata in the inception event. Serve configuration via the OOBI endpoint instead. This also resolves L2 (inflexible config SAID commitment) since mutable configuration would not be bound to an immutable inception event.

---

### C3. The endorsement policy is underspecified and may be wrong

**Spec reference**: Section 5.4

**The problem**: The spec says:

> "the backer only anchors events that are themselves valid key events (i.e., events the backer has received and validated via keripy). The backer does not independently verify seals in the controller's KEL before anchoring -- keripy's Kevery performs this validation as part of standard event processing."

This conflates two different things:

1. **Event validity** -- Is the event well-formed, properly signed, and correctly chained? (Kevery checks this.)
2. **Endorsement authorization** -- Has the controller committed to having THIS backer endorse THIS event? (Kevery does NOT check this for ledger backers.)

Smith's policy from Issue #149 is:

> "Backers may only endorse something previously committed to via a seal in the KEL."

This means: a validator can drop any backer endorsement that is not anchored in the controller's prior KEL. But the backer itself should check that the controller has designated it as a backer in the controller's `b` field.

**Correction (from spec-validator keripy source analysis)**: Kevery does NOT check whether the processing node is in the controller's backer list. Kevery validates event chaining and signatures only. The `b` field check is done explicitly by the application layer -- in the Cardano backer, it is in `ReceiptEnd.on_post`: `if self.hab.pre not in wits: raise HTTPBadRequest`. This is backer-specific logic, not a Kevery feature. Our spec must implement this check explicitly.

**Why it matters**: Without this check, any controller could submit events to the backer and have them anchored on-chain, consuming the backer's gas/ETH. This is a denial-of-service vector.

**Update (from spec-validator findings)**: The spec-validator confirmed the Cardano backer DOES perform this check: `if self.hab.pre not in wits: raise HTTPBadRequest`. So the check exists in the reference implementation but is missing from our spec.

**`lax=True` concern -- RESOLVED (from spec-validator keripy source trace)**: The backer uses `Kevery(lax=True, local=False)`. `lax=True` is called "promiscuous mode" in the keripy source (`eventing.py` line 3912). It does NOT weaken any cryptographic validation -- signature verification, event chaining, sequence number checks, and threshold validation all run identically regardless of `lax`. It only affects three things: (1) cue routing for own events (irrelevant for a backer processing other controllers' events), (2) whether the node stores its own receipts (minor), and (3) whether key state notices from untrusted sources are accepted (appropriate for a public backer that serves many controllers). The Cardano backer uses `lax=True` correctly, and the EVM backer should too. **This is not a security concern.**

**Proposed resolution**: After Kevery validation, the backer must explicitly verify that its own AID appears in the controller's `b` field (witness list) for the current key state. Reject events from controllers that have not designated this backer. This matches the Cardano backer behavior.

---

### C4. `sn` field type mismatch: `uint64` parameter vs `uint32` storage

**Spec reference**: Section 3.1-3.2

**The problem**: The `anchorEvent` function signature uses `uint64 sn`, but the `AnchorRecord` struct stores `uint32 sn`. This means:

```solidity
rec.sn = uint32(sn);  // Silent truncation for sn > 2^32 - 1
```

KERI sequence numbers are unbounded integers represented as hex strings. While it is unlikely a real KEL would exceed 2^32 events (~4 billion), the silent truncation is a correctness bug. A sequence number `0x100000000` would be stored as `0`.

**Why it matters**: Silent data corruption. The `getAnchor` function returns the truncated `sn`, which would not match the actual event.

**Proposed resolution**: Use `uint64` consistently in the struct, or remove `sn` from the struct entirely since the mapping key `(prefix, sn)` already encodes it. Storing it redundantly in the struct wastes a storage slot.

---

## HIGH: Security

### H1. ~~The `onlyBacker` modifier is a single point of failure with no recovery path~~ — RESOLVED

**Spec reference**: Section 3.2

**Resolution (Feb 2026)**: The modular verifier registry design eliminates this problem entirely.

`KERIBacker` no longer stores a backer pubkey or uses `onlyBacker`. Instead:
- `KERIBacker.owner` (GLEIF's multisig) governs `approveVerifier`/`revokeVerifier`
- `Ed25519Verifier.owner` (GLEIF's multisig) governs `approveBacker`/`revokeBacker`

If a QVI backer's Ed25519 key is compromised, GLEIF calls `Ed25519Verifier.revokeBacker(compromisedPubKey)`. The attacker can no longer anchor events. GLEIF then calls `approveBacker(newPubKey)` for the replacement key. No contract redeployment, no controller migration, no historical anchor disruption — `KERIBacker` and all its anchors remain intact.

**Original problem** (for reference): The old design used `address public immutable backer`. If the backer's Ethereum private key was compromised, the attacker could anchor arbitrary events. The immutable address meant the entire contract had to be redeployed and all controllers notified.

---

### H2. First-seen policy is NOT safe from front-running on public mempools

**Spec reference**: Section 3.2, the `_anchor` function

**The problem**: The spec claims the `rec.exists` check provides a first-seen policy. Within a single transaction, this is atomic (Solidity storage writes are atomic within a tx). But on a public Ethereum mempool:

1. Backer submits `anchorBatch([{prefix: X, sn: 5, said: A, ...}])`
2. An attacker sees this in the mempool
3. Attacker front-runs with `anchorEvent(X, 5, B, ...)` using higher gas (but they cannot call this -- `onlyBacker` prevents it)

Wait -- `onlyBacker` actually prevents this. Only the authorized backer address can call `anchorEvent`. So front-running by external attackers is not possible. The real risk is different:

**The actual risk**: If the backer's Ethereum key is compromised (see H1), the attacker can race the legitimate backer to anchor conflicting events. But this is subsumed by H1 -- key compromise is the root issue.

**A subtler problem**: The backer itself could be compromised at the application level (not key compromise, but logic compromise -- e.g., a bug in validation that lets a bad event through). Once anchored, the first-seen policy means the correct event can never be anchored at that `(prefix, sn)`. The only signal is the `DuplicityDetected` event, but there is no recovery mechanism.

**Proposed resolution**: This is inherent to immutable first-seen policies. Document clearly that once an incorrect event is anchored, the only recovery is contract redeployment. Consider adding an `emergencyPause()` function to halt anchoring if the backer detects compromise.

---

### H3. Dual-key compromise correlation

**Spec reference**: Section 2.3

**The problem**: Both keys (Ed25519 for KERI, secp256k1 for Ethereum) are derived from the same salt. Compromise of the salt compromises both. There is no independent recovery: you cannot rotate the KERI key without also rotating the Ethereum key, and vice versa.

In contrast, if the keys were independently generated, compromise of the Ethereum key would not affect the KERI AID, and the controller could continue using the backer's KERI identity while deploying a new contract with a new Ethereum key.

**Why it matters**: Correlated key compromise violates defense-in-depth. In security, independent keys provide independent failure modes.

**Update (from spec-validator findings)**: The spec-validator raises an interesting counter-point: with dual keys, compromise of the Ed25519 key allows forging KERI receipts but does not allow on-chain anchoring (secp256k1 required). Compromise of the secp256k1 key allows on-chain anchoring but the KERI receipts would still be signed by the legitimate Ed25519 key. In theory, this provides partial defense-in-depth.

**Devil's advocate response**: This "partial independence" is illusory. Both keys come from the same salt. If an attacker obtains the salt (which is the likely compromise vector -- it is a single file/env var on the backer server), both keys are compromised simultaneously. The only scenario where dual keys help is if an attacker compromises the derived key material but not the salt -- e.g., extracting the secp256k1 private key from memory but not the salt from disk. This is an extremely narrow threat model. The complexity cost of dual-key management (two derivation paths, two signing operations, potential for implementation bugs in the derivation) outweighs this marginal benefit.

**Proposed resolution**: If C1 is adopted (secp256k1 for both KERI and Ethereum), this issue becomes moot -- there is only one key, and its compromise is a single, well-understood failure mode with a clear recovery path (controller rotates the backer in their KEL). The correlated dual-key model is actually worse than a single shared key because it creates the illusion of independence while adding implementation complexity.

---

## HIGH: Architecture

### A1. Storing raw CESR bytes in contract storage is prohibitively expensive and unnecessary

**Spec reference**: Section 3.1, `bytes raw` parameter

**The problem**: The contract stores `bytes raw` (full CESR-encoded event bytes) via the `KERIEventAnchored` event log AND processes it through `_anchor`. At ~500 bytes per event:

**Gas cost for storage**: Storing 500 bytes costs ~16 * 500 = 8,000 gas for non-zero bytes via `SSTORE` -- but wait, the `raw` bytes are NOT stored in contract storage. Looking at the `_anchor` function, `raw` is only used in the `emit KERIEventAnchored(...)` event log. Event log storage costs ~375 gas per byte (8 gas/byte for data + 375 gas per topic). For 500 bytes: ~4,000 gas for data + 375 * 3 topics = 5,125 gas overhead. Total: ~9,125 gas per event just for the raw bytes.

But the real question: **is `raw` necessary?** The `isAnchored(prefix, sn, said)` function does not use `raw`. The raw bytes are only in the event log, which is NOT readable by other smart contracts. Event logs can only be read off-chain via `eth_getLogs`. So the raw bytes provide no on-chain benefit.

**Why it matters**: For a batch of 20 events, the raw bytes add ~182,500 gas (~$0.55 at 30 gwei, ~$5.50 at 300 gwei). This is pure waste if the only on-chain consumer is `isAnchored`. The raw bytes could instead be stored off-chain (IPFS, the backer's own API, or reconstructed from the controller's KEL).

**Proposed resolution**: Remove `bytes raw` from `anchorEvent` and `anchorBatch`. Remove it from the `KERIEventAnchored` event as well (or make it optional via a separate function). The SAID is a content-addressed identifier -- anyone with the event bytes can verify the SAID matches. The backer's HTTP endpoint already serves the full event bytes to anyone who queries it.

---

### A2. The backer service is a required intermediary -- no direct-to-contract path exists

**Spec reference**: Section 5.1

**The problem**: The spec requires controllers to run their events through the backer service (POST to HTTP endpoint -> keripy validation -> queue -> Ethereum tx). There is no path for a controller to submit directly to the contract.

This means:
1. The backer service is a single point of availability failure
2. If the backer service goes down, no events can be anchored
3. Controllers must trust the backer service to be online and responsive

**Why this might be acceptable**: The backer service performs validation that the contract cannot do (KERI signature verification in Ed25519 is not practical in Solidity). The `onlyBacker` modifier ensures only validated events reach the contract. This is architecturally correct -- the contract is a dumb anchor, the backer is the validator.

**Why it is still a problem**: Unlike witness backers (where multiple independent witnesses provide redundancy), the EVM backer is a single service. If it goes down, the entire ledger backer is unavailable. The spec does not address high availability, failover, or redundancy.

**Proposed resolution**: Document that the backer service should be deployed with standard HA patterns (load balancer, multiple replicas sharing the same keripy database and Ethereum key). Alternatively, consider supporting multiple authorized backer addresses in the contract (a set rather than a single address) for operational redundancy -- though this complicates the security model.

---

### A3. Batch failure atomicity: all-or-nothing with no granular retry

**Spec reference**: Section 5.5

**The problem**: `anchorBatch` processes events in a loop. If the Ethereum transaction reverts (out of gas, RPC error, nonce collision), ALL events in the batch are lost. The spec says events are "requeued" on timeout (Section 5.7), but:

1. If the tx reverts, the backer must detect the revert, identify which events were in the batch, and requeue them. The spec does not describe this mechanism.
2. If the tx succeeds partially (it cannot -- EVM transactions are atomic), this is not an issue. But if the tx runs out of gas mid-execution, the entire batch reverts.
3. Gas estimation for variable-length `bytes raw` across 20 events is unreliable. A batch might estimate at 290,000 gas but actually cost 310,000 due to storage slot cold/warm access patterns.

**Why it matters**: Lost events mean controllers never get receipts. Controllers must re-submit, but the spec does not describe a retry protocol from the controller's perspective.

**Proposed resolution**:

1. The Crawler (Section 5.7) should check for reverted transactions explicitly, not just missing receipts.
2. On revert, requeue all events from the failed batch.
3. Reduce batch size dynamically if gas estimation fails repeatedly.
4. Consider adding a gas buffer (e.g., estimate * 1.2) to prevent out-of-gas reverts.
5. Document the controller retry behavior: if no receipt within N minutes, re-submit the event.

---

### A4. Polling-based confirmation is fragile during RPC downtime

**Spec reference**: Section 5.7

**The problem**: The Crawler polls `eth_getTransactionReceipt` on a fixed interval. If the RPC endpoint is down:

1. Pending transactions are not monitored
2. The TIMEOUT_DEPTH counter (32 blocks) continues advancing based on block numbers
3. When RPC comes back, the backer may incorrectly timeout transactions that were actually confirmed during the outage
4. This could lead to double-submission: the backer requeues events that are already anchored on-chain

**Why it matters**: Double-submission triggers `DuplicityDetected` events for the same SAID (the `rec.eventSAID != eventSAID` check would be false, so it would just silently return). This wastes gas but is not a correctness issue. However, if the backer requeues and the events were NOT confirmed (tx dropped from mempool during outage), then the retry is correct.

The real risk: the backer's nonce management becomes corrupted during RPC downtime. If the backer increments the nonce locally but the tx was never broadcast (or was dropped), subsequent transactions will fail with "nonce too high."

**Proposed resolution**:

1. Use `eth_getTransactionCount(backer, "pending")` to resync nonce after RPC recovery.
2. Implement exponential backoff for RPC polling, not fixed interval.
3. Use multiple RPC endpoints with failover (the spec already lists multiple in the config, but the Crawler implementation must actually use them).
4. Track RPC downtime separately from block-based timeout -- do not advance the timeout counter when RPC is unreachable.

---

## MEDIUM: Protocol Design

### M1. KERI prefix to `bytes32` encoding is lossy and ambiguous

**Spec reference**: Section 3.3

**The problem**: The prefix encoding function:

```python
def prefix_to_bytes32(qb64_prefix: str) -> bytes:
    raw = base64.urlsafe_b64decode(qb64_prefix + "==")
    return raw[:32].ljust(32, b'\x00')
```

This decodes the full qb64 string (including the derivation code) and takes the first 32 bytes. Problems:

1. **Lossy**: KERI prefixes can be longer than 32 bytes (e.g., multi-sig prefixes, different derivation codes). Truncation to 32 bytes loses information.
2. **Ambiguous padding**: Adding `"=="` to the qb64 string before decoding is incorrect. Base64url strings have specific padding requirements based on length. Blindly adding `"=="` may produce incorrect decoding.
3. **Derivation code included**: The first 1-4 characters of a qb64 string are the derivation code, not key material. Including them in the bytes32 means different derivation codes for the same key material produce different bytes32 values. This is correct (different derivation = different identity) but should be explicit.
4. **Collision risk**: Two different qb64 prefixes that share the same first 32 decoded bytes would collide in the contract mapping.

**Why it matters**: If the encoding is wrong, `isAnchored` lookups will fail -- validators will not find events that were actually anchored.

**Proposed resolution**: Use the SAID (which is always exactly 32 bytes when decoded from qb64 Blake3) as the primary key instead of the prefix. Or use `keccak256(bytes(qb64_prefix))` as the bytes32 key -- this is collision-resistant and handles arbitrary-length prefixes.

---

### M2. Multi-chain backer identity creates ambiguous verification

**Spec reference**: Section 4 (configuration metadata) and Section 10, Question 3

**The problem**: The spec allows a single backer AID to anchor events on multiple chains simultaneously (mainnet + Arbitrum, etc.). A validator receiving a receipt must know which chain to check. The receipt includes `cid` (chain ID), but:

1. If the backer anchors the same event on both mainnet and Arbitrum, which anchoring is authoritative?
2. If the backer anchors event N on mainnet but event N+1 on Arbitrum (due to gas costs), the validator must check multiple chains.
3. The `isAnchored` check is per-contract. A validator verifying on mainnet will not see events anchored on Arbitrum.

**Why it matters**: Multi-chain creates split-brain scenarios. A sophisticated attacker could anchor conflicting events on different chains (same prefix, same sn, different SAID) -- each chain's first-seen policy would accept its respective version, and validators checking different chains would see different states.

**Proposed resolution**: One AID, one chain. If you want to anchor on Arbitrum, deploy a separate backer with a separate AID. Controllers that want both mainnet and L2 protection put both backers in their `b` field. This is simpler, unambiguous, and consistent with KERI's model where each backer is an independent entity.

---

### M3. The Cardano backer's "metadata storage" model may actually be superior for data availability

**Spec reference**: Section 8 (comparison table)

**The problem**: The spec frames contract storage as an advantage: "readable by other smart contracts." But:

1. The contract only stores `(eventSAID, blockNumber, sn, exists)` -- 4 values per anchor. It does NOT store the full event.
2. The `raw` bytes are in event logs, not storage. Event logs are NOT readable by smart contracts.
3. The Cardano backer stores the full CESR event bytes as transaction metadata. This is permanently available on-chain and indexable by any Cardano node.
4. On Ethereum, event logs can be pruned by nodes running in "light" mode. Historical logs are not guaranteed to be available without an archive node.

**Why it matters**: For long-term data availability, the Cardano model (full event bytes in transaction metadata, permanently on-chain) may be stronger than the EVM model (only a SAID hash in storage, full bytes in prunable event logs).

**Proposed resolution**: Acknowledge this trade-off in the spec. For data availability, the backer's HTTP endpoint is the primary source of full event data, not the contract. The contract's role is verification (`isAnchored`), not data availability. If full on-chain data availability is required, consider storing a CID (IPFS content hash) alongside the SAID.

---

### M4. No mechanism to handle keripy escrow overflow or stale events

**Spec reference**: Section 5.3

**The problem**: The spec says "Out-of-order events are held in keripy's standard escrow until predecessors arrive." But:

1. If a predecessor never arrives, the escrowed event stays in memory/database forever.
2. keripy's escrow has configurable timeouts, but the spec does not document what happens when an escrowed event times out.
3. A malicious controller could flood the backer with out-of-order events to consume memory/storage.

**Why it matters**: Resource exhaustion attack vector. The backer must handle this gracefully.

**Proposed resolution**: Document keripy's escrow timeout behavior. Set reasonable limits (e.g., escrow timeout of 1 hour, max escrowed events per prefix). Note that this is likely handled by keripy defaults, but the spec should make this explicit.

---

## LOW: Cost and Efficiency

### L1. Gas cost estimates in Section 9.3 are significantly understated

**Spec reference**: Section 9.3

**The problem**: The spec claims:

- Single event: ~80,000 gas
- Batch of 20: ~300,000 gas

The actual costs:

- `anchorEvent` with 500 bytes of `raw` data:
  - 21,000 base tx cost
  - ~20,000 for `SSTORE` of new AnchorRecord (cold slot: 22,100 gas for first write)
  - ~8,000 for event log topics (3 indexed topics)
  - ~4,000 for event log data (500 bytes raw)
  - ~5,000 for calldata (500 bytes at 16 gas/byte non-zero)
  - Total: ~58,100 per event + 21,000 base = ~79,100 for single event

OK, 80,000 is roughly correct for a single event. But for a batch of 20:

- 21,000 base (once)
- 20 * ~58,100 per event = 1,162,000
- Total: ~1,183,000 gas -- NOT 300,000

The spec's 300,000 estimate is off by ~4x. At 30 gwei, that is ~0.035 ETH per batch, not 0.009 ETH.

**Why it matters**: Operational cost planning. If a production backer processes 100 events/day, gas costs at mainnet prices could be significant.

**Proposed resolution**: Recalculate gas costs with realistic estimates. If `raw` bytes are removed (per A1), costs drop substantially: ~25,000 per event in a batch, ~521,000 for a batch of 20. Still nearly 2x the spec's estimate.

---

### L2. Configuration metadata SAID commitment in inception event is inflexible

**Spec reference**: Section 2.2, the `a` field

**The problem**: The inception event commits to a SAID of the configuration metadata (contract address, chain ID, RPC URLs). Since the inception event is immutable (non-transferable AID, no rotation), this means:

1. If the contract is redeployed (new address), the configuration metadata SAID changes, but the inception event cannot be updated.
2. If RPC URLs change (very common -- providers deprecate endpoints), the metadata SAID is stale.
3. The backer would need a new AID for any configuration change.

**Why it matters**: Operational inflexibility. RPC URL changes are routine and should not require redeploying the backer's identity.

**Proposed resolution**: Per Sam Smith's discussion in Issue #149, use the "virtual TEL" pattern: configuration metadata is attached to events in the controller's KEL (not the backer's inception event). The backer's inception event only commits to the backer's public key -- configuration is mutable and controller-anchored. Alternatively, only commit to immutable configuration (chain ID, contract address) in the inception event and serve mutable configuration (RPC URLs) via the OOBI endpoint.

---

## Summary Table

| ID | Severity | Category | Issue |
|----|----------|----------|-------|
| C1 | CRITICAL | Protocol | Dual-key derivation violates KERI backer identity binding |
| C2 | CRITICAL | Protocol | `rct` receipt with EVM attestation is not a valid KERI receipt |
| C3 | CRITICAL | Protocol | Endorsement policy does not verify backer designation in `b` field |
| C4 | CRITICAL | Contract | `sn` type mismatch: uint64 param vs uint32 storage |
| C5 | CRITICAL | Protocol | Receipt returned before vs after on-chain anchoring -- contradictory models |
| C6 | CRITICAL | Protocol | Inception event `a` field cannot contain seals with `transferable=False` |
| H1 | HIGH | Security | Immutable backer address with no rotation/recovery |
| H2 | HIGH | Security | First-seen policy recovery after backer logic compromise |
| H3 | HIGH | Security | Correlated key compromise from shared salt |
| A1 | HIGH | Architecture | Raw CESR bytes in event logs are expensive and unnecessary |
| A2 | HIGH | Architecture | Backer service is single point of availability failure |
| A3 | HIGH | Architecture | Batch failure has no granular retry mechanism |
| A4 | HIGH | Architecture | Polling-based confirmation fragile during RPC downtime |
| M1 | MEDIUM | Protocol | Prefix-to-bytes32 encoding is lossy and ambiguous |
| M2 | MEDIUM | Protocol | Multi-chain backer creates split-brain verification |
| M3 | MEDIUM | Architecture | Contract storage may be weaker than Cardano metadata for data availability |
| M4 | MEDIUM | Protocol | No escrow overflow or stale event handling |
| L1 | LOW | Cost | Gas estimates understated by ~4x |
| L2 | LOW | Architecture | SAID commitment in inception event is inflexible for mutable config |

---

## Recommendations

The changes that would resolve the highest number of issues, in priority order:

1. **Sign standard `rct` receipts with Ed25519 `NonTransReceiptCouples`, treat EVM anchoring as an orthogonal concern** (resolves C2, C5). The backer signs receipts like any KERI backer and returns them immediately (receipt-first model, matching Cardano). The on-chain anchor happens asynchronously and provides additional assurance that validators can optionally verify. This makes the backer work with unmodified keripy and does not require a new CESR code.

2. **Remove the `a` field seal from the inception event** (resolves C6, L2). Follow the Cardano backer approach: no configuration metadata in the inception event. Serve configuration via the OOBI endpoint.

3. **Add `b` field verification** (resolves C3). After Kevery validation, check `self.hab.pre in wits` before anchoring. Match the Cardano backer behavior.

4. **Key type decision: secp256k1 vs Ed25519** (affects C1, H3). Two viable paths:
   - **Option A (secp256k1 for KERI)**: One key, tight binding per Smith's Issue #149 guidance. Resolves C1 and H3 completely. Risk: untested with keripy's `NonTransReceiptCouples`.
   - **Option B (keep Ed25519 for KERI, separate secp256k1 for Ethereum)**: Two keys, weaker binding. Simpler keripy integration. Document the identity binding gap as a known limitation.
   - **Recommendation**: Needs KERI community input. Prototype Option A and test whether keripy accepts secp256k1 `NonTransReceiptCouples`. If it does, Option A is clearly superior.

5. **Fix `uint32` truncation** (resolves C4). Use `uint64` consistently or remove `sn` from the struct.

6. **Remove `bytes raw` from contract interface** (resolves A1, partially L1). The SAID is sufficient for on-chain verification. Raw event bytes can be served via the backer's HTTP endpoint.

These changes convert the EVM backer from "incompatible with KERI" to "compatible with KERI and provides additional on-chain verifiability" while reducing gas costs and implementation complexity.
