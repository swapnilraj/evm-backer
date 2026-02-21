# vLEI Technical Stack: KERI, ACDC, CESR

The vLEI technical stack is built on three interrelated IETF specifications developed by **Samuel M. Smith** (ProSapien LLC / WebOfTrust) and incubated at the **Trust over IP (ToIP) Foundation**.

---

## KERI — Key Event Receipt Infrastructure

KERI is the foundational identity and key management protocol. It solves the "universal secure attribution problem" — creating a cryptographic root-of-trust for digital identifiers independent of any centralised authority, blockchain, or distributed ledger.

### Autonomic Identifiers (AIDs)

AIDs are **self-certifying identifiers** derived directly from cryptographic key material:
- **Decentralised** — no registration required
- **Portable** — not tied to any specific infrastructure
- The AID prefix is a cryptographic digest of the initial public key (or digest of initial key set for multi-signature)
- GLEIF controls a **Root AID** which is the cryptographic root of trust for all vLEI credentials

### Key Event Log (KEL)

The KEL is an **append-only, cryptographically chained log** of all key state transitions for an identifier. All events reference the prior event's digest (backward chaining) and commit to future keys (forward chaining via pre-rotation).

**Event types:**

| Code | Name | Purpose |
|---|---|---|
| `icp` | Inception | Establishes a new AID with initial keys and witness configuration |
| `rot` | Rotation | Rotates to new signing keys, revealing pre-committed next keys |
| `ixn` | Interaction | Anchors data to the KEL without changing keys (used for credential issuance/revocation anchors) |
| `dip` | Delegated Inception | Creates a delegated AID |
| `drt` | Delegated Rotation | Rotates a delegated AID |
| `rct` | Receipt | Witness/backer acknowledgment of an event |

**Key inception event fields:**

```json
{
  "v":  "KERI10JSON0000ef_",   // version string
  "t":  "icp",                  // event type
  "d":  "<SAID>",               // self-addressing identifier of this event
  "i":  "<AID prefix>",         // controller identifier
  "s":  "0",                    // sequence number
  "kt": "1",                    // signing key threshold
  "k":  ["<Ed25519 public key qb64>"],  // current signing keys
  "nt": "1",                    // next key threshold
  "n":  ["<digest of next key>"],       // pre-rotation commitment
  "bt": "3",                    // backer threshold (TOAD)
  "b":  ["<backer AID>", ...],  // backer set
  "c":  [],                     // configuration traits
  "a":  []                      // anchors / seals
}
```

### Pre-Rotation

KERI's most novel mechanism. When establishing or rotating keys, controllers cryptographically **commit to the NEXT keys** they plan to use via a digest:
- Actual next keys are never revealed until needed
- When rotation occurs, the new event reveals those pre-committed keys
- Provides **forward security**: even if current keys are compromised, pre-rotated keys remain secure
- Offers **quantum resistance**: digest commitments survive future cryptographic developments

### Witnesses and KAWA

Witnesses are designated entities that receive, verify, and store key events:
- They add their own signatures (receipts) to create redundancy
- Controllers specify a **TOAD** (Threshold Of Accountable Duplicity) — minimum witnesses that must receipt an event
- **KAWA** (KERI Agreement Algorithm for Witness Agreement) provides Byzantine-fault-tolerant consensus
- The vLEI EGF requires a minimum pool of **5 witnesses**

### Watchers and Duplicity Detection

Watchers monitor KELs across the network:
- Implement a **first-seen policy**: the first version of any event is recorded
- Conflicting key states (duplicity) become cryptographically evident
- Makes it impossible for a controller to secretly present two different key states to different parties

### Cryptographic Algorithms

Per the vLEI EGF:
- Signing: **Ed25519** (primary) — 128-bit security
- Hashing: **BLAKE3** and SHA-3 family
- All key pairs must provide approximately **128 bits of cryptographic strength**

---

## ACDC — Authentic Chained Data Containers

ACDCs are the **credential format** used for vLEI credentials. They are being standardised through the ToIP Foundation (`draft-ssmith-acdc`) and are a variant of W3C Verifiable Credentials with significant enhancements.

### Core Structure

```json
{
  "v": "ACDC10JSON000197_",        // version string
  "d": "E...",                      // SAID of the entire ACDC
  "i": "E...",                      // issuer AID
  "s": "E...",                      // schema SAID
  "ri": "E...",                     // revocation registry AID
  "a": {                            // attributes block
    "d": "E...",                    // SAID of attributes block
    "i": "E...",                    // issuee AID
    "lei": "549300MLUDYVRQOOXS22",  // the LEI code
    "..."
  }
}
```

### SAID — Self-Addressing Identifier

A SAID is a **cryptographic digest of the data it addresses, embedded within the data itself**:
- The `d` field of an ACDC is computed from the ACDC's content
- SAIDs are always calculated in **compacted form** (nested blocks replaced by their own SAIDs)
- Makes the top-level SAID stable and verifiable regardless of which blocks are expanded
- Content-addressed: the SAID of a credential uniquely and permanently identifies it

### Credential Chaining

The defining feature of ACDC vs. W3C VC is normative support for **credential chaining**:
- ACDCs can be chained together as a **directed acyclic graph (DAG)**
- **Edges** connect two ACDCs with logical operators:
  - `I2I` (Issuer-to-Issuee): The issuer of one credential must be the holder of the previous
  - `NI2I` (Not-Issuer-to-Issuee): Alternative trust model
- Edge groups use boolean logic (AND, OR, NOR)
- If any edge in the chain is invalid, the entire chain is invalid
- This chaining creates the **vLEI Trust Chain**: every credential's provenance can be traced cryptographically back to GLEIF's Root AID

### Selective Disclosure

- The attributes block has its own SAID, enabling **graduated disclosure**
- A holder can present only the SAID of an attribute block (proving it exists and hasn't changed) without revealing contents
- Optional `u` fields contain randomly generated salts (UUIDs), making it computationally infeasible to brute-force block contents even when the schema is known

### Compact vs. Full Forms

- **Compact form**: Nested blocks replaced by their SAIDs only
- **Full form**: All blocks expanded with full content
- Both carry the same top-level SAID — enables privacy-preserving presentations

### Revocation via PTEL

- Credential status tracked via a **Public Transaction Event Log (PTEL)** anchored to the issuer's KEL
- Revocation is cryptographically recorded and verifiable without contacting the issuer
- Revocation checks work at presentation time for real-time status verification

---

## CESR — Composable Event Streaming Representation

CESR is the **encoding standard** for all KERI messages and ACDC credentials.

Key features:
- **Text-binary composability**: Any CESR primitive converts between text (Base64url) and binary without loss and without a framing indicator
- **Self-framing**: Primitives are self-delimiting — no external length fields needed
- **Streaming-friendly**: Can be composed into streams for efficient transport

CESR primitives include:
- `v` — Version string (e.g., `"ACDC10JSON000197_"`)
- `d` — Event digest / SAID
- `i` — AID prefix
- `kt`, `k` — Current signing threshold and signing keys
- `nt`, `n` — Next signing threshold and next key digests (pre-rotation)

Supported encodings (proposed IANA media types):
- `application/cesr+json`
- `application/cesr+cbor`
- `application/cesr+msgpk`
- `application/cesr`

---

## OOBI — Out-of-Band Introduction

OOBIs are URLs that bootstrap trust by introducing an AID and a service endpoint where its KEL can be retrieved. They allow parties to discover each other's key state without pre-existing trust relationships.

Example:
```
http://witness.example.com:5642/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao/witness
```

---

## Signify / KERIA Architecture

The vLEI credential wallet infrastructure:

- **Signify Client**: Implements "signing at the edge" — private keys never leave the client environment. Acts as an embedded library in wallets/applications. Adds controller signatures to key events.
- **KERIA (KERI Agent)**: Backend infrastructure. Maintains KELs for each client instance and distributes signed logs to the witness network.
- **Witness Network**: Witnesses receive key events, add receipt signatures, store/distribute KELs.
- **Verifier**: Accesses KELs from multiple witnesses to validate signatures and credential presentations.

---

## Key IETF Drafts

| Draft | Description |
|---|---|
| `draft-ssmith-keri` | Key Event Receipt Infrastructure — core identity protocol |
| `draft-ssmith-acdc-03` | Authentic Chained Data Containers — credential format |
| `draft-ssmith-cesr` | Composable Event Streaming Representation — encoding |
| `draft-smith-satp-vlei-binding-01` | vLEI binding for Secure Asset Transfer Protocol |
| `draft-ssmith-said` | Self-Addressing Identifiers |

## References

- [KERI IETF Draft](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- [ACDC IETF Draft](https://datatracker.ietf.org/doc/draft-ssmith-acdc/)
- [WebOfTrust/vLEI GitHub — schemas and samples](https://github.com/WebOfTrust/vLEI)
- [Trust over IP — ACDC Task Force](https://trustoverip.org/blog/2024/03/21/authentic-chained-data-containers-acdc-task-force-announces-public-review/)
- [KERI Community — DIF](https://identity.foundation/keri/)
