# vLEI Integration into ERC-FIX
### A Proposal for Nethermind

---

## Executive Summary

ERC-FIX embeds standardized FIX protocol descriptors into tokenized securities, solving the N×M integration problem across trading infrastructure. But the specification contains a deliberate gap: **Merkle proofs verify that a field exists in the committed descriptor — they do not validate that the party named in that field actually is who they claim to be.**

This proposal describes how integrating the **verifiable Legal Entity Identifier (vLEI)** into ERC-FIX closes that gap. vLEI provides cryptographically verifiable organizational identity — anchored to GLEIF's global root of trust — for the exact party identification fields that FIX protocol already defines. Together, ERC-FIX and vLEI form a complete stack for institutional tokenized securities: machine-readable instrument descriptors plus cryptographic proof of who issued them and who is authorized to act on them.

We propose a four-phase implementation:

1. **Credential anchoring** — embed vLEI credential references in FIX descriptors, enabling immediate off-chain verification
2. **On-chain verifier infrastructure** — a `KERIVerifier` oracle contract and credential status registry
3. **Credential-gated descriptor management** — restrict descriptor updates to addresses holding valid OOR credentials from the issuing entity
4. **ERC-3643 compliance module** — enforce vLEI-based counterparty identity checks as transfer conditions

The resulting system positions Nethermind as the natural infrastructure layer connecting GLEIF's global identity ecosystem to Ethereum-native tokenized securities — a gap that no other team is better placed to fill.

---

## 1. Background

### 1.1 ERC-FIX

ERC-FIX standardizes tokenized security metadata by embedding FIX protocol descriptors on-chain as a Merkle commitment. The interface is minimal and composable:

```solidity
struct FixDescriptor {
    bytes32 schemaHash;   // FIX dictionary version
    bytes32 fixRoot;      // Merkle root of all committed fields
    address fixSBEPtr;    // SSTORE2 pointer to SBE-encoded payload
    uint32  fixSBELen;
    string  schemaURI;
}

interface IFixDescriptor {
    function getFixDescriptor() external view returns (FixDescriptor memory);
    function getFixRoot()       external view returns (bytes32);
    function verifyField(
        bytes calldata pathCBOR,
        bytes calldata value,
        bytes32[] calldata proof,
        bool[]    calldata directions
    ) external view returns (bool);
}
```

FIX tag 453 (Parties) is already included in the committed field set, with `PartyIDSource = "N"` designating LEI as the party identifier. So ERC-FIX tokens can today carry an issuer's 20-character LEI code as a committed, Merkle-provable field.

The specification explicitly acknowledges its own limit:

> **"No Semantic Guarantees: Merkle proofs verify field presence in the committed tree but do NOT validate data accuracy or real-world correspondence."**

### 1.2 vLEI

The verifiable Legal Entity Identifier (ISO 17442-3:2024) is a cryptographically signed credential built on the KERI + ACDC stack:

- **KERI** (Key Event Receipt Infrastructure) provides decentralized, self-certifying identifiers (AIDs) with pre-rotation and witness-based key state consensus
- **ACDC** (Authentic Chained Data Containers) are credentials with built-in chaining, SAID-based content addressing, and cryptographic revocation via on-chain-anchored PTELs
- **The trust chain** runs from GLEIF's multi-sig Root AID → Qualified vLEI Issuers (QVIs) → Legal Entities → authorized individuals

Five credential types form the chain:

| Credential | Issued by | Issued to | Purpose |
|---|---|---|---|
| QVI | GLEIF | QVI organization | Authorizes QVI to issue LE credentials |
| LE (Legal Entity) | QVI | Organization | Org's verifiable identity tied to its LEI |
| OOR AUTH | Organization LAR | QVI | Authorizes QVI to issue OOR for a named person |
| OOR (Official Org Role) | QVI | Individual | ISO 5009 role credential (CEO, CFO, Authorized Signatory, etc.) |
| ECR (Engagement Context Role) | QVI or Org | Individual | Functional/transactional role credential |

Every credential carries a **SAID** (Self-Addressing Identifier): a cryptographic digest of the credential's own content, embedded within it. SAIDs are content-addressed and tamper-evident by construction.

### 1.3 The Gap

ERC-FIX solves the **syntactic** problem: standardized, machine-readable token descriptors that any FIX-compatible system can parse without custom integration.

vLEI solves the **semantic** problem: cryptographic proof that the party identified in those descriptors is the legal entity they claim to be, and that the person acting on their behalf is actually authorized to do so.

Neither is sufficient alone. Together they cover the full trust stack required for institutional adoption.

---

## 2. Proposed Architecture

### 2.1 Conceptual Stack

```
┌─────────────────────────────────────────────────────┐
│              ERC-3643 Compliance Module             │  Transfer rules
│         (counterparty vLEI LE verification)         │
├─────────────────────────────────────────────────────┤
│           Credential-Gated Descriptor Mgmt          │  Update authorization
│        (OOR-gated FixDescriptor updates)            │
├─────────────────────────────────────────────────────┤
│              KERIVerifier + Status Registry         │  On-chain KERI oracle
│        (credential validity, AID key state)         │
├─────────────────────────────────────────────────────┤
│           vLEI Credential Anchoring in FIX          │  Credential references
│        (SAID fields in Parties group / ext)         │
├─────────────────────────────────────────────────────┤
│                     ERC-FIX Core                    │  FIX descriptor + Merkle
│           (IFixDescriptor, FixDescriptor)           │
└─────────────────────────────────────────────────────┘
```

Each phase builds on the previous. Phase 1 requires no on-chain KERI infrastructure and delivers immediate value. Phases 2–4 progressively increase trustlessness.

---

### Phase 1 — Credential Anchoring in FIX Descriptors

**Goal**: Allow any ERC-FIX token to reference a vLEI credential, enabling off-chain verification today with no new on-chain infrastructure.

#### 1a. FIX Convention: vLEI SAID in the Parties Group

FIX tag 447 (`PartyIDSource`) already defines `"N"` as LEI. We introduce a new convention:

| PartyIDSource value | Meaning |
|---|---|
| `"N"` | PartyID is a 20-character LEI (existing FIX standard) |
| `"V"` | PartyID is the SAID of an ACDC LE credential |

A token's Parties group entry identifying the issuer would carry **two entries**: one `"N"` entry with the raw LEI string, and one `"V"` entry with the SAID of the issuing organization's LE credential. Both become Merkle-committed fields in the ERC-FIX descriptor.

Example FIX Parties group representation:
```
453=2                          # Two party entries
448=549300MLUDYVRQOOXS22|447=N|452=13   # Issuer by LEI
448=ENPXp1vQ...RF6JwIuS|447=V|452=13   # Same issuer, vLEI LE credential SAID
```

Both entries are committed in the Merkle tree. Any counterparty can independently:
1. Extract the SAID from the descriptor via `verifyField()`
2. Resolve the SAID against KERI infrastructure (witnesses / GLEIF API)
3. Verify the LE credential is active (non-revoked via PTEL)
4. Confirm the LEI in the credential matches the `"N"` entry in the same Parties group

#### 1b. IVleiAugmented Extension Interface

Tokens that opt into vLEI anchoring implement a lightweight extension:

```solidity
/// @notice Extension of IFixDescriptor for tokens with vLEI credential anchoring.
interface IVleiAugmented is IFixDescriptor {

    struct VleiAnchor {
        bytes32 leSaid;        // SAID of the issuer's LE vLEI credential
        bytes32 leSchemaSaid;  // ACDC schema SAID (for schema verification)
        address verifier;      // KERIVerifier contract (address(0) if Phase 1 only)
    }

    /// @notice Returns the vLEI anchor for this token's issuing entity.
    function getVleiAnchor() external view returns (VleiAnchor memory);

    /// @notice Returns true if an on-chain KERIVerifier has confirmed credential validity.
    ///         Returns false if no verifier is configured (Phase 1: off-chain only).
    function isVleiValid() external view returns (bool);

    event VleiAnchorSet(bytes32 indexed leSaid, address indexed verifier);
    event VleiAnchorRevoked(bytes32 indexed leSaid, uint256 timestamp);
}
```

**Phase 1 deliverables**:
- FIX PartyIDSource `"V"` convention published as an ERC-FIX extension spec
- `IVleiAugmented` interface deployed
- Reference implementation of the off-chain resolution + verification script
- Integration guide for QVIs and token issuers

**What this unlocks immediately**: Institutional counterparties can verify, off-chain, that a token's issuer holds a valid vLEI before onboarding or settling. This alone satisfies many institutional KYB requirements without waiting for on-chain KERI infrastructure.

---

### Phase 2 — On-Chain KERI Verifier Infrastructure

**Goal**: Bring KERI credential status on-chain so smart contracts can query it trustlessly.

The core challenge: KERI is intentionally independent of any blockchain. Credential validity (revocation state) lives in PTELs anchored to off-chain KELs maintained by the issuing QVI and verified by witness networks. Bridging this to EVM requires an oracle.

#### 2a. KERIVerifier Contract

```solidity
/// @notice On-chain registry of vLEI credential status, updated by authorized relayers.
contract KERIVerifier {

    struct CredentialStatus {
        bool    valid;           // true = active, false = revoked/expired
        uint64  lastUpdated;     // block.timestamp of last relay update
        bytes32 issuerAid;       // AID of the QVI that issued this credential
        bytes32 issuerKeyHash;   // keccak256 of current issuer signing key (Ed25519)
        uint64  expiresAt;       // credential expiry (0 = no expiry)
    }

    mapping(bytes32 credentialSaid => CredentialStatus) public credentialStatus;

    event CredentialStatusUpdated(
        bytes32 indexed credentialSaid,
        bool    valid,
        bytes32 issuerAid,
        uint64  expiresAt
    );

    /// @notice Called by authorized relayer nodes to push credential status on-chain.
    /// @dev    Relayer must hold a valid relayer role credential; signature verified
    ///         against the stored relayer key set.
    function updateCredentialStatus(
        bytes32            credentialSaid,
        CredentialStatus calldata status,
        bytes   calldata   relayerSignature
    ) external;

    function isValid(bytes32 credentialSaid) external view returns (bool);
    function getStatus(bytes32 credentialSaid)
        external view returns (CredentialStatus memory);
}
```

#### 2b. KERI Witness Relay Network

Nethermind operates 20,000+ blockchain nodes globally. The same operational infrastructure supports a **KERI Witness Relay Service**:

- Nethermind runs a set of KERI watchers that monitor QVI witness networks
- Watchers detect credential issuance events (anchored `ixn` events in the QVI's KEL)
- Watchers detect revocation events (PTEL updates)
- Authorized relayer nodes (Nethermind-operated, multi-sig governed) submit status updates to `KERIVerifier`
- Update frequency: configurable per credential type (e.g., LE credentials: daily or on revocation event; OOR/ECR: on event)

**Trust model**: The relay is semi-trusted — operated by Nethermind, governance-upgradeable, with the relayer key set itself anchored to a KERI AID. This is equivalent to the trust model used by Chainlink's DON for the ACE integration, but operated natively within Nethermind's infrastructure rather than requiring a separate oracle dependency.

**Phase 3 upgrade path**: The relay oracle is designed to be replaceable by a ZK-KERI prover (see Phase 4), which removes the trusted relayer assumption entirely.

#### 2c. Relayer Key Management

Relayer update rights are governed by a multi-sig KERI AID controlled by Nethermind. The `KERIVerifier` contract stores the relayer's current Ed25519 public key and validates update signatures against it. Key rotation follows the KERI pre-rotation model, submitted as a governance transaction.

**Phase 2 deliverables**:
- `KERIVerifier` contract (audited)
- KERI Witness Relay Service (Nethermind-operated)
- SDK for resolving `IVleiAugmented.isVleiValid()` queries
- Integration with GLEIF's vLEI ecosystem for witness access

---

### Phase 3 — Credential-Gated Descriptor Management

**Goal**: Ensure that only addresses holding a valid OOR/ECR credential from the token's issuing entity can deploy or update FIX descriptors.

This closes the authorization gap: today, any address that controls a token contract's admin key can update the FIX descriptor. With Phase 3, the descriptor can only be updated by someone who cryptographically proves they are an authorized officer of the issuing legal entity.

#### 3a. DescriptorManager Contract

```solidity
/// @notice Wraps IFixDescriptor with vLEI-gated update authorization.
contract DescriptorManager {

    IFixDescriptor  public descriptor;
    KERIVerifier    public verifier;
    bytes32         public issuingEntityLeSaid;  // The entity's LE credential SAID

    error CallerNotAuthorized(address caller, bytes32 credentialSaid);
    error CredentialInvalid(bytes32 credentialSaid);
    error CredentialEntityMismatch(bytes32 credentialSaid, bytes32 expectedLeSaid);

    event DescriptorUpdatedByAuthorized(
        address indexed updater,
        bytes32 indexed oorCredentialSaid,
        bytes32 newFixRoot
    );

    /// @notice Update the FIX descriptor.
    /// @param  oorOrEcrSaid  SAID of the caller's OOR or ECR credential from the issuing entity.
    ///                       Must chain to this contract's issuingEntityLeSaid.
    function updateDescriptor(
        FixDescriptor calldata newDescriptor,
        bytes32               oorOrEcrSaid
    ) external {
        // 1. Verify credential is valid and active
        if (!verifier.isValid(oorOrEcrSaid))
            revert CredentialInvalid(oorOrEcrSaid);

        // 2. Verify credential chains to this entity's LE credential
        CredentialStatus memory status = verifier.getStatus(oorOrEcrSaid);
        if (status.issuingEntitySaid != issuingEntityLeSaid)
            revert CredentialEntityMismatch(oorOrEcrSaid, issuingEntityLeSaid);

        // 3. Verify caller controls the AID bound to this credential
        _verifyCallerAidBinding(msg.sender, oorOrEcrSaid);

        // Update
        descriptor.updateFixDescriptor(newDescriptor);
        emit DescriptorUpdatedByAuthorized(msg.sender, oorOrEcrSaid, newDescriptor.fixRoot);
    }
}
```

#### 3b. AID-to-Address Binding

KERI AIDs are based on Ed25519 keys. Ethereum addresses are derived from secp256k1 keys. Bridging them requires a binding mechanism. Options, in order of complexity:

1. **Signed binding message** (Phase 3): The KERI AID holder signs a binding message `"bind:0x<ethAddress>:<chainId>:<nonce>"` with their Ed25519 key. This is submitted to `KERIVerifier` as part of credential registration, stored as `aidToAddress[aid] = ethAddress`. The caller's `msg.sender` is then checked against this mapping.

2. **Dual-key wallet** (Phase 3+): The credential holder uses a wallet that holds both Ed25519 and secp256k1 keys, signing descriptor update transactions with both. Nethermind's agent infrastructure is well-positioned to build this.

3. **ZK key equivalence proof** (Phase 4): A ZK proof that the secp256k1 key controlling `msg.sender` and the Ed25519 key in the KERI AID share a common seed or are otherwise linked — without revealing either private key.

**Phase 3 deliverables**:
- `DescriptorManager` contract (audited)
- AID-to-address binding registry
- CLI tooling for authorized signatories to perform credential-gated descriptor updates
- Integration guide for token issuers

---

### Phase 4 — ERC-3643 Compliance Module

**Goal**: Enforce vLEI-based counterparty identity as a transfer condition in permissioned token contracts.

ERC-3643 (T-REX) is the dominant standard for permissioned tokenized securities on Ethereum. Its `ICompliance` interface allows pluggable compliance rules that are checked on every transfer. Chainlink ACE has built one such module using Chainlink's oracle network. Nethermind's module would use the `KERIVerifier` directly, without a Chainlink dependency.

#### 4a. VleiComplianceModule

```solidity
/// @notice ERC-3643 ICompliance module enforcing vLEI LE credential validity
///         for both sender and receiver of permissioned token transfers.
contract VleiComplianceModule is ICompliance {

    KERIVerifier public verifier;

    /// @notice Maps token holder address → their entity's LE credential SAID.
    ///         Set at onboarding time; must be kept current.
    mapping(address holder => bytes32 leSaid) public holderCredential;

    /// @notice Optional: jurisdiction allowlist. If set, only LE credentials
    ///         from approved LEI jurisdictions may hold this token.
    mapping(bytes2 isoCountry => bool allowed) public allowedJurisdictions;

    function canTransfer(
        address from,
        address to,
        uint256 /*amount*/
    ) external view override returns (bool) {
        bytes32 fromSaid = holderCredential[from];
        bytes32 toSaid   = holderCredential[to];

        // Both parties must have registered LE credentials
        if (fromSaid == bytes32(0) || toSaid == bytes32(0)) return false;

        // Both credentials must be currently valid
        if (!verifier.isValid(fromSaid)) return false;
        if (!verifier.isValid(toSaid))   return false;

        // Optional: jurisdiction check
        if (_jurisdictionCheckEnabled()) {
            if (!allowedJurisdictions[_getJurisdiction(fromSaid)]) return false;
            if (!allowedJurisdictions[_getJurisdiction(toSaid)])   return false;
        }

        return true;
    }

    /// @notice Register a holder's LE credential at onboarding time.
    /// @dev    Caller must prove control of the AID bound to the credential.
    function registerHolderCredential(
        address holder,
        bytes32 leSaid,
        bytes   calldata aidBindingProof
    ) external onlyIssuerOrCompliance {
        require(verifier.isValid(leSaid), "Credential not valid");
        _verifyAidBinding(holder, leSaid, aidBindingProof);
        holderCredential[holder] = leSaid;
    }
}
```

#### 4b. Relationship to Chainlink ACE

Chainlink's ACE integration (announced with GLEIF and ERC-3643 Association) achieves similar goals via Chainlink's DON oracle network. The key differences:

| | **Chainlink ACE** | **Nethermind VleiComplianceModule** |
|---|---|---|
| Oracle trust model | Chainlink DON (decentralized) | Nethermind relay (operator-controlled → ZK in Phase 4) |
| Infrastructure dependency | Requires Chainlink integration | Native to ERC-FIX + Nethermind BaaS stack |
| FIX protocol binding | Not native | Native (FIX Parties group ↔ vLEI) |
| Institutional client access | General market | Nethermind's existing institutional clients |
| Upgrade path | Chainlink-governed | ZK-KERI (Nethermind-governed) |

These are **complementary, not competing**. Issuers building on Nethermind's BaaS who want a single integrated stack would use the Nethermind module. Issuers already using Chainlink infrastructure could use ACE. Both read from the same underlying vLEI ecosystem.

**Phase 4 deliverables**:
- `VleiComplianceModule` (audited)
- Holder onboarding tooling (credential registration + AID binding)
- Integration with Nethermind's existing ERC-3643 tokenization work
- Joint reference deployment with a QVI partner

---

### Phase 5 (Future) — ZK-KERI: Trustless On-Chain Verification

The long-term direction removes the trusted relay assumption by generating **ZK proofs of KERI key events**.

A ZK circuit would prove:
1. The KEL from inception to current state is cryptographically valid (all events correctly chained, signatures valid)
2. A credential was issued with a valid signature from the current key state
3. No revocation event exists in the PTEL as of a given block height

The proof is verified on-chain in the `KERIVerifier` contract, replacing the relayer entirely. Ed25519 signature verification in circuits is well-studied; BLAKE3 preimage circuits are feasible. This would make the Nethermind vLEI integration fully trustless and would be a significant contribution to both the vLEI and ZK ecosystems.

---

## 3. Why Nethermind Is the Right Team

| Capability | Relevance |
|---|---|
| Ethereum client (~30% of network) | Core protocol expertise required to propose and drive adoption of a new ERC standard |
| 20,000+ node operations | Ready-made infrastructure for KERI witness relay network |
| World ID operator (7M+ verifications) | Proven operational experience running cryptographic identity infrastructure at scale |
| Institutional BaaS clients (Nomura, Brevan Howard) | Direct distribution channel for the first production deployments |
| Tokenization standards research (with PwC, GFTN) | Identified "legal entity identity" as the missing link — this is the answer |
| Smart contract security (audits, formal verification) | Required for auditing the `KERIVerifier` and compliance module contracts |
| AI agent identity work | Long-term: vLEI OOR/ECR credentials for AI agents executing on-chain transactions |
| ERC-3643 expertise | Integration with the dominant permissioned token standard already in scope |

No other organization currently combining deep Ethereum protocol expertise, institutional client relationships, node operations at scale, and active tokenization standards work. The intersection is uniquely Nethermind's.

---

## 4. Implementation Roadmap

| Phase | Deliverable | Dependency | Estimated Effort |
|---|---|---|---|
| **1** | FIX `"V"` PartyIDSource convention, `IVleiAugmented`, off-chain verifier script | None | 4–6 weeks |
| **2** | `KERIVerifier`, KERI Witness Relay Service | Phase 1, QVI partner access | 8–12 weeks |
| **3** | `DescriptorManager`, AID-to-address binding, CLI tooling | Phase 2 | 6–8 weeks |
| **4** | `VleiComplianceModule`, holder onboarding tooling, reference deployment | Phase 2–3 | 6–8 weeks |
| **5** | ZK-KERI prover + on-chain verifier | Phase 2, ZK team | Research + 6–12 months |

Phase 1 can be shipped as a standalone ERC-FIX extension with no external dependencies and begins building the ecosystem immediately. Phases 2–4 are sequentially dependent but independently useful at each step.

---

## 5. Ecosystem and Partnerships

### QVI Partners

Phase 2 requires access to at least one QVI's KERI witness infrastructure to bootstrap the relay. **Provenant** (first-ever QVI, US-based) and **Global vLEI** (European, spun off from NordLEI with 176,000+ legacy LEI customers) are the most natural first partners. A joint reference deployment with a QVI would validate the integration and provide shared marketing material.

### GLEIF

GLEIF maintains a Technical Advisory Board for the vLEI ecosystem and has actively sought on-chain integrations (as evidenced by the ACE collaboration and the 2025 Hackathon's on-chain finance track). Nethermind contributing the ERC-FIX vLEI integration to the vLEI open-source ecosystem (`WebOfTrust/vLEI` GitHub) would be a meaningful contribution that builds the relationship.

### ERC-3643 Association

The Association has already engaged with Chainlink for ACE. A Nethermind-led integration would give institutional clients a second, natively ERC-FIX-integrated compliance option. Co-presenting at ERC-3643 governance forums would accelerate adoption.

### Institutional Clients

Existing Nethermind BaaS clients with tokenization programs are the natural first users. A tokenized bond or money market fund with ERC-FIX + vLEI would be the flagship reference deployment. The regulatory reporting benefit (LEI fields automatically satisfied in EMIR/MiFID II reports) is a concrete, quantifiable value proposition for compliance teams.

---

## 6. Open Questions

1. **QVI access for Phase 2**: Which QVI partner will grant Nethermind watcher-level access to their witness network for the relay? What are the contractual terms?

2. **FIX standards body**: Should the `"V"` PartyIDSource value be proposed to the FIX Trading Community for formal standardization, or maintained as an ERC-FIX-specific extension?

3. **GLEIF alignment**: Does GLEIF have a preference for how on-chain credential status is relayed (oracle vs. ZK)? Getting GLEIF's endorsement of the architecture would accelerate QVI adoption.

4. **AID-to-address binding UX**: What wallet tooling exists today for institutional signatories to manage both a KERI AID and an Ethereum signing key? Is this a gap Nethermind should fill as part of Phase 3?

5. **Revocation latency**: For high-frequency trading scenarios, what is the acceptable lag between a QVI revoking a credential and the `KERIVerifier` reflecting that revocation? This drives relay frequency requirements and has direct gas cost implications.

6. **ZK-KERI feasibility timeline**: Is there existing circuit work for Ed25519 + BLAKE3 verification that Nethermind's ZK team can build on, or does Phase 5 require original circuit development?

---

## Appendix: FIX Tags Referenced

| Tag | Field Name | Relevance |
|---|---|---|
| 48 | SecurityID | Primary security identifier (ISIN, etc.) |
| 22 | SecurityIDSource | Source for tag 48 |
| 453 | NoPartyIDs | Count of Parties group entries |
| 448 | PartyID | Party identifier (LEI, vLEI SAID) |
| 447 | PartyIDSource | `"N"` = LEI; proposed `"V"` = vLEI SAID |
| 452 | PartyRole | `13` = Issuer; `17` = Guarantor; etc. |
| 454 | NoSecurityAltID | Count of SecurityAltID entries |
| 455 | SecurityAltID | Alternative identifier |
| 456 | SecurityAltIDSource | Source for tag 455 |
| 167 | SecurityType | Instrument type (BOND, CS, etc.) |
| 541 | MaturityDate | For fixed-income instruments |
| 223 | CouponRate | For fixed-income instruments |
| 461 | CFICode | ISO 10962 classification |
