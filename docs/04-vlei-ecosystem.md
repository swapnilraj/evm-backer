# vLEI Ecosystem: Credentials, Trust Chain, and Governance

## The Trust Chain

Every vLEI credential's provenance traces cryptographically back to GLEIF's Root AID. No manual steps required — the entire chain is machine-verifiable.

```
GLEIF Root AID  (cryptographic root of trust, multi-sig)
      │
      │  issues QVI Credential
      ▼
GLEIF External AID  (operational, also multi-sig)
      │
      │  issues QVI Credential to each QVI
      ▼
Qualified vLEI Issuer (QVI) AID
      │
      │  issues LE vLEI Credential
      ▼
Legal Entity AID
      │
      │  authorises (via OOR AUTH / ECR AUTH) → QVI issues
      ▼
Individual Person AID  (authorized representatives)
```

**GLEIF's Dual AID Structure:**
- **GLEIF Root AID**: Ultimate cryptographic root of trust. Controlled by GLEIF leadership with multi-signature requirements.
- **GLEIF External AID**: Operational identifier used to issue QVI credentials. Also multi-signature.

Both are **multi-sig AIDs** — multiple key holders must sign events, preventing any single point of compromise.

---

## The Six Credential Types

### 1. QVI Credential (Qualified vLEI Issuer vLEI Credential)

| Field | Value |
|---|---|
| **Issued by** | GLEIF External AID |
| **Issued to** | QVI organisation |
| **Purpose** | Authorises the QVI to issue Legal Entity vLEI Credentials |
| **Contains** | QVI's AID, LEI, legal name, qualification attestation |
| **Schema SAID** | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` |

### 2. LE Credential (Legal Entity vLEI Credential)

| Field | Value |
|---|---|
| **Issued by** | QVI (authorised by its QVI Credential) |
| **Issued to** | Legal Entity |
| **Purpose** | Establishes the organisation's verifiable digital identity tied to its LEI |
| **Contains** | Organisation's AID, LEI, legal name |
| **Requires** | Active, valid LEI in the Global LEI System |
| **Schema SAID** | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWQ` |

### 3. OOR AUTH Credential (QVI OOR Authorization vLEI Credential)

| Field | Value |
|---|---|
| **Issued by** | Legal Entity's Legal Authorised Representative (LAR) |
| **Issued to** | QVI |
| **Purpose** | Authorises the QVI to issue an OOR Credential to a specific named person |
| **Contains** | Person's AID, name, role designation, reference to LE Credential |

This authorisation step prevents the QVI from issuing role credentials without explicit entity approval.

### 4. OOR Credential (Legal Entity Official Organizational Role vLEI Credential)

| Field | Value |
|---|---|
| **Issued by** | QVI (after receiving OOR AUTH from the Legal Entity) |
| **Issued to** | Individual person |
| **Purpose** | Verifies that a person holds a specific official organisational role per ISO 5009 |
| **Contains** | Person's AID, name, legal name, role title (e.g., CEO, CFO, Board Member), organisation LEI |
| **Schema SAID** | `EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy` |

### 5. ECR AUTH Credential (QVI ECR Authorization vLEI Credential)

| Field | Value |
|---|---|
| **Issued by** | Legal Entity's LAR |
| **Issued to** | QVI |
| **Purpose** | Authorises QVI to issue an ECR Credential to a specific person |

### 6. ECR Credential (Legal Entity Engagement Context Role vLEI Credential)

| Field | Value |
|---|---|
| **Issued by** | QVI or directly by the Legal Entity |
| **Issued to** | Individual person |
| **Purpose** | Verifies functional, transactional, or engagement-specific roles beyond ISO 5009 official roles |
| **Contains** | Person's AID, name, role context (organisation-defined), engagement identifier |
| **Examples** | "Supplier to [Company]", "Authorised Vendor", "Project Lead" |
| **Schema SAID** | `EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw` |

---

## Legal Authorised Representatives (LARs)

LARs are individuals within a Legal Entity who have authority to:
- Instruct QVIs to issue, revoke, and manage vLEI credentials on behalf of their organisation
- Issue OOR AUTH and ECR AUTH credentials to QVIs
- Hold their own AIDs and ECR/OOR credentials attesting to their authorisation status

---

## Qualified vLEI Issuers (QVIs)

QVIs are organisations that have:
1. Completed the **GLEIF Qualification Programme** (assessment of technical, operational, legal, and security capabilities)
2. Signed the **vLEI Ecosystem Governance Framework** agreement with GLEIF
3. Received a **QVI Credential** from GLEIF's External AID
4. Established their own operational KERI infrastructure (witnesses, wallets, verifiers)

### Qualification Process

**Step 1 — Programme Initiation**: Review the vLEI Issuer Qualification Programme Manual and submit a signed NDA to `qualificationrequest@gleif.org`.

**Step 2 — Documentation**: 60-day window to submit complete qualification documentation. GLEIF has 60 days to assess the submission.

**Step 3 — Software Testing**: Install GLEIF-provided vLEI software and test credential issuance, verification, revocation, and key rotation.

**Step 4 — Agreement Signing**: Upon approval, sign the vLEI Issuer Qualification Agreement. The organisation receives its QVI Credential and TrustMark.

**Ongoing**: GLEIF reverifies QVI compliance annually.

---

## vLEI Ecosystem Governance Framework (EGF)

Published by GLEIF, currently at **version 3.0** (April 2025). Described as "the most comprehensive Governance Framework developed based on the ToIP Governance Framework Meta-model."

### Structure

**Primary Document**: Master framework overview

**Controlled Documents**:
- Business and Governance Requirements
- Information Security Policies
- Risk Assessment Framework
- Trust Assurance Framework (v1.5, April 2025)
- Information Trust Policies (v1.2, April 2025)

**Technical Requirements**:
- Part 1: KERI Infrastructure (v1.3, April 2025) — witness requirements, cryptographic algorithms, AID management
- Part 2: vLEI Credentials — credential structure specifications
- Part 3: vLEI Credential Schema Registry (v1.1, December 2023) — standardised JSON schema definitions

**Credential Frameworks**: One framework document per credential type

**Version compatibility**: Previous versions supported for 18 months; new versions must be implemented within 12 months of final approval.

### Technical Requirements Highlights (Part 1)

- Minimum pool of **5 witnesses** per AID
- Signing algorithm: **Ed25519**
- Hashing: **BLAKE3** and SHA-3 family
- Minimum **128 bits of cryptographic strength** for all key pairs
- KAWA (KERI Agreement Algorithm for Witness Agreement) consensus

---

## Open-Source Resources

| Resource | URL |
|---|---|
| vLEI schemas and sample credentials | [WebOfTrust/vLEI](https://github.com/WebOfTrust/vLEI) |
| KERI reference implementation (Python) | [WebOfTrust/keripy](https://github.com/WebOfTrust/keripy) |
| KERI community discussions | [WebOfTrust/keri](https://github.com/WebOfTrust/keri) |
| KERIA (agent infrastructure) | [WebOfTrust/keria](https://github.com/WebOfTrust/keria) |
| Signify client (TypeScript) | [WebOfTrust/signify-ts](https://github.com/WebOfTrust/signify-ts) |
| GLEIF IT repos | [GLEIF-IT GitHub](https://github.com/GLEIF-IT) |

---

## Community and Working Groups

### KERI Community Meetings
- **Discord**: [discord.gg/YEyTH5TfuB](https://discord.gg/YEyTH5TfuB)
- **Meetings**: Alternating Tuesdays, 10am EDT
- **Zoom**: Meeting ID `847 2107 1832`
- **Chair**: Samuel M. Smith | **Co-chair**: Philip Feairheller
- **Agenda**: [hackmd.io/-soUScAqQEaSw5MJ71899w](https://hackmd.io/-soUScAqQEaSw5MJ71899w)
- GLEIF representatives attend

### ToIP KERI Suite Working Group
- Formal spec governance body
- Meets under Trust over IP Foundation
- Requires ToIP membership for verbal contribution
- [KSWG Confluence](https://lf-toip.atlassian.net/wiki/spaces/HOME/pages/56819755/KERI+Suite+Working+Group)

### Key People
- **Samuel M. Smith** — KERI/ACDC/CESR creator. GitHub: [SmithSamuelM](https://github.com/SmithSamuelM). Email: `smith.samuel.m@gmail.com`
- **Philip Feairheller** — KERI community co-chair
- **Timothy Ruff** — vLEI co-inventor, Digital Trust Venture Partners. LinkedIn: [rufftim](https://www.linkedin.com/in/rufftim/)
- **Ivan Mortimer-Schutts** — GLEIF Global Head of vLEI

## References

- [GLEIF — vLEI EGF](https://www.gleif.org/en/vlei/introducing-the-vlei-ecosystem-governance-framework/)
- [GLEIF — Qualification Process](https://www.gleif.org/en/organizational-identity/the-lifecycle-of-a-vlei-issuer/gleif-qualification-of-vlei-issuers/qualification-process)
- [WebOfTrust/vLEI — credential schemas](https://github.com/WebOfTrust/vLEI)
