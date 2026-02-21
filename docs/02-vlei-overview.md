# vLEI — Verifiable Legal Entity Identifier

## What It Is

The verifiable Legal Entity Identifier (vLEI) is the cryptographic evolution of the LEI. Standardised as **ISO 17442-3:2024** (published October 2024), it is a **cryptographically verifiable digital credential** that:

1. Contains the organisation's 20-character LEI code
2. Is digitally signed and tamper-evident
3. Can be verified automatically by machine without human intervention
4. Can delegate identity authority to individuals acting on behalf of the organisation

The "v" stands for **verifiable** — any party can cryptographically confirm the credential's authenticity, integrity, and provenance without contacting the issuer.

## Why vLEI Was Created

The traditional LEI has fundamental limitations in the digital age:

| Limitation | Impact |
|---|---|
| Static database record — not "presentable" in a transaction | Cannot be embedded in a digital signature or automated workflow |
| Verification requires manual database lookup | Slow, human-dependent, not machine-readable |
| Identifies organisations but not the people acting for them | No way to prove who is authorised to sign |
| No cryptographic proof of authorisation | Anyone with admin access can claim to act for the entity |
| No revocation mechanism | Once issued, no way to invalidate compromised credentials |

## LEI vs. vLEI

| Aspect | LEI | vLEI |
|---|---|---|
| Nature | Static database record / alphanumeric code | Cryptographically signed digital credential |
| Format | 20-character alphanumeric | ACDC credential (CESR/JSON encoded) |
| Standard | ISO 17442-1 | ISO 17442-3 (ACDC/KERI) |
| Verification | Manual database lookup at GLEIF | Automated cryptographic validation |
| Tamper Evidence | None | Cryptographically sealed (SAID) |
| Speed | Hours to days (manual) | Instant (automated) |
| Person Binding | Not possible | Yes — OOR and ECR credentials |
| Delegation | Not possible | Yes — credential chaining |
| Revocation | N/A | Cryptographic revocation via KERI PTEL |
| Technology | ISO 17442-1 code | KERI + ACDC + CESR |

## Use Cases

### Digital Document Signing
Organisations sign documents (contracts, financial reports, regulatory filings, invoices) using their vLEI credentials. The signature proves:
- The signing organisation's identity (LE Credential)
- The signing individual's authority (OOR or ECR Credential)
- Document integrity (cryptographic hash)
- Non-repudiation (audit trail in KEL)

**Live deployment**: Provenant built GLEIF's own XBRL signing system; GLEIF signs its financial reports with vLEI credentials.

### Corporate Caller ID Authentication
First commercial vLEI service (Provenant). Enterprises making outbound calls/texts digitally sign communications with vLEI credentials. Recipients receive cryptographic proof the communication originates from the claimed organisation. Addresses robocalls, spoofed corporate numbers, and fraudulent business communications.

### Cross-Border Trade / Electronic Bills of Lading
**GLEIF + WaveBL Partnership (July 2024)**: WaveBL integrates LEI/vLEI into electronic Bills of Lading (eBLs) and Bills of Exchange. All parties identified via LEI and verified via vLEI. Only 1–2% of trade documents currently processed digitally — vLEI enables rapid digitisation.

### ESG / Sustainability Reporting
CSRD (Corporate Sustainability Reporting Directive) applies from January 2025. vLEI enables cryptographically signed, tamper-proof ESG reports tied to verified legal entity identity.

### On-Chain Finance / DeFi
vLEI credentials bind wallets to verified organisational identities. Smart contracts can enforce eligibility rules based on organisational identity, jurisdiction, and role. **Chainlink ACE** integration: codifies KYC/AML and jurisdictional rules into smart contracts, with vLEI as the identity layer.

### KYB (Know Your Business)
Eliminates time-consuming manual identity verification in financial services onboarding. vLEI enables instant, automated, cryptographically verified entity onboarding. Works globally without re-verification per jurisdiction.

### AI Agent Identity
GLEIF's 2025 Hackathon explicitly targets "identifying AI agents" as a vLEI use case. As AI systems increasingly act on behalf of organisations, vLEI credentials could establish which organisation an AI agent represents, the scope of authorised actions, and a verifiable audit trail.

### ISO 20022 Cross-Border Payments
CPMI endorsed LEI within ISO 20022 data requirements for cross-border payments. LEI/vLEI in payment messages enables automated counterparty identification and more effective AML/CFT measures.

## Current Adoption Status (Early 2026)

### Standards
- **ISO 17442-3:2024**: Published October 2024 — major milestone
- **vLEI EGF v3.0**: Active, documents dated April 2025
- **IETF Drafts**: KERI, ACDC, CESR undergoing review through ToIP Foundation

### QVI Network
8 Qualified vLEI Issuers globally:

| Organisation | LEI | Qualification Date | Region |
|---|---|---|---|
| Provenant | 984500983AD71E4FBC41 | 2022-12-08 | Americas (first ever) |
| CFCA | 300300CQ1FG1K4KM7075 | 2025-02-14 | China |
| FINEMA | 894500D5AV38KEBZAS18 | 2025-02-21 | Thailand |
| Certizen | 836800VC81GMPMG59W77 | 2025-03-20 | Europe |
| Global vLEI | 636700LQ8SMYXSBX5D74 | 2025-05-26 | Europe |
| TradeGo | 984500C2EED6A7382A87 | 2025-06-25 | Asia-Pacific |
| TOPPAN Edge | 353800460NTF5K7NU940 | 2025-09-05 | Japan (first) |
| SHECA | 83680008RNIDW9LD8Z21 | 2025-10-15 | China |

12+ additional organisations reportedly in the qualification pipeline.

### Regulatory Tailwinds
- eIDAS 2.0 (EU digital identity wallet)
- CSRD sustainability reporting mandates
- ISO 20022 cross-border payment requirements
- Growing enterprise fraud pressure

## References

- [GLEIF — Introducing the vLEI](https://www.gleif.org/en/organizational-identity/introducing-the-verifiable-lei-vlei)
- [ISO 17442-3:2024](https://www.iso.org/standard/85628.html)
- [GLEIF — List of Qualified vLEI Issuers](https://www.gleif.org/en/vlei/get-a-vlei-list-of-qualified-vlei-issuing-organizations)
- [GLEIF — WaveBL Partnership](https://www.gleif.org/en/newsroom/press-releases/gleif-and-wavebl-take-trust-and-transparency-in-trade-shipping-to-the-next-level-with-the-implementation-of-the-lei-and-vlei-on-)
