# GLEIF and the Legal Entity Identifier (LEI)

## GLEIF — Global Legal Entity Identifier Foundation

### Origins

GLEIF was established on **June 26, 2014** in Basel, Switzerland, as a direct response to the 2008 financial crisis. During that crisis, regulators could not reliably identify the parties to financial transactions across markets and borders — a systemic blind spot that worsened the collapse.

Timeline:
- **2008**: Crisis exposes absence of any universal entity identifier
- **2011**: G20 Cannes Summit calls on the FSB to develop a global LEI system
- **2012**: FSB's 15 High-Level Principles endorsed by G20 at Los Cabos
- **2013**: LEI Regulatory Oversight Committee (LEI ROC) takes over
- **2014**: GLEIF Board inaugural meeting; Stephan Wolf appointed CEO
- **2024**: Alexandre Kech succeeds Wolf as CEO (June 26)

### Mission

GLEIF is a **supra-national, not-for-profit organisation** that:
- Manages the only open, non-proprietary legal entity identification system designed as a public good
- Ensures operational integrity of the Global LEI System
- Develops and maintains LEI standards and data quality
- Promotes LEI use beyond financial regulation into cross-border payments, supply chain, digital identity, and ESG

GLEIF itself **does not issue LEIs**. It oversees a network of accredited LEI-issuing organisations (Local Operating Units / LOUs).

### Governance — Three-Tier Model

```
Tier 1: LEI Regulatory Oversight Committee (LEI ROC)
        ├── Representatives of public authorities (regulators, central banks)
        └── Establishes global policies; ensures LEI operates as a public good

Tier 2: GLEIF
        ├── Manages global LEI infrastructure
        ├── Accredits LOUs
        ├── Maintains the Global LEI Index (free, public database)
        └── Runs the vLEI qualification program

Tier 3: Local Operating Units (LOUs)
        ├── Accredited organisations that issue and maintain LEIs
        ├── Verify reference data with local Registration Authorities
        └── Share portion of fees with GLEIF
```

---

## LEI — Legal Entity Identifier

### What It Is

A **20-character alphanumeric code** standardised under **ISO 17442-1**. Like a global barcode for legal entities — it uniquely and unambiguously identifies any organisation participating in financial transactions.

The LEI answers two questions:
- **"Who is who?"** (Level 1 data — identity)
- **"Who owns whom?"** (Level 2 data — ownership)

### Code Structure

```
[Characters 1–4]  [Characters 5–18]  [Characters 19–20]
  LOU Prefix        Entity Block         Check Digits
  (4 chars)         (14 chars)           (2 chars)
```

- **Characters 1–4**: Identifies the issuing LOU. Does not encode geography.
- **Characters 5–18**: Unique alphanumeric string, no embedded intelligence.
- **Characters 19–20**: Check digits via **ISO/IEC 7064 MOD 97-10**.
- Allowed characters: A–Z and 0–9 only. No spaces or special symbols.

Example: `549300MLUDYVRQOOXS22`

### Two Levels of Data

**Level 1 — "Who is who?"**
- Official legal name
- Registered address (country, region, city, postal code)
- Legal form
- Registration authority and number
- Date of formation
- Entity status (active, inactive)
- LEI issuer (LOU)
- Issuance and renewal dates

**Level 2 — "Who owns whom?"**
- Direct parent entity (direct accounting consolidating parent)
- Ultimate parent entity
- Fund relationship data

### Who Needs an LEI

Required for legal entities:
- Participating in financial transactions subject to regulation (OTC derivatives, securities, funds)
- Counterparties in cross-border deals, syndicated loans
- Reporting under MiFID II, EMIR, Dodd-Frank, ASIC, and 300+ other regulations

Individuals **cannot** obtain an LEI — it is exclusively for legal entities.

### Issuance Process

1. Entity contacts a preferred LOU (GLEIF maintains the list)
2. Submits registration data (legal name, address, registration number)
3. LOU verifies against local Registration Authorities (national company registries)
4. LOU issues the LEI
5. Entity pays initial registration fee + annual maintenance/renewal fee
6. LEI valid for **one year**, renewed annually
7. All LEI data made publicly available for free via GLEIF Global LEI Index

### Scale (2024)

- **2.63 million** active LEIs globally
- **278,000** new LEIs issued in 2024
- Annual growth rate: **11.5%**
- India: second-largest jurisdiction, 35.9% annual growth
- Overall renewal rate: 56.1% (Japan leads at 91.7%)

---

## ISO Standards for LEI

| Standard | Description |
|---|---|
| ISO 17442-1 | LEI code structure (the 20-character code) |
| ISO 17442-2:2020 | LEI in X.509 digital certificates |
| **ISO 17442-3:2024** | Verifiable LEIs (vLEIs) — ACDC/KERI based |
| ISO 5009:2022 | Official Organisational Roles (used in OOR credentials) |
| ISO/IEC 7064 | MOD 97-10 check digit calculation |

---

## References

- [GLEIF — This is GLEIF](https://www.gleif.org/en/about/this-is-gleif)
- [GLEIF — History of the Global LEI System](https://www.gleif.org/en/about/history)
- [FSB — Legal Entity Identifier](https://www.fsb.org/work-of-the-fsb/market-and-institutional-resilience/post-2008-financial-crisis-reforms/legalentityidentifier/)
- [ISO 17442-1 — LEI Code Structure](https://www.iso.org/standard/78829.html)
