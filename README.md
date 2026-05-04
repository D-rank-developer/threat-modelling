# 🛡️ Cyber Risk Assessment — MSc Cyber Security (CMP-LO19-0)

> **University of Roehampton London** | MSc Cyber Security 2025/26  
> Module: CMP-LO19-0 | Full report: [`CRM-A1-ASSESSMENT.pdf`](./CRM-A1-ASSESSMENT__4_.pdf)

---

## Overview

This assessment covers three interconnected areas of cyber risk practice: security risk review, threat modelling, and vulnerability rating. All three parts draw on real tools and industry-standard frameworks applied to realistic systems — DVWA for the risk review, and a UK Online Safety Act (OSA) age verification platform for the threat modelling.

---

## Part 1 — Security Risk Review of DVWA

**Objective:** Identify and quantify risks across key assets in the Damn Vulnerable Web Application.

### Assets Identified

| Asset | Type | Key Risk |
|---|---|---|
| User Login & Authentication | Service | Brute force, credential theft |
| User Data Records | Database | SQL injection, data exfiltration |
| File Upload Storage | Service / Infrastructure | Remote code execution, web shell upload |
| User Session Management | Service | Session hijacking via weak session IDs |

### Qualitative Risk Analysis (`RQual = IQual + PQual`)

| Risk | PQual | IQual | RQual | Level |
|---|---|---|---|---|
| SQL Injection / DB Compromise | 4 | 4 | 8 | High |
| RCE via File Upload / Web Shell | 4 | 5 | 9 | **Extreme** |
| Session Hijacking (Weak IDs) | 3 | 4 | 7 | High |

### Quantitative Risk Analysis

Using:
- `PQuant = N · 10^(PQual − 5)` where N = 100 (baseline frequency)
- `VQuant = M · 10^(IQual − 5)` where M = £30,000,000 (maximum impact)
- `RQuant = PQuant · VQuant`

| Risk | PQuant (events/yr) | VQuant | RQuant |
|---|---|---|---|
| SQL Injection | 10 | £3,000,000 | £30,000,000 |
| File Upload / RCE | 10 | £30,000,000 | £300,000,000 |
| Session Hijacking | 1 | £3,000,000 | £3,000,000 |

### Key Finding
Quantitative analysis reveals a **100× gap** between the highest and lowest risk — something qualitative scoring alone (scores of 9, 8, 7) fails to communicate. File Upload / RCE is prioritised first, followed by SQL Injection, then Session Hijacking.

**ISO 27002:2022 controls mapped:** 8.12 (Data Leakage Prevention), 8.28 (Secure Coding), 5.15 (Access Control)

---

## Part 2 — Threat Analysis: OSA Age Verification Process

**Objective:** Model threats across the UK Online Safety Act age verification pipeline using STRIDE and DFD trust boundaries.

### System Components

| Component | Role |
|---|---|
| Website Platform | User-facing UI; entry point for ID/selfie submission |
| Platform Backend Server | Access control logic, selfie storage, AVP communication |
| AVP API (Age Verification Provider) | Third-party age check; returns verified/denied result |
| Compliance Logs Database | Stores audit evidence for Ofcom regulatory requests |

### Actors
- **Users** — adults or minors attempting access to restricted content
- **Age Verification Provider** — external third-party identity checker
- **Internal Admins / SIEM** — monitoring and log review
- **Ofcom** — regulatory auditor

### Trust Boundaries (DFD)

```
[User] ──TB1──> [Website Platform] ──TB2──> [Platform Backend]
                                                    │
                                              TB3──> [AVP API]
                                              TB4──> [Compliance Logs DB]
```

### STRIDE Analysis — Key Vulnerabilities

| ID | Boundary | STRIDE Category | Vulnerability |
|---|---|---|---|
| V1 | TB1 | Spoofing | Fake / deepfake ID submission bypassing liveness checks |
| V2 | TB1 | Info Disclosure | Sensitive data exposed in selfie background |
| V3 | TB1 | Spoofing | Phishing site spoofing the legitimate platform |
| V4 | TB2 | Denial of Service | Backend connection exhaustion via HTTP flood |
| V5 | TB2 | Elevation of Privilege | Backend bugs enabling unauthorised AVP access |
| V6 | TB3 | Tampering | Manipulated AVP response (e.g. always returning `over18=true`) |
| V7 | TB3/TB4 | Denial of Service | Single point of failure — AVP outage halts all verification |
| V8 | TB4 | Tampering | SQL injection into compliance database |
| V9 | TB4 | Repudiation | Log deletion destroying verification evidence |

### Mitigations

| REC | Control |
|---|---|
| REC1 | Liveness detection with challenge-response (blink / head movement) |
| REC2 | User guidance + automatic blurring of sensitive selfie backgrounds |
| REC3 | HSTS enforcement + visual trust indicators |
| REC4 | Rate limiting + connection timeout controls |
| REC5 | Least-privilege role-based access for backend services |
| REC6 | HMAC-SHA256 signing of all AVP API responses |
| REC7 | Redundant AVP providers with automatic failover |
| REC8 | Parameterised queries + database firewall + regular SQLi testing |
| REC9 | Cryptographic audit trail proofs for compliance logs |

### Key Finding
The highest-priority threats are **Spoofing at TB1** (deepfakes undermine the entire OSA compliance purpose) and **Repudiation at TB4** (missing logs expose the platform to Ofcom fines of up to 10% of global revenue), independent of CVSS score.

---

## Part 3 — Vulnerability Rating and System Resilience

**Objective:** Discover, score, and prioritise real vulnerabilities using Nessus, CVSSv4, CWE mapping, and CISA KEV — then define redundancy and resilience measures.

### Nessus Scan Target
Host: `10.0.2.15` | Scanner: Tenable Nessus Essentials | Policy: Basic Network Scan  
Results: 0 Critical · 4 High · 2 Medium · 1 Low · 84 Info

### CVEs Selected for Analysis

| CVE | Description | Severity | CWE Root Cause |
|---|---|---|---|
| CVE-2025-62171 | ImageMagick BMP integer overflow on 32-bit systems | High (7.5) | CWE-190 |
| CVE-2025-58767 | Ruby REXML XML parsing denial-of-service loop | Medium (5.3) | CWE-400 |
| CVE-2025-61984 | OpenSSH control character injection via untrusted usernames | Low (3.6) | CWE-159 |

### CVSSv4 Scoring

| CVE | CVSSv4 Vector | CVSSv4 Score | Nessus v3 Score |
|---|---|---|---|
| CVE-2025-62171 | `AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` | **8.2 (High)** | 7.5 |
| CVE-2025-58767 | `AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` | **5.1 (Medium)** | 5.3 |
| CVE-2025-61984 | `AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` | **2.0 (Low)** | 3.6 |

> CVSSv4 differences from v3 are driven by the removal of the Scope metric and the addition of Attack Requirements (AT), which recalibrates weights across all vectors.

### KEV Status

All three CVEs returned **No Results** in the CISA Known Exploited Vulnerabilities catalogue at time of assessment, indicating no confirmed active exploitation at that date.

### Patching Priority (Context-Driven — overrides raw CVSS)

| Priority | CVE | Reason |
|---|---|---|
| 🔴 Extreme | CVE-2025-61984 | OpenSSH is internet-facing; control character injection via ProxyCommand can enable unintended command execution under specific configurations. Low CVSS score is misleading given deployment surface. |
| 🟠 High | CVE-2025-58767 | Trivially exploitable — attacker submits one malformed XML file. Any Ruby service parsing untrusted XML is at risk of full outage. |
| 🟡 Low | CVE-2025-62171 | Affects 32-bit systems only. Narrow attack surface; safe to defer to scheduled maintenance. |

### Resilience and Redundancy Measures

| CVE | Redundancy | Resilience |
|---|---|---|
| CVE-2025-61984 | Out-of-band access (IPMI / AWS Session Manager) as SSH fallback | Sanitise usernames; restrict ProxyCommand in SSH config |
| CVE-2025-58767 | Load balancer across multiple app instances; failover on crash | WAF / proxy-layer XML validation before reaching parser |
| CVE-2025-62171 | Fallback to GraphicsMagick or libvips if ImageMagick crashes | Disable BMP processing in `policy.xml`; enforce resource limits |

> Resilience framework: NIST SP 800-160 Vol. 2 Rev. 1 (Ross et al., 2021)

---

## Tools & Frameworks Used

| Tool / Framework | Purpose |
|---|---|
| DVWA | Target application for Part 1 risk review |
| Tenable Nessus Essentials | Vulnerability scanning (Part 3) |
| CVSS v4.0 Calculator (FIRST) | Vulnerability scoring |
| MITRE CWE | Root cause classification |
| CISA KEV Catalogue | Exploitation status check |
| STRIDE | Threat categorisation (Part 2) |
| DFD / Trust Boundaries | Threat modelling diagram (Part 2) |
| ISO 27001/27002:2022 | Control framework references (Part 1) |
| NIST SP 800-160 v2r1 | Resilience and redundancy framework (Part 3) |

---

## References

- Tenable. *Common Vulnerabilities and Exposures (CVEs)*. https://www.tenable.com/cve
- FIRST. *Common Vulnerability Scoring System Version 4.0 Calculator*. https://www.first.org/cvss/calculator/4-0
- MITRE. *CWE — Common Weakness Enumeration*. https://cwe.mitre.org/
- Kali Linux Tools. *DVWA*. https://www.kali.org/tools/dvwa/
- CISA. *Known Exploited Vulnerabilities Catalog*. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Ross, R. et al. (2021). *Developing Cyber-Resilient Systems*. NIST SP 800-160 Vol. 2 Rev. 1. https://doi.org/10.6028/NIST.SP.800-160V2R1
- Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley.

---

> 📄 Full assessment with figures, STRIDE tables, CVSS calculator screenshots, and Nessus scan reports:  
> **[`CRM-A1-ASSESSMENT.pdf`](./CRM-A1-ASSESSMENT__4_.pdf)**
