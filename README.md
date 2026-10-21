# ◈ VALORYNN

### **Defend what you make.**

<p align="center">
  <img src="https://img.shields.io/badge/AI%2FML-Assisted-000000?style=for-the-badge&logoColor=white" alt="AI/ML Assisted"/>
  <img src="https://img.shields.io/badge/Application-Security-000000?style=for-the-badge" alt="Application Security"/>
  <img src="https://img.shields.io/badge/Python-3.11%2B-000000?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Docker-Ready-000000?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/License-TBD-000000?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=18&duration=2800&pause=900&color=FFFFFF&background=00000000&center=true&vCenter=true&width=700&lines=SCAN+%E2%86%92+UNDERSTAND+%E2%86%92+FIX+%E2%86%92+VERIFY;Application+Security%2C+made+understandable.;Find+what%27s+insecure.;Know+why+it+matters.;Fix+what+matters+first.;Measure+the+improvement." alt="Valorynn animated tagline"/>
</p>

<p align="center">
  <b>Valorynn</b> is a GUI-based, AI/ML-assisted application-security platform for authorized web application assessment.
</p>

<p align="center">
  <a href="https://github.com/ashfaqhyder/Valorynn">Repository</a>
  ·
  <a href="https://github.com/ashfaqhyder/Valorynn/issues">Issues</a>
  ·
  <a href="https://github.com/ashfaqhyder/Valorynn/pulls">Pull Requests</a>
</p>

---

## ◇ The Problem

Security scanners can produce a long list of technical findings.

But a useful security assessment should answer four simple questions:

```text
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   WHAT IS INSECURE?                                     │
│                                                         │
│   WHY DOES IT MATTER?                                   │
│                                                         │
│   WHAT SHOULD I FIX FIRST?                              │
│                                                         │
│   DID THE FIX ACTUALLY IMPROVE SECURITY?                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Valorynn is designed around those four questions.**

It transforms security signals into findings, evidence, risk scores, remediation guidance, projected improvements, and verified re-scan results.

---

# ◉ What is Valorynn?

Valorynn is an application-security assessment platform designed for **students, developers, and organizations** working with authorized web applications.

It combines:

* Automated security checks
* Explainable risk scoring
* Evidence-based findings
* Remediation guidance
* Source-archive analysis
* ML-assisted severity classification
* FixSignal score simulation
* Re-scan comparison
* HTML/PDF reporting

> **Important:** Valorynn's score is an evidence-based risk indicator. It is not proof that an application is completely secure.

---

# ◎ How It Works

```text
                    ┌─────────────┐
                    │ APPLICATION │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │    SCAN     │
                    └──────┬──────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │ ANALYZE + CLASSIFY │
                 └─────────┬─────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  FINDINGS   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ RISK SCORE  │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │    FIX      │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   RESCAN    │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  VERIFY     │
                    └─────────────┘
```

**Scan → Understand → Prioritize → Fix → Verify**

---

# ✦ Core Capabilities

<table>
<tr>
<td width="50%">

### ◈ Authorized Scanning

Valorynn requires ownership/authorization confirmation before scanning a target.

</td>
<td width="50%">

### ◈ Security Findings

Organizes detected issues into meaningful severity groups with supporting evidence.

</td>
</tr>

<tr>
<td>

### ◇ Explainable Scoring

Every scan produces a transparent **0–100 security score** based on detected findings.

</td>
<td>

### ◇ Remediation Guidance

Each finding provides an explanation of its impact and suggested remediation direction.

</td>
</tr>

<tr>
<td>

### ◉ FixSignal

Simulate how selected remediation actions could affect the projected security score.

</td>
<td>

### ◎ Re-scan Verification

Run another assessment and compare the actual result against the previous scan.

</td>
</tr>

<tr>
<td>

### ⬡ Source Review

Analyze uploaded ZIP source archives in memory for security-relevant signals.

</td>
<td>

### △ ML Severity Model

TF-IDF + Logistic Regression workflow for ML-assisted vulnerability severity classification.

</td>
</tr>
</table>

---

# ▣ Security Checks

Valorynn's current low-impact URL assessment includes checks related to:

```text
HTTPS / TLS
│
├── HTTP Security Headers
├── Cookie Security Flags
├── Redirect Configuration
├── Debug / Framework Indicators
└── Broad CORS Configuration
```

Source archives can additionally be reviewed for signals involving:

```text
Secrets
Debug Configuration
Firebase / Supabase Indicators
CORS
Upload Validation
Route Access Control
Dependency Manifests
```

The scanner validates every resolved address, pins outbound connections to a validated IP while retaining hostname-based TLS verification, does not follow redirects, and inspects at most 250 KB of raw response-body data. Truncated or unexpectedly encoded bodies are explicitly reported as incomplete. It is intentionally bounded and does **not** attempt exploitation, brute force, authentication attacks, or internal-network scanning.

---

# ◈ Explainable Security Score

Valorynn starts every scan at:

```text
100
```

Findings contribute severity-based deductions.

| Severity | Deduction |
| -------- | --------: |
| Critical |       −25 |
| High     |       −14 |
| Medium   |        −7 |
| Low      |        −3 |
| Info     |         0 |

The resulting score provides a compact view of the application's observed security posture.

```text
             SECURITY SCORE

                   87
              ─────────────
                /       \
               /   ◎     \
              /           \
              ─────────────

          Evidence-based
             indicator
```

The score is intentionally **explainable rather than opaque**.

---

# ⟡ FixSignal

### *See the projected impact before you fix.*

FixSignal allows users to select findings and estimate how their recorded deductions would affect the security score.

```text
CURRENT SCORE

     72

      │
      │ + remediation projection
      ▼

PROJECTED SCORE

     89
```

### Important distinction

```text
FixSignal
    ↓
PROJECTED RESULT

Re-scan
    ↓
VERIFIED RESULT
```

A FixSignal projection does **not** replace a real security re-scan.

---

# ⟳ Re-scan & Compare

Security improvement should be measurable.

Valorynn keeps scan history so users can compare:

```text
             BEFORE          AFTER

Score          64      →       87

Findings       12      →        5

High Risk       4      →        1

Status       REVIEWED →     IMPROVED
```

This makes remediation measurable rather than subjective.

---

# ⌁ ML-Assisted Severity Classification

Valorynn includes a local training workflow based on public NVD CVE data.

### Pipeline

```text
NVD CVE DATA
     │
     ▼
TEXT + CWE / CATEGORY
     │
     ▼
TF-IDF
     │
     ▼
LOGISTIC REGRESSION
     │
     ▼
SEVERITY + CONFIDENCE
     │
     ▼
MANUAL REVIEW
```

The model reports:

* Accuracy
* Macro F1
* Confusion matrix
* Predicted severity
* Confidence

Predictions below the configured confidence threshold are marked for manual review.

> Official NVD/CVSS/CVE information remains authoritative. The ML model is intended to assist analysis, not override authoritative security data.

---

# ⚡ Quick Start

## 1. Clone

```bash
git clone https://github.com/ashfaqhyder/Valorynn.git
cd Valorynn
```

## 2. Configure Environment

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

### Linux / macOS

```bash
cp .env.example .env
```

Generate a strong random value and replace:

```env
VALORYNN_SECRET_KEY=your-high-entropy-secret
```

---

# ◉ Run with Docker

Valorynn is designed around a Docker-first development workflow.

```bash
docker compose up --build
```

Then open:

```text
http://localhost:8000
```

Create an account and add a public target that you own or are explicitly authorized to assess.

---

# 🧪 Development

Python:

```text
Python 3.11+
```

Install development dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check app tests scripts
```

---

# 🧠 Train the ML Model

Download a public NVD CVE JSON 2.0 export and run:

```bash
python scripts/train_severity_model.py path/to/nvdcve-2.0.json
```

The workflow produces:

```text
Accuracy
Macro F1
Confusion Matrix
Predicted Severity
Confidence
```

and writes:

```text
models/severity_classifier.joblib
```

---

# 🛡️ Scanner Safety

Valorynn is deliberately designed for **authorized assessment**.

Current safety boundaries include:

```text
✓ Public HTTP(S) targets only
✓ Authorization confirmation
✓ Loopback/private/reserved address rejection
✓ One request without crawling
✓ Short request timeouts
✓ ZIP size limits
✓ Scan-rate limiting
✓ In-memory source review
✓ Secret-value redaction
```

Valorynn does **not**:

```text
✗ Attempt exploits
✗ Brute force credentials
✗ Authenticate to targets
✗ Crawl entire websites
✗ Scan internal networks
```

### Use responsibly.

Only assess applications that you own or have explicit authorization to test.

---

# 🏗️ Project Structure

```text
Valorynn/
│
├── app/
│   └── Application source
│
├── models/
│   └── ML model artifacts
│
├── scripts/
│   └── Training / utility scripts
│
├── tests/
│   └── Automated tests
│
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

# 🔐 Production Notes

Before production deployment:

* Use PostgreSQL
* Use managed storage/volumes
* Set `VALORYNN_ENV=production`
* Generate a strong `VALORYNN_SECRET_KEY`
* Enable secure cookies
* Use HTTPS
* Configure a trusted reverse proxy
* Protect deployment access

Never commit:

```text
.env
Database files
ZIP archives
Tokens
Credentials
Deployment secrets
Generated private artifacts
```

---

# 🗺️ Roadmap

```text
                         VALORYNN

       ┌─────────────────────────────────────────┐
       │              CURRENT MVP                │
       └────────────────────┬────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
       Scanner            Scoring            ML
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                            ▼
                    FixSignal + Reports
                            │
                            ▼
                   Re-scan Verification
                            │
                            ▼
                 ┌──────────────────────┐
                 │    FUTURE PHASES     │
                 └──────────────────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        Team Sharing      RBAC       Advanced ML
             │              │              │
             ▼              ▼              ▼
       Compliance       Integrations   Deep CVE Matching
```

Potential future directions include:

* Team collaboration
* Organization RBAC
* Email verification / password recovery
* Compliance reporting
* Advanced ML prioritization
* Deeper dependency/CVE matching
* Additional application-security checks
* Expanded integrations

---

# ◇ Design Philosophy

Valorynn is built around one principle:

> **Security information should lead to security decisions.**

Instead of overwhelming users with raw scanner output, Valorynn aims to create a chain of understanding:

```text
SIGNAL
  ↓
FINDING
  ↓
EVIDENCE
  ↓
IMPACT
  ↓
PRIORITY
  ↓
REMEDIATION
  ↓
VERIFICATION
```

---

# 🤝 Contributing

Contributions are welcome.

A simple workflow:

```bash
git checkout -b feature/your-feature
```

Make your changes, then run:

```bash
pytest
ruff check app tests scripts
```

Review the changes for:

* Security implications
* Private-data exposure
* Test coverage
* Backward compatibility

Then open a Pull Request.

---

# ⚠️ Disclaimer

Valorynn is an application-security assessment tool intended for **authorized testing only**.

Do not use it to scan systems, applications, networks, or infrastructure without permission.

A clean Valorynn result or high security score does not guarantee that an application is completely secure.

---

# ◈ Built With

<p align="center">

<img src="https://img.shields.io/badge/Python-000000?style=flat-square&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/FastAPI-000000?style=flat-square&logo=fastapi&logoColor=white"/>
<img src="https://img.shields.io/badge/Docker-000000?style=flat-square&logo=docker&logoColor=white"/>
<img src="https://img.shields.io/badge/Scikit--learn-000000?style=flat-square&logo=scikit-learn&logoColor=white"/>
<img src="https://img.shields.io/badge/PostgreSQL-000000?style=flat-square&logo=postgresql&logoColor=white"/>
<img src="https://img.shields.io/badge/pytest-000000?style=flat-square&logo=pytest&logoColor=white"/>

</p>

---

# ◉ Valorynn

<p align="center">

### **SCAN. UNDERSTAND. FIX. VERIFY.**

<br>

`Application Security × Explainable Risk × AI/ML`

<br><br>

<a href="https://github.com/ashfaqhyder/Valorynn">
  <img src="https://img.shields.io/badge/★_Star_Valorynn-000000?style=for-the-badge&logo=github&logoColor=white" alt="Star Valorynn"/>
</a>

</p>

---

<p align="center">
  <sub>Built with curiosity, security, and a lot of debugging.</sub>
</p>
