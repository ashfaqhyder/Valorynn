# Valorynn — Defend what you make

Valorynn is a GUI-based, AI/ML-assisted application-security platform for authorized web application assessment. It helps students, developers, and organizations answer: **what is insecure, why it matters, what to fix first, and whether a re-scan improved the result.**

> Valorynn's score is an evidence-based risk indicator. It is not proof that an application is completely secure.

## What this MVP includes

- Private sign-up and sign-in for Student, Individual / Developer, and Organization accounts; passwords use scrypt hashes, never plaintext.
- Per-account application inventory, authorized target URLs, repository references, and private scan/report history.
- Mandatory ownership/authorization confirmation before each scan.
- Low-impact URL checks: HTTPS/TLS, HTTP security headers, cookie flags, redirects, debug/framework indicators, and broad CORS.
- In-memory ZIP source review (the archive is not retained): secret patterns, debug config, Firebase/Supabase indicators, CORS, upload validation, route access-control signals, and dependency manifest discovery.
- Explainable 0–100 scoring, severity groups, evidence, remediation guidance, and Easy / Moderate / Advanced effort labels.
- FixSignal simulator, re-scan history, score comparisons, and private HTML/PDF report exports.
- NVD CVE TF-IDF + Logistic Regression training workflow with accuracy, macro-F1, and confusion matrix output.

## Quick start

1. Copy the environment template: Copy-Item .env.example .env
2. Replace VALORYNN_SECRET_KEY in .env with a high-entropy random value.
3. Start the local container: docker compose up --build
4. Open http://localhost:8000, register an account, add a public target you own or are authorized to assess, then confirm authorization to scan.

The database is held in the Docker volume valorynn_data. Stop with docker compose down; use docker compose down -v only when you intentionally want to delete all local scan data.

## Scanner safety controls

The scanner is deliberately bounded. It accepts only public HTTP(S) targets, rejects loopback/private/reserved addresses during validation, makes one request without crawling or following redirects, uses short timeouts, caps ZIP upload/review sizes, and enforces five scans per account per hour. It does not try exploits, brute force, authenticate to targets, or scan internal networks.

Source archives are handled in memory for the current scan and discarded, leaving only optional filename/hash metadata. Findings redact matching secret values rather than storing them.

## Explainable score

Every scan starts at 100. Each finding records a severity-based deduction (Critical 25, High 14, Medium 7, Low 3, Info 0), capped at 25 per finding. The result page states the total deduction and severity count; the simulator adds back the selected findings' recorded deductions as a projection. The only verification is a new scan after the fix.

Risk levels combine score and evidence: any critical finding (or score below 35) is Critical; repeated High evidence (or score below 60) is High; a High finding (or score below 80) is Medium; otherwise Low.

## ML severity model

Download a public NVD CVE JSON 2.0 export and train locally or in the container:

    python scripts/train_severity_model.py path/to/nvdcve-2.0.json

The script combines English vulnerability descriptions with CWE/category text, trains TF-IDF + Logistic Regression, prints accuracy, macro F1, and a confusion matrix, then writes models/severity_classifier.joblib. Its output includes predicted severity and confidence. Any prediction below 0.65 is marked for manual review. Official NVD/CVSS/CVE data remains authoritative; the model must not override it.

## Development checks

With Python 3.11+ available:

    pip install -e .[dev]
    pytest
    ruff check app tests scripts

This workstation is Docker-first; the included Docker image installs the application dependencies.

## Deployment notes

Use PostgreSQL and a managed volume/object store before production deployment. Set VALORYNN_ENV=production, a strong VALORYNN_SECRET_KEY, VALORYNN_COOKIE_SECURE=true, a trusted reverse proxy with HTTPS, and private Render access for demonstrations. Never commit .env, database files, ZIP archives, generated model artifacts, tokens, or deployment credentials.

Current scope intentionally excludes direct AI-builder integrations, instructor/team sharing, email verification/resets, organization RBAC, compliance reporting, advanced ML prioritization, and deep dependency/CVE matching. These are the planned next phases.

## Suggested Git workflow

    main
    ├─ feature/auth-and-users
    ├─ feature/app-management
    ├─ feature/scanner
    ├─ feature/dashboard
    ├─ feature/ml-severity-model
    ├─ feature/scoring
    └─ feature/reporting

Keep changes isolated to a feature branch, run the checks above, review for private data exposure, then merge through a pull request.
