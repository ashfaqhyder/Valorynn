"""Train and evaluate Valorynn's explainable dependency-severity classifier.

Input is an NVD CVE JSON 2.0 export. Official NVD/CVSS data is kept authoritative;
this classifier provides a confidence-scored suggestion only when verified data is
absent or needs triage.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def english_description(cve: dict) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def cvss_severity(cve: dict) -> str | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key, [])
        if values:
            severity = values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity")
            if isinstance(severity, str) and severity.upper() in SEVERITIES:
                return severity.upper()
    return None


def categories(cve: dict) -> str:
    values: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            values.append(description.get("value", ""))
    return " ".join(values)


def generate_synthetic_examples() -> tuple[list[str], list[str]]:
    samples = [
        ("Remote code execution vulnerability via unauthenticated deserialization in payload processing.", "critical"),
        ("SQL injection vulnerability allows unauthorized database dumping and admin access.", "critical"),
        ("Hard-coded administrative credentials and JWT secret key in source code repository.", "critical"),
        ("Unauthenticated arbitrary file upload leading to web shell execution.", "critical"),
        ("Cross-site scripting (XSS) vulnerability in user input rendering without escaping.", "high"),
        ("Missing authentication middleware on sensitive API endpoint exposing user records.", "high"),
        ("Wildcard Access-Control-Allow-Origin header allowing cross-origin data access.", "high"),
        ("Broken access control allowing privilege escalation to organization admin role.", "high"),
        ("Missing HTTP security header Strict-Transport-Security HSTS on HTTPS endpoint.", "medium"),
        ("Missing HttpOnly and Secure flags on session authentication cookies.", "medium"),
        ("Development debug mode enabled disclosing framework tracebacks and environment variables.", "medium"),
        ("Outdated dependency with known low severity denial of service vulnerability.", "medium"),
        ("Missing Referrer-Policy header exposing sensitive query parameters to external sites.", "low"),
        ("Server header disclosing precise backend web framework version information.", "low"),
        ("Information disclosure via detailed error messages in public API response.", "low"),
    ]
    texts, labels = [], []
    for base_text, severity in samples:
        for suffix in [" (CWE-89)", " (CWE-79)", " (CWE-200)", " (CWE-287)", " (CWE-306)", " (CWE-20)"]:
            texts.append(f"{base_text}{suffix}")
            labels.append(severity)
    return texts, labels


def load_examples(path: Path | None) -> tuple[list[str], list[str]]:
    if path is None or not path.exists():
        return generate_synthetic_examples()
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = document.get("vulnerabilities", document.get("CVE_Items", []))
    texts, labels = [], []
    for row in rows:
        cve = row.get("cve", row)
        severity = cvss_severity(cve)
        description = english_description(cve)
        if severity and description:
            texts.append(f"{description} {categories(cve)}")
            labels.append(severity.lower())
    if len(set(labels)) < 2:
        return generate_synthetic_examples()
    return texts, labels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("nvd_json", type=Path, nargs="?", default=None, help="NVD CVE JSON 2.0 export")
    parser.add_argument("--synthetic", action="store_true", help="Generate synthetic training data")
    parser.add_argument("--output", type=Path, default=Path("models/severity_classifier.joblib"))
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    if args.synthetic or args.nvd_json is None:
        texts, labels = generate_synthetic_examples()
    else:
        texts, labels = load_examples(args.nvd_json)

    train_x, test_x, train_y, test_y = train_test_split(
        texts, labels, test_size=args.test_size, random_state=42, stratify=labels
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=50_000)),
        ("model", LogisticRegression(max_iter=2_000, class_weight="balanced", random_state=42)),
    ])
    pipeline.fit(train_x, train_y)
    predicted = pipeline.predict(test_x)
    ordered = sorted(set(labels))
    metrics = {
        "accuracy": round(float(accuracy_score(test_y, predicted)), 4),
        "macro_f1": round(float(f1_score(test_y, predicted, average="macro")), 4),
        "labels": ordered,
        "confusion_matrix": confusion_matrix(test_y, predicted, labels=ordered).tolist(),
        "train_examples": len(train_x),
        "test_examples": len(test_x),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipeline, "version": "tfidf-logreg-v1", "metrics": metrics}, args.output)
    print(json.dumps(metrics, indent=2))
    print(f"Saved model to {args.output}")


if __name__ == "__main__":
    main()
