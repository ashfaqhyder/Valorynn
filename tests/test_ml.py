from app.ml import predict_severity
from scripts.train_severity_model import cvss_severity


def test_cvss_v40_is_preferred_over_older_metrics() -> None:
    cve = {
        "metrics": {
            "cvssMetricV40": [{"cvssData": {"baseSeverity": "CRITICAL"}}],
            "cvssMetricV31": [{"cvssData": {"baseSeverity": "LOW"}}],
        }
    }
    assert cvss_severity(cve) == "CRITICAL"


def test_authoritative_severity_bypasses_model() -> None:
    result = predict_severity("unrelated description", authoritative_severity="HIGH")
    assert result == {
        "severity": "high",
        "confidence": 1.0,
        "manual_review": False,
        "model_version": "authoritative-cvss",
    }
