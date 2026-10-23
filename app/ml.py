"""Severity classifier integration with an authoritative-data-first policy."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

MODEL_PATH = Path("models/severity_classifier.joblib")
LOW_CONFIDENCE = 0.65


def predict_severity(
    description: str,
    categories: str = "",
    authoritative_severity: str | None = None,
) -> dict[str, Any] | None:
    """Predict severity only when a locally trained model is present.

    CVSS/NVD severity must always be used where supplied. A low-confidence prediction
    explicitly asks for manual review instead of presenting false certainty.
    """
    if authoritative_severity:
        return {
            "severity": authoritative_severity.lower(),
            "confidence": 1.0,
            "manual_review": False,
            "model_version": "authoritative-cvss",
        }
    if not MODEL_PATH.exists():
        return None
    bundle = joblib.load(MODEL_PATH)
    text = f"{description} {categories}".strip()
    probabilities = bundle["pipeline"].predict_proba([text])[0]
    classes = bundle["pipeline"].classes_
    index = int(probabilities.argmax())
    confidence = float(probabilities[index])
    return {
        "severity": str(classes[index]).lower(),
        "confidence": confidence,
        "manual_review": confidence < LOW_CONFIDENCE,
        "model_version": bundle.get("version", "tfidf-logreg-v1"),
    }
