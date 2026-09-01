"""Deterministic, evidence-based security score calculations."""
from __future__ import annotations

from collections import Counter

SEVERITY_POINTS = {"critical": 25, "high": 14, "medium": 7, "low": 3, "info": 0}


def calculate_score(findings: list[dict]) -> tuple[int, str, str]:
    """Return a bounded score, risk label, and transparent score explanation.

    Findings have capped, documented deductions. This makes the score a prioritization
    signal rather than a claim that an app is safe or free from vulnerabilities.
    """
    deductions = sum(min(int(f.get("score_impact", SEVERITY_POINTS[f["severity"]])), 25) for f in findings)
    score = max(0, min(100, 100 - deductions))
    critical = sum(f["severity"] == "critical" for f in findings)
    high = sum(f["severity"] == "high" for f in findings)
    if critical or score < 35:
        risk = "Critical"
    elif high >= 2 or score < 60:
        risk = "High"
    elif high or score < 80:
        risk = "Medium"
    else:
        risk = "Low"
    counts = Counter(f["severity"] for f in findings)
    detail = ", ".join(f"{counts.get(level, 0)} {level}" for level in ("critical", "high", "medium", "low"))
    explanation = f"100 starting points minus {deductions} evidence-based deduction(s): {detail}."
    return score, risk, explanation


def projected_score(scan_score: int, selected_findings: list[dict]) -> int:
    return min(100, scan_score + sum(int(item["score_impact"]) for item in selected_findings))
