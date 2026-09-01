from app.scoring import calculate_score, projected_score


def finding(severity: str, impact: int) -> dict:
    return {"severity": severity, "score_impact": impact}


def test_score_is_bounded_and_explained() -> None:
    score, risk, explanation = calculate_score([finding("critical", 25), finding("high", 14)])
    assert score == 61
    assert risk == "Critical"
    assert "100 starting points" in explanation


def test_projection_never_exceeds_one_hundred() -> None:
    assert projected_score(92, [finding("high", 14)]) == 100
