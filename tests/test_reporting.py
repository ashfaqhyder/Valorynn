from __future__ import annotations

from collections import Counter

from app import remediation, reporting
from app.main import templates


def _finding(category: str, title: str, evidence: str = "Observed test evidence.") -> dict:
    return {
        "category": category,
        "title": title,
        "severity": "medium",
        "evidence": evidence,
        "explanation": "Stored scanner explanation.",
        "remediation": "Stored remediation.",
        "effort": "Moderate",
        "score_impact": 7,
        "confidence": None,
        "source": "url-check",
    }


def _scan(summary: str = "100 starting points minus 7 evidence-based deduction(s).") -> dict:
    return {
        "application_name": "Example application",
        "target_url": "https://example.invalid",
        "score": 93,
        "risk_level": "Low",
        "completed_at": "2026-10-21T10:00:00+00:00",
        "summary": summary,
    }


def test_every_supported_finding_rule_has_complete_guidance():
    categories = set()
    for category, title in remediation.GUIDANCE_BY_RULE:
        categories.add(category)
        guide = remediation.guidance_for(_finding(category, title))
        assert guide["simple_explanation"]
        assert guide["what_scanner_observed"]
        assert guide["why_it_matters"]
        assert guide["steps"]
        assert guide["verification"]
        assert guide["ask_developer"]
        assert isinstance(guide["priority"], str) and guide["priority"]
        assert guide["effort"]
        assert guide["technical_details"]["source"]

    assert categories == {
        "Transport",
        "Configuration",
        "Availability",
        "Assessment coverage",
        "Security headers",
        "Cookies",
        "Exposure",
        "Vibe-coded app mode",
        "Source review",
        "Dependencies",
        "Secrets",
    }


def test_missing_evidence_and_unknown_finding_are_explicitly_unverified():
    finding = _finding("Transport", "HTTPS is not used", evidence="")
    guide = remediation.guidance_for(finding)
    assert guide["evidence_kind"] == "unverified"
    assert guide["evidence_label"] == "Unverified; no evidence recorded"
    assert "No evidence was recorded" in guide["evidence"]

    unknown = remediation.guidance_for(_finding("New category", "New rule"))
    assert unknown["evidence_kind"] == "unverified"
    assert "no category-specific" in unknown["simple_explanation"]
    assert "does not infer an unsupported" in unknown["why_it_matters"]


def test_html_report_includes_guidance_and_marks_incomplete_scan():
    finding = _finding(
        "Assessment coverage",
        "Response body inspection incomplete",
        "Only the first 250000 response-body bytes were inspected.",
    )
    report = reporting.html_report(
        _scan("Incomplete assessment. 100 starting points minus 0 evidence-based deduction(s)."),
        [finding],
    )

    assert "Executive summary" in report
    assert "Key risks and recommended order" in report
    assert "Assessment coverage:</strong> Incomplete" in report
    assert "What to ask your developer" in report
    assert "How to verify" in report
    assert "Only the first" in report
    assert "suggested fix is not a verified fix" in report.lower()


def test_html_and_pdf_escape_untrusted_finding_content(monkeypatch):
    hostile = '<script>alert("x")</script><link href="https://evil.invalid">click</link>'
    finding = _finding("Unknown", "Unrecognized <img src=x>", hostile)
    html = reporting.html_report(_scan(), [finding])

    assert 'src="data:image/png;base64,' in html
    assert 'class="brand-title">VALORYNN' in html
    assert 'url(\'data:font/otf;base64,' in html
    assert 'class="brand-lockup"' in html
    assert reporting.LOGO_LIGHT_PATH.exists()
    assert 'filter:invert(1)' not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "<script>alert" not in html
    assert "href=\"https://evil.invalid\"" not in html

    original_paragraph = reporting.Paragraph
    original_image = reporting.Image
    paragraph_inputs = []
    image_paths = []

    def capture_paragraph(text, style, *args, **kwargs):
        paragraph_inputs.append(text)
        return original_paragraph(text, style, *args, **kwargs)

    def capture_image(path, *args, **kwargs):
        image_paths.append(str(path))
        return original_image(path, *args, **kwargs)

    monkeypatch.setattr(reporting, "Paragraph", capture_paragraph)
    monkeypatch.setattr(reporting, "Image", capture_image)
    pdf = reporting.pdf_report(_scan(), [finding])

    assert pdf.startswith(b"%PDF")
    assert set(image_paths) == {str(reporting.LOGO_LIGHT_PATH), str(reporting.WORDMARK_PATH)}
    assert any("&lt;script&gt;" in text for text in paragraph_inputs)
    assert any("&lt;link" in text for text in paragraph_inputs)
    assert not any('<link href="https://evil.invalid">' in text for text in paragraph_inputs)


def test_dashboard_finding_details_escape_untrusted_evidence():
    hostile = '<script>alert("x")</script>'
    finding = remediation.enrich_findings(
        [_finding("Unknown", "<img src=x>", hostile)]
    )[0]
    rendered = templates.get_template("scan_results.html").render(
        user=None,
        csrf_token="csrf",
        scan={
            "id": 1,
            "application_id": 2,
            "application_name": "Example",
            "target_url": "https://example.invalid",
            "score": 93,
            "risk_level": "Low",
            "summary": "Test summary",
        },
        findings=[finding],
        groups={"critical": [], "high": [], "medium": [finding], "low": [], "info": []},
        counts=Counter({"medium": 1}),
        report=remediation.report_overview(_scan(), [finding]),
    )

    assert "&lt;script&gt;" in rendered
    assert "&lt;img" in rendered
    assert "<script>alert" not in rendered


def test_comparison_does_not_call_findings_resolved_when_later_scan_is_incomplete():
    rendered = templates.get_template("comparison.html").render(
        user=None,
        csrf_token="csrf",
        application={"id": 2, "name": "Example"},
        scans=[],
        before={"id": 1, "score": 80, "risk_level": "Medium", "completed_at": "before"},
        after={"id": 2, "score": 90, "risk_level": "Low", "completed_at": "after"},
        score_change=10,
        resolved=["Missing header"],
        new=[],
        before_assessment_status="Completed within configured checks",
        before_limitation="Limited scope.",
        after_assessment_status="Incomplete",
        after_limitation="Some checks did not complete.",
    )

    assert "Later assessment incomplete; score change is not directly comparable" in rendered
    assert "Their absence is inconclusive and must not be treated as resolution." in rendered
    assert "Findings no longer observed" in rendered
    assert "Resolved Findings" not in rendered


def test_assessment_status_does_not_call_completed_assessment_secure():
    scan = _scan()
    scan["summary"] = "Incomplete assessment. retry required"
    status, limitation = remediation.assessment_status(scan, [])

    assert status == "Incomplete"
    assert "not as clear" in limitation

    status, limitation = remediation.assessment_status(_scan(), [])
    assert status == "Completed within configured checks"
    assert "cannot prove" in limitation
