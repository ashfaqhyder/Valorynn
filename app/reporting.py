"""Private report renderers. Reports contain only the requesting owner's scan data."""
from __future__ import annotations

import base64
from html import escape
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table

from app.remediation import assessment_status, enrich_findings, report_overview

LOGO_PATH = Path(__file__).resolve().parent / "static" / "images" / "valorynn-logo.png"
LOGO_LIGHT_PATH = Path(__file__).resolve().parent / "static" / "images" / "valorynn-logo-light.png"
FONT_PATH = Path(__file__).resolve().parent / "static" / "anurati-regular.otf"
WORDMARK_PATH = Path(__file__).resolve().parent / "static" / "images" / "valorynn-wordmark.png"


def _data_uri(path: Path, media_type: str) -> str:
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


def _html_guidance(guidance: dict) -> str:
    steps = "".join(f"<li>{escape(step)}</li>" for step in guidance["steps"])
    example = ""
    if guidance["example"]:
        example = (
            "<h4>Example configuration (illustrative; review before use)</h4>"
            f"<pre>{escape(guidance['example'])}</pre>"
        )
    references = "".join(
        f'<li><a href="{escape(reference["url"], quote=True)}" rel="noopener">'
        f'{escape(reference["label"])}</a></li>'
        for reference in guidance["references"]
    )
    reference_section = f"<h4>References</h4><ul>{references}</ul>" if references else ""
    technical = guidance["technical_details"]
    confidence = (
        str(technical["confidence"])
        if technical["confidence"] is not None
        else "not recorded"
    )
    return (
        f"<h3>Simple explanation</h3><p>{escape(guidance['simple_explanation'])}</p>"
        f"<p><strong>Why it matters:</strong> {escape(guidance['why_it_matters'])}</p>"
        f"<h3>What the scanner observed</h3>"
        f"<p>{escape(guidance['what_scanner_observed'])}</p>"
        f"<p><strong>{escape(guidance['evidence_label'])}:</strong> "
        f"{escape(guidance['evidence'])}</p>"
        f"<p><strong>Suggested priority:</strong> {escape(guidance['priority'])}; "
        f"<strong>complexity:</strong> {escape(guidance['effort'])}</p>"
        f"<h3>Recommended steps</h3><ol>{steps}</ol>{example}"
        f"<p><strong>How to verify:</strong> {escape(guidance['verification'])}</p>"
        f"<p><strong>What to ask your developer:</strong> "
        f"{escape(guidance['ask_developer'])}</p>"
        f"<h3>Technical details</h3>"
        f"<p>Category: {escape(technical['category'])}; source: "
        f"{escape(technical['source'])}; confidence: {escape(confidence)}.</p>"
        f"<p>{escape(technical['location_note'])}</p>{reference_section}"
    )


def html_report(scan: dict, findings: list[dict]) -> str:
    overview = report_overview(scan, findings)
    enriched = enrich_findings(findings)
    logo_uri = _data_uri(LOGO_LIGHT_PATH, "image/png")
    font_uri = _data_uri(FONT_PATH, "font/otf")
    items = "".join(
        f"<article><h2>{escape(item.get('title', 'Untitled finding'))} "
        f"<small>{escape(str(item.get('severity', 'info')).upper())}</small></h2>"
        f"<p><strong>Original scanner explanation:</strong> "
        f"{escape(item.get('explanation') or 'No explanation was recorded.')}</p>"
        f"<p><strong>Original remediation:</strong> "
        f"{escape(item.get('remediation') or 'No remediation was recorded.')}</p>"
        f"{_html_guidance(item['guidance'])}</article>"
        for item in enriched
    ) or "<p>No findings were recorded in this scan. This does not prove the application is secure.</p>"
    key_risks = "".join(
        f"<li><strong>{escape(str(item.get('severity', 'info')).upper())}: "
        f"{escape(item.get('title', 'Untitled finding'))}</strong> - "
        f"{escape(item['guidance']['priority'])} priority</li>"
        for item in enrich_findings(overview["key_risks"])
    ) or "<li>No medium-or-higher findings were recorded.</li>"
    status, limitation = assessment_status(scan, findings)
    return f"""<!doctype html><html><head><meta charset=utf-8><title>Valorynn scan report</title>
    <style>@font-face{{font-family:Anurati;src:url('{font_uri}') format('opentype');font-display:swap}}body{{font:16px system-ui;max-width:900px;margin:3rem auto;color:#172033}}header{{display:flex;align-items:center;gap:.65rem;border-bottom:1px solid #d9dfeb;padding-bottom:1rem}}header .brand-symbol{{width:2.5rem;height:auto;object-fit:contain}}.brand-title{{font:1.4rem Anurati,system-ui,sans-serif;letter-spacing:.08em;color:#172033;line-height:1}}article{{border-top:1px solid #d9dfeb;padding:1rem 0}}small{{color:#a33}}pre{{white-space:pre-wrap;background:#f4f6fa;padding:1rem}}a{{overflow-wrap:anywhere}}</style></head><body>
    <header class="brand-lockup"><img class="brand-symbol" src="{logo_uri}" alt=""><span class="brand-title">VALORYNN</span></header>
    <h1>Security assessment</h1><p><strong>Application:</strong> {escape(scan['application_name'])}<br>
    <strong>Target:</strong> {escape(scan['target_url'])}<br><strong>Score:</strong> {scan['score']}/100 ({escape(scan['risk_level'] or 'Unavailable')})<br>
    <strong>Completed:</strong> {escape(scan.get('completed_at') or 'Not completed')}<br>
    <strong>Assessment coverage:</strong> {escape(status)}</p>
    <h2>Executive summary</h2><p>{escape(overview['executive_summary'])}</p>
    <h2>Key risks and recommended order</h2><ol>{key_risks}</ol>
    <h2>Detailed findings</h2>{items}
    <h2>Verification and limitations</h2>
    <p>{escape(overview['verification_note'])}</p><p>{escape(limitation)}</p>
    <p><em>The score remains an evidence-based prioritization indicator, not proof that the application is secure.</em></p>
    </body></html>"""


def pdf_report(scan: dict, findings: list[dict]) -> bytes:
    output = BytesIO()
    styles = getSampleStyleSheet()
    overview = report_overview(scan, findings)
    status, limitation = assessment_status(scan, findings)
    story = [
        Table(
            [[Image(str(LOGO_LIGHT_PATH), width=34, height=32), Image(str(WORDMARK_PATH), width=170, height=27.6)]],
            colWidths=[42, 180],
            style=[
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#d9dfeb")),
            ],
        ),
        Paragraph("Security assessment", styles["Heading2"]),
        Paragraph(f"<b>Application:</b> {escape(scan['application_name'])}", styles["BodyText"]),
        Paragraph(f"<b>Target:</b> {escape(scan['target_url'])}", styles["BodyText"]),
        Paragraph(
            f"<b>Score:</b> {scan['score']}/100 - {escape(scan['risk_level'] or 'Unavailable')}",
            styles["BodyText"],
        ),
        Paragraph(f"<b>Assessment coverage:</b> {escape(status)}", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Executive summary", styles["Heading2"]),
        Paragraph(escape(overview["executive_summary"]), styles["BodyText"]),
        Paragraph("Key risks and recommended order", styles["Heading2"]),
    ]
    for finding in overview["key_risks"]:
        guide = enrich_findings([finding])[0]["guidance"]
        story.append(
            Paragraph(
                f"<b>{escape(str(finding.get('severity', 'info')).upper())}: "
                f"{escape(finding.get('title', 'Untitled finding'))}</b> - "
                f"{escape(guide['priority'])} priority.",
                styles["BodyText"],
            )
        )
    story.append(Paragraph("Detailed findings", styles["Heading2"]))
    enriched = enrich_findings(findings)
    if not enriched:
        story.append(
            Paragraph(
                "No findings were recorded. This does not prove the application is secure.",
                styles["BodyText"],
            )
        )
    for finding in enriched:
        guide = finding["guidance"]
        technical = guide["technical_details"]
        confidence = str(technical["confidence"]) if technical["confidence"] is not None else "not recorded"
        story.extend([
            Paragraph(
                f"{escape(finding.get('title', 'Untitled finding'))} "
                f"({escape(str(finding.get('severity', 'info')).upper())})",
                styles["Heading3"],
            ),
            Paragraph(
                f"<b>Original scanner explanation:</b> "
                f"{escape(finding.get('explanation') or 'No explanation was recorded.')}",
                styles["BodyText"],
            ),
            Paragraph(
                f"<b>Original remediation:</b> "
                f"{escape(finding.get('remediation') or 'No remediation was recorded.')}",
                styles["BodyText"],
            ),
            Paragraph("Simple explanation", styles["Heading4"]),
            Paragraph(escape(guide["simple_explanation"]), styles["BodyText"]),
            Paragraph(f"<b>Why it matters:</b> {escape(guide['why_it_matters'])}", styles["BodyText"]),
            Paragraph("What the scanner observed", styles["Heading4"]),
            Paragraph(escape(guide["what_scanner_observed"]), styles["BodyText"]),
            Paragraph(
                f"<b>{escape(guide['evidence_label'])}:</b> {escape(guide['evidence'])}",
                styles["BodyText"],
            ),
            Paragraph(
                f"<b>Suggested priority:</b> {escape(guide['priority'])}; "
                f"<b>complexity:</b> {escape(guide['effort'])}",
                styles["BodyText"],
            ),
            Paragraph("Recommended steps", styles["Heading4"]),
        ])
        for number, step in enumerate(guide["steps"], start=1):
            story.append(Paragraph(f"{number}. {escape(step)}", styles["BodyText"]))
        if guide["example"]:
            story.extend([
                Paragraph("Example configuration (review before use)", styles["Heading4"]),
                Paragraph(
                    escape(guide["example"]).replace("\n", "<br/>"),
                    styles["Code"],
                ),
            ])
        story.extend([
            Paragraph(f"<b>How to verify:</b> {escape(guide['verification'])}", styles["BodyText"]),
            Paragraph(f"<b>What to ask your developer:</b> {escape(guide['ask_developer'])}", styles["BodyText"]),
            Paragraph("Technical details", styles["Heading4"]),
            Paragraph(
                f"Category: {escape(technical['category'])}; source: "
                f"{escape(technical['source'])}; confidence: {escape(confidence)}.",
                styles["BodyText"],
            ),
            Paragraph(escape(technical["location_note"]), styles["BodyText"]),
        ])
        for reference in guide["references"]:
            story.append(
                Paragraph(
                    f'<link href="{escape(reference["url"], quote=True)}">'
                    f"{escape(reference['label'])}</link>",
                    styles["BodyText"],
                )
            )
        story.append(Spacer(1, 8))
    story.extend([
        Paragraph("Verification and limitations", styles["Heading2"]),
        Paragraph(escape(overview["verification_note"]), styles["BodyText"]),
        Paragraph(escape(limitation), styles["BodyText"]),
        Paragraph(
            "The score is an evidence-based risk indicator, not proof an application is secure.",
            styles["Italic"],
        ),
        Spacer(1, 12),
    ])
    SimpleDocTemplate(output, pagesize=letter, title="Valorynn security report").build(story)
    return output.getvalue()
