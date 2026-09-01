"""Private report renderers. Reports contain only the requesting owner's scan data."""
from __future__ import annotations

from html import escape
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def html_report(scan: dict, findings: list[dict]) -> str:
    items = "".join(
        f"<article><h3>{escape(item['title'])} <small>{escape(item['severity'].upper())}</small></h3>"
        f"<p><strong>Evidence:</strong> {escape(item['evidence'])}</p>"
        f"<p>{escape(item['explanation'])}</p><p><strong>Fix:</strong> {escape(item['remediation'])}</p></article>"
        for item in findings
    ) or "<p>No findings were recorded in this scan.</p>"
    return f"""<!doctype html><html><head><meta charset=utf-8><title>Valorynn scan report</title>
    <style>body{{font:16px system-ui;max-width:900px;margin:3rem auto;color:#172033}}article{{border-top:1px solid #d9dfeb;padding:1rem 0}}small{{color:#a33}}</style></head><body>
    <h1>Valorynn security assessment</h1><p><strong>Application:</strong> {escape(scan['application_name'])}<br>
    <strong>Target:</strong> {escape(scan['target_url'])}<br><strong>Score:</strong> {scan['score']}/100 ({escape(scan['risk_level'] or 'Unavailable')})<br>
    <strong>Completed:</strong> {escape(scan['completed_at'] or 'Not completed')}</p>
    <p><em>This score is an evidence-based risk indicator, not proof that the application is secure.</em></p><h2>Findings</h2>{items}</body></html>"""


def pdf_report(scan: dict, findings: list[dict]) -> bytes:
    output = BytesIO()
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Valorynn security assessment", styles["Title"]),
        Paragraph(f"<b>Application:</b> {escape(scan['application_name'])}", styles["BodyText"]),
        Paragraph(f"<b>Target:</b> {escape(scan['target_url'])}", styles["BodyText"]),
        Paragraph(f"<b>Score:</b> {scan['score']}/100 — {escape(scan['risk_level'] or 'Unavailable')}", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("This score is an evidence-based risk indicator, not proof an application is completely secure.", styles["Italic"]),
        Spacer(1, 12),
    ]
    for finding in findings:
        story.extend([
            Paragraph(f"{escape(finding['title'])} ({escape(finding['severity'].upper())})", styles["Heading3"]),
            Paragraph(f"<b>Evidence:</b> {escape(finding['evidence'])}", styles["BodyText"]),
            Paragraph(escape(finding["explanation"]), styles["BodyText"]),
            Paragraph(f"<b>Recommended fix:</b> {escape(finding['remediation'])}", styles["BodyText"]),
            Spacer(1, 8),
        ])
    SimpleDocTemplate(output, pagesize=letter, title="Valorynn security report").build(story)
    return output.getvalue()
