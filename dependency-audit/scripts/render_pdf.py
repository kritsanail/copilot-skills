#!/usr/bin/env python3

import json
import os
import sys

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except ImportError:
    sys.stderr.write("reportlab is required: python3 -m pip install -r requirements.txt\n")
    sys.exit(3)


def find_font():
    candidates = [
        os.environ.get("DEPENDENCY_AUDIT_REPORT_FONT"),
        "/System/Library/Fonts/Thonburi.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf",
        "C:/Windows/Fonts/tahoma.ttf",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            try:
                pdfmetrics.registerFont(TTFont("ReportFont", candidate, subfontIndex=0))
                return "ReportFont"
            except Exception:
                continue
    return "Helvetica"


def safe(value):
    return str(value if value is not None else "-").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(FONT, 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, 10 * mm, "Dependency Audit")
    canvas.drawRightString(192 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


if len(sys.argv) != 3:
    sys.stderr.write("usage: render_pdf.py summary.json output.pdf\n")
    sys.exit(2)

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

FONT = find_font()
styles = getSampleStyleSheet()
title = ParagraphStyle("TitleCustom", parent=styles["Title"], fontName=FONT, fontSize=22, leading=27, textColor=colors.HexColor("#0f172a"), alignment=TA_LEFT, spaceAfter=12)
heading = ParagraphStyle("HeadingCustom", parent=styles["Heading2"], fontName=FONT, fontSize=14, leading=18, textColor=colors.HexColor("#1d4ed8"), spaceBefore=12, spaceAfter=8)
body = ParagraphStyle("BodyCustom", parent=styles["BodyText"], fontName=FONT, fontSize=9.5, leading=14, textColor=colors.HexColor("#334155"))
small = ParagraphStyle("SmallCustom", parent=body, fontSize=8, leading=11)

doc = SimpleDocTemplate(sys.argv[2], pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm, title="Dependency Audit")
story = [
    Paragraph("Dependency Audit", title),
    Paragraph(f"Project: {safe(data['project']['name'])} | Ecosystem: {safe(data['project'].get('ecosystem'))} | Generated: {safe(data['generatedAt'])}", body),
    Spacer(1, 8),
    Paragraph("Read-only audit report. Project files were not modified. Scanner coverage limitations and failed data sources must be considered when interpreting findings.", body),
    Paragraph("Audit summary", heading),
]

summary_rows = [
    ["Metric", "Value"],
    ["Package manager", safe(data["project"]["packageManager"])],
    ["Direct dependencies", str(data["dependencies"]["direct"])],
    ["Unique resolved packages", str(data["dependencies"]["uniqueResolved"])],
    ["Potentially unused findings", str(data["dependencies"]["possiblyUnused"])],
    ["Vulnerability findings", str(data["vulnerabilities"]["total"])],
    ["Critical", str(data["vulnerabilities"]["severity"].get("critical", 0))],
    ["High", str(data["vulnerabilities"]["severity"].get("high", 0))],
]
table = Table(summary_rows, colWidths=[105 * mm, 50 * mm], repeatRows=1)
table.setStyle(TableStyle([
    ("FONTNAME", (0, 0), (-1, -1), FONT),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
]))
story.extend([table, Paragraph("Scan coverage", heading)])
coverage_rows = [["Area", "Result"]] + [[safe(key), safe(value)] for key, value in data["coverage"].items()]
coverage = Table(coverage_rows, colWidths=[50 * mm, 105 * mm], repeatRows=1)
coverage.setStyle(TableStyle([
    ("FONTNAME", (0, 0), (-1, -1), FONT),
    ("FONTSIZE", (0, 0), (-1, -1), 8),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]))
story.extend([
    coverage,
    Paragraph("Cache", heading),
    Paragraph(f"Dependency scan: {safe(data['cache']['dependencyScan'])}<br/>Vulnerability scan: {safe(data['cache']['vulnerabilityScan'])}<br/>Fingerprint: {safe(data['cache']['fingerprint'])}", small),
    Paragraph("Artifacts", heading),
])
for key, value in data["reports"].items():
    if isinstance(value, str):
        story.append(Paragraph(f"{safe(key)}: {safe(value)}", small))

doc.build(story, onFirstPage=footer, onLaterPages=footer)
