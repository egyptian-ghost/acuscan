#!/usr/bin/env python3
"""PDF report (via weasyprint or reportlab)."""
import os
from collections import Counter
from datetime import datetime

from core.config import VERSION
from core.colors import SEVERITY_ORDER


def write_pdf_report(filepath, targets, findings):
    """
    Try weasyprint first, fall back to reportlab, else return False.
    """
    # Try weasyprint (HTML → PDF)
    try:
        from weasyprint import HTML
        from .html_report import write_html_report

        html_path = filepath.replace(".pdf", ".html")
        write_html_report(html_path, targets, findings)
        HTML(filename=html_path).write_pdf(filepath)
        try:
            os.remove(html_path)
        except Exception:
            pass
        return True
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: reportlab
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak,
        )
    except ImportError:
        return False

    try:
        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            topMargin=2 * cm, bottomMargin=2 * cm,
            leftMargin=2 * cm, rightMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "Title", parent=styles["Title"], fontSize=24,
            textColor=colors.HexColor("#0f172a"),
        )
        h2 = ParagraphStyle(
            "H2", parent=styles["Heading2"], fontSize=16,
            textColor=colors.HexColor("#38bdf8"),
        )
        normal = styles["Normal"]

        story = []
        story.append(Paragraph("AcuScan Security Report", title_style))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            normal,
        ))
        story.append(Paragraph(f"Targets: {len(targets)}", normal))
        story.append(Paragraph(f"Total Findings: {len(findings)}", normal))
        story.append(Spacer(1, 1 * cm))

        # Summary table
        sev_counts = Counter(f.severity for f in findings)
        data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            data.append([sev.upper(), str(sev_counts.get(sev, 0))])
        table = Table(data, colWidths=[8 * cm, 4 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#475569")),
        ]))
        story.append(table)
        story.append(PageBreak())

        # Findings
        story.append(Paragraph("Findings", h2))
        story.append(Spacer(1, 0.5 * cm))
        sorted_f = sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.name),
        )
        for i, f in enumerate(sorted_f, 1):
            story.append(Paragraph(
                f"{i}. [{f.severity.upper()}] {f.name}", h2
            ))
            story.append(Paragraph(f"<b>URL:</b> {f.url}", normal))
            if getattr(f, "parameter", ""):
                story.append(Paragraph(
                    f"<b>Parameter:</b> {f.parameter}", normal
                ))
            if getattr(f, "confidence", 0):
                story.append(Paragraph(
                    f"<b>Confidence:</b> {f.confidence:.0%}", normal
                ))
            if f.detail:
                story.append(Paragraph(f"<b>Detail:</b> {f.detail}", normal))
            if getattr(f, "evidence", ""):
                story.append(Paragraph(
                    f"<b>Evidence:</b> {f.evidence[:300]}", normal
                ))
            if getattr(f, "cve", ""):
                story.append(Paragraph(f"<b>CVE:</b> {f.cve}", normal))
            story.append(Spacer(1, 0.5 * cm))

        doc.build(story)
        return True
    except Exception:
        return False