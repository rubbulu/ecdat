from __future__ import annotations

import io
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from backend.app.models.artefact import Artefact
from backend.app.recommend.engine import Recommendation, generate_recommendations
from backend.app.risk.engine import RiskSummary, assess_scan_risk

logger = logging.getLogger(__name__)

# Check for WeasyPrint
try:
    from weasyprint import HTML as WeasyHTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, Exception):
    WeasyHTML = None
    WEASYPRINT_AVAILABLE = False

# Check for ReportLab
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFReportGenerator:
    """
    Exports cryptographic risk and CBOM assessment into a printable PDF report.
    Uses WeasyPrint when available, with a resilient ReportLab fallback.
    """

    @classmethod
    def generate_pdf(
        cls,
        artefacts: List[Artefact],
        summary: Optional[RiskSummary] = None,
        recommendations: Optional[List[Recommendation]] = None,
        target_name: str = "ECDAT Target Application",
        default_y: float = 3.0,
        default_z: float = 12.0,
        output_path: Optional[str | Path] = None,
    ) -> bytes:
        if summary is None:
            summary = assess_scan_risk(artefacts, y=default_y, z=default_z)
        if recommendations is None:
            recommendations = generate_recommendations(artefacts, y=default_y, z=default_z)

        # 1. Try WeasyPrint if installed
        if WEASYPRINT_AVAILABLE:
            try:
                from backend.app.export.report_html import HTMLReportGenerator
                html_str = HTMLReportGenerator.generate_html(
                    artefacts=artefacts,
                    summary=summary,
                    recommendations=recommendations,
                    target_name=target_name,
                    default_y=default_y,
                    default_z=default_z,
                )
                pdf_bytes = WeasyHTML(string=html_str).write_pdf()
                if output_path:
                    Path(output_path).write_bytes(pdf_bytes)
                return pdf_bytes
            except Exception as e:
                logger.warning(f"WeasyPrint rendering failed: {e}. Falling back to ReportLab.")

        # 2. ReportLab Fallback
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("Neither WeasyPrint nor ReportLab is available for PDF generation.")

        return cls._generate_with_reportlab(
            artefacts=artefacts,
            summary=summary,
            recommendations=recommendations,
            target_name=target_name,
            output_path=output_path,
        )

    @classmethod
    def _generate_with_reportlab(
        cls,
        artefacts: List[Artefact],
        summary: RiskSummary,
        recommendations: List[Recommendation],
        target_name: str,
        output_path: Optional[str | Path] = None,
    ) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e3a8a"),
            alignment=0,
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#6b7280"),
        )
        h2_style = ParagraphStyle(
            "H2Style",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#1e3a8a"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodySmall",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
        )
        bold_cell = ParagraphStyle(
            "BoldCell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
        )

        story = []

        # Header
        story.append(Paragraph("ECDAT Quantum Cryptographic Risk Report", title_style))
        story.append(Paragraph(f"Target: <b>{target_name}</b> | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e3a8a"), spaceAfter=15))

        # KPI Executive Summary
        kpi_data = [
            [
                Paragraph("<b>Total Assets</b>", subtitle_style),
                Paragraph("<b>At Risk (Mosca)</b>", subtitle_style),
                Paragraph("<b>Quantum Vulnerable</b>", subtitle_style),
                Paragraph("<b>Critical / High</b>", subtitle_style),
            ],
            [
                Paragraph(f"<font size=16 color='#1e3a8a'><b>{summary.total_artefacts}</b></font>", body_style),
                Paragraph(f"<font size=16 color='#dc2626'><b>{summary.at_risk_count}</b></font>", body_style),
                Paragraph(f"<font size=16 color='#f59e0b'><b>{summary.percent_quantum_vulnerable}%</b></font>", body_style),
                Paragraph(f"<font size=16 color='#dc2626'><b>{summary.counts_by_risk_level['critical'] + summary.counts_by_risk_level['high']}</b></font>", body_style),
            ],
        ]
        kpi_table = Table(kpi_data, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 15))

        # Mosca Inequality Summary Box
        story.append(Paragraph("Quantum Risk Horizon (Mosca's Theorem: X + Y > Z)", h2_style))
        mosca_p = (
            "Under the <i>Harvest Now, Decrypt Later</i> threat, encrypted records with shelf-life <b>X</b> "
            "migrating over <b>Y</b> years are at risk if <b>X + Y &gt; Z</b> (estimated CRQC horizon ~2038)."
        )
        story.append(Paragraph(mosca_p, body_style))
        story.append(Spacer(1, 10))

        # Top 10 Risks Table
        story.append(Paragraph("Top Urgent Cryptographic Risks", h2_style))
        top_data = [["Asset", "Score", "Criticality", "File", "Threat Analysis"]]
        for t in summary.top_riskiest[:8]:
            top_data.append([
                Paragraph(f"<b>{t.artefact_name}</b>", bold_cell),
                Paragraph(f"<b>{t.risk_score}</b>", bold_cell),
                Paragraph(t.criticality.value.upper(), body_style),
                Paragraph(Path(t.metadata.get("file", "")).name, body_style),
                Paragraph(t.explanation[:120] + "..." if len(t.explanation) > 120 else t.explanation, body_style),
            ])

        top_table = Table(top_data, colWidths=[1.2 * inch, 0.7 * inch, 0.9 * inch, 1.4 * inch, 3.2 * inch])
        top_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
        ]))
        story.append(top_table)
        story.append(Spacer(1, 15))

        # Recommendations Table
        story.append(Paragraph("Prioritized Post-Quantum Migration Action Plan", h2_style))
        rec_data = [["Primitive", "PQC Replacement", "Approach", "Effort", "Implementation"]]
        for r in recommendations[:8]:
            rec_data.append([
                Paragraph(f"<b>{r.current_primitive}</b>", bold_cell),
                Paragraph(f"<b>{r.replacement}</b>", bold_cell),
                Paragraph(r.hybrid_vs_pure.value.upper(), body_style),
                Paragraph(r.migration_effort.value.upper(), body_style),
                Paragraph(", ".join(r.library_suggestion[:2]), body_style),
            ])

        rec_table = Table(rec_data, colWidths=[1.4 * inch, 2.5 * inch, 1.0 * inch, 0.8 * inch, 1.7 * inch])
        rec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(rec_table)

        doc.build(story)
        pdf_bytes = buffer.getvalue()

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(pdf_bytes)
            logger.info(f"Generated PDF report at {out}")

        return pdf_bytes
