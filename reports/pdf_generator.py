import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Adds running headers and footers with dynamic page numbers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Header (pages after page 1)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "CyberLens — Security Posture Assessment Report")
            self.drawRightString(letter[0] - 54, letter[1] - 36, "CONFIDENTIAL")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 45, letter[0] - 54, 45)
        self.drawString(54, 32, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | CyberLens Auditor")
        self.drawRightString(letter[0] - 54, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class PDFReportGenerator:
    """Generates publication-quality executive and technical security audit PDF reports."""

    NAVY = colors.HexColor("#0B192C")
    DARK_BLUE = colors.HexColor("#1E3E62")
    ACCENT_BLUE = colors.HexColor("#0284C7")
    TEXT_MAIN = colors.HexColor("#0F172A")
    TEXT_MUTED = colors.HexColor("#64748B")
    BG_LIGHT = colors.HexColor("#F8FAFC")
    BORDER_LIGHT = colors.HexColor("#E2E8F0")

    COLOR_PASS = colors.HexColor("#16A34A")
    COLOR_WARN = colors.HexColor("#D97706")
    COLOR_FAIL = colors.HexColor("#DC2626")
    COLOR_INFO = colors.HexColor("#2563EB")

    @classmethod
    def generate_report(cls, scan) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=cls.NAVY
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=cls.TEXT_MUTED
        )
        h1_style = ParagraphStyle(
            'Heading1_Custom',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=cls.NAVY,
            spaceBefore=14,
            spaceAfter=6
        )
        h2_style = ParagraphStyle(
            'Heading2_Custom',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=cls.DARK_BLUE,
            spaceBefore=8,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'Body_Custom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=cls.TEXT_MAIN
        )
        body_muted = ParagraphStyle(
            'Body_Muted',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=cls.TEXT_MUTED
        )
        code_style = ParagraphStyle(
            'Code_Custom',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#1E293B")
        )

        elements = []

        # Header Banner Table
        header_table_data = [
            [
                Paragraph("<b>CYBERLENS</b><br/><font size=8 color='#64748B'>Web Security Posture Assessment</font>", title_style),
                Paragraph(f"<b>STATUS:</b> {scan.get_status_display().upper()}<br/><b>DATE:</b> {scan.created_at.strftime('%Y-%m-%d %H:%M')}<br/><b>SCAN ID:</b> {str(scan.scan_uuid)[:8]}", body_style)
            ]
        ]
        header_table = Table(header_table_data, colWidths=[330, 174])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=cls.ACCENT_BLUE, spaceBefore=4, spaceAfter=14))

        # Executive Summary Box
        grade_colors = {
            'A+': colors.HexColor('#16A34A'),
            'A': colors.HexColor('#16A34A'),
            'B': colors.HexColor('#0284C7'),
            'C': colors.HexColor('#D97706'),
            'D': colors.HexColor('#EA580C'),
            'F': colors.HexColor('#DC2626'),
        }
        badge_col = grade_colors.get(scan.grade, colors.HexColor('#DC2626'))

        findings_count = scan.get_findings_count_by_severity()

        summary_table_data = [
            [
                Paragraph(f"<font size=10 color='#64748B'>TARGET HOST</font><br/><b><font size=13 color='#0B192C'>{scan.target_hostname}</font></b><br/><font size=8 color='#64748B'>{scan.target_url}</font><br/><font size=8 color='#64748B'>IP Address: {scan.ip_address or 'N/A'}</font>", body_style),
                Paragraph(f"<div align='center'><font size=9 color='#64748B'>OVERALL SCORE</font><br/><b><font size=28 color='{badge_col.hexval()}'>{scan.overall_score}/100</font></b><br/><b><font size=12 color='{badge_col.hexval()}'>GRADE {scan.grade}</font></b><br/><font size=8 color='#64748B'>Risk: {scan.risk_level}</font></div>", body_style),
                Paragraph(f"<font size=9 color='#64748B'>FINDINGS OVERVIEW</font><br/>"
                          f"<font color='#DC2626'><b>Critical:</b> {findings_count['critical']}</font><br/>"
                          f"<font color='#EA580C'><b>High:</b> {findings_count['high']}</font><br/>"
                          f"<font color='#D97706'><b>Medium:</b> {findings_count['medium']}</font><br/>"
                          f"<font color='#0284C7'><b>Low/Info:</b> {findings_count['low'] + findings_count['info']}</font><br/>"
                          f"<font color='#16A34A'><b>Passed:</b> {findings_count['pass']}</font>", body_style)
            ]
        ]
        summary_table = Table(summary_table_data, colWidths=[200, 140, 164])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), cls.BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, cls.BORDER_LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        # Category Breakdown Table
        elements.append(Paragraph("Category Security Breakdown", h1_style))
        cat_scores = scan.category_scores or {}
        cat_data = [
            [
                Paragraph("<b>Security Domain</b>", body_style),
                Paragraph("<b>Weight</b>", body_style),
                Paragraph("<b>Score</b>", body_style),
                Paragraph("<b>Status Rating</b>", body_style)
            ],
            [
                Paragraph("TLS / SSL Cryptography", body_style),
                Paragraph("25%", body_style),
                Paragraph(f"<b>{cat_scores.get('ssl', 0)}/100</b>", body_style),
                Paragraph(cls._get_status_text(cat_scores.get('ssl', 0)), body_style),
            ],
            [
                Paragraph("HTTP Security Headers", body_style),
                Paragraph("35%", body_style),
                Paragraph(f"<b>{cat_scores.get('headers', 0)}/100</b>", body_style),
                Paragraph(cls._get_status_text(cat_scores.get('headers', 0)), body_style),
            ],
            [
                Paragraph("Cookie Protection", body_style),
                Paragraph("15%", body_style),
                Paragraph(f"<b>{cat_scores.get('cookies', 0)}/100</b>", body_style),
                Paragraph(cls._get_status_text(cat_scores.get('cookies', 0)), body_style),
            ],
            [
                Paragraph("DNS & Email Security (SPF/DMARC/CAA)", body_style),
                Paragraph("15%", body_style),
                Paragraph(f"<b>{cat_scores.get('dns', 0)}/100</b>", body_style),
                Paragraph(cls._get_status_text(cat_scores.get('dns', 0)), body_style),
            ],
            [
                Paragraph("Infrastructure & Redirection", body_style),
                Paragraph("10%", body_style),
                Paragraph(f"<b>{cat_scores.get('infrastructure', 0)}/100</b>", body_style),
                Paragraph(cls._get_status_text(cat_scores.get('infrastructure', 0)), body_style),
            ],
        ]
        cat_table = Table(cat_data, colWidths=[204, 70, 90, 140])
        cat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0B192C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, cls.BORDER_LIGHT),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, cls.BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(cat_table)
        elements.append(Spacer(1, 14))

        # Detailed Findings Section
        elements.append(Paragraph("Explainable Findings & Actionable Remediation", h1_style))
        elements.append(Paragraph("Findings are cataloged below according to observed technical evidence, potential risk exposure, and prioritized remediation guidance.", body_muted))
        elements.append(Spacer(1, 8))

        findings = scan.findings.all()
        for idx, finding in enumerate(findings, 1):
            sev_color = {
                'critical': '#DC2626',
                'high': '#EA580C',
                'medium': '#D97706',
                'low': '#0284C7',
                'info': '#2563EB',
                'pass': '#16A34A',
            }.get(finding.severity.lower(), '#64748B')

            finding_box_data = [
                [
                    Paragraph(f"<b>#{idx}. {finding.title}</b>", h2_style),
                    Paragraph(f"<font color='{sev_color}'><b>[{finding.get_severity_display().upper()}]</b></font> <font color='#64748B'>Impact: {finding.score_impact} pts</font>", body_style)
                ],
                [
                    Paragraph(
                        f"<b>Category:</b> {finding.get_category_display()}&nbsp;&nbsp;|&nbsp;&nbsp;"
                        f"<b>OWASP:</b> {finding.owasp_category or 'N/A'}&nbsp;&nbsp;|&nbsp;&nbsp;"
                        f"<b>CWE:</b> {finding.cwe_id or 'N/A'}<br/>"
                        f"<b>What was detected:</b> {finding.description}<br/>"
                        f"<b>Why it matters:</b> {finding.impact}<br/>"
                        f"<b>Remediation:</b> {finding.remediation}",
                        body_style
                    ),
                    ""
                ]
            ]

            if finding.remediation_code:
                # Add snippet row
                code_snippet_clean = finding.remediation_code.replace('<', '&lt;').replace('>', '&gt;')
                finding_box_data.append([
                    Paragraph(f"<b>Config Snippet:</b><br/><font face='Courier' size=7 color='#1E293B'>{code_snippet_clean}</font>", code_style),
                    ""
                ])

            finding_table = Table(finding_box_data, colWidths=[380, 124])
            finding_table.setStyle(TableStyle([
                ('SPAN', (0, 1), (1, 1)),
                ('SPAN', (0, 2), (1, 2)) if finding.remediation_code else ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (-1, -1), cls.BG_LIGHT if finding.status != 'fail' else colors.HexColor('#FEF2F2')),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor(sev_color) if finding.status == 'fail' else cls.BORDER_LIGHT),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ]))

            elements.append(KeepTogether([finding_table, Spacer(1, 6)]))

        # Disclaimer Section
        elements.append(Spacer(1, 12))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=cls.BORDER_LIGHT, spaceBefore=6, spaceAfter=8))
        disclaimer_text = (
            "<b>Assessment Disclaimer:</b> This assessment report was generated automatically by CyberLens utilizing strictly passive "
            "non-intrusive inspection methods (HTTP headers, SSL/TLS handshake metadata, DNS queries). No active exploitation, intrusive "
            "penetration testing, or denial-of-service tests were executed. The security scores and grades reflect observable public configurations "
            "and do not certify the absence of underlying software vulnerabilities or business logic flaws."
        )
        elements.append(Paragraph(disclaimer_text, body_muted))

        # Build Document
        doc.build(elements, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @staticmethod
    def _get_status_text(score: int) -> str:
        if score >= 85:
            return "<font color='#16A34A'><b>Optimal / Strong</b></font>"
        elif score >= 65:
            return "<font color='#0284C7'><b>Good / Moderate</b></font>"
        elif score >= 40:
            return "<font color='#D97706'><b>Needs Attention</b></font>"
        else:
            return "<font color='#DC2626'><b>High Risk / Failing</b></font>"
