from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from datetime import datetime
import os
from pathlib import Path


class PDFReportGenerator:
    def __init__(
        self,
        report_data: dict,
        output_directory: str,
        client_name: str,
        output_name: str = "report",
    ):
        self.report_data = report_data
        self.output_directory = output_directory
        self.client_name = client_name
        self.output_name = output_name
        self.styles = getSampleStyleSheet()
        self.timestamp = self._resolve_timestamp()

    def _resolve_timestamp(self) -> str:
        timestamp = self.report_data.get("timestamp") or self.report_data.get(
            "generated_at"
        )
        if timestamp:
            try:
                clean = timestamp.replace("Z", "")
                return datetime.fromisoformat(clean).strftime("%B %d, %Y")
            except ValueError:
                pass
        return datetime.now().strftime("%B %d, %Y")

    def generate(self):
        output_root = Path(self.output_directory).resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        pdf_path = output_root / f"{self.output_name}.pdf"

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        elements = []

        stats = self.report_data.get("statistics", {})
        severity_stats = stats.get("findings_by_severity", {})
        risk = stats.get("risk", {})
        raw_risk = risk.get("raw_score", 0)
        adjusted_risk = risk.get("adjusted_score", risk.get("normalized_score", 0))
        normalized_risk = risk.get("normalized_score", adjusted_risk)

        # COVER
        elements.append(Paragraph("BitProbe Security Assessment Report", self.styles["Title"]))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"<b>Client:</b> {self.client_name}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Target:</b> {self.report_data.get('target')}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Date:</b> {self.timestamp}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Scan ID:</b> {self.report_data.get('scan_id')}", self.styles["Normal"]))

        elements.append(PageBreak())

        # EXEC SUMMARY
        elements.append(Paragraph("Executive Summary", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.2 * inch))

        summary_text = (
            "This report presents the results of an automated security assessment performed using BitProbe. "
            "The objective of this assessment was to identify vulnerabilities, misconfigurations, and known "
            "security risks that could impact the target system."
        )
        elements.append(Paragraph(summary_text, self.styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Overall Risk Posture", self.styles["Heading2"]))
        elements.append(Spacer(1, 0.1 * inch))

        elements.append(
            Paragraph(
                f"Overall Risk Level: <b>{risk.get('level', 'unknown').upper()}</b>",
                self.styles["Normal"],
            )
        )
        elements.append(
            Paragraph(
                f"Risk Score (Post-Edge): {normalized_risk} / 100 "
                f"(pre-edge: {raw_risk})",
                self.styles["Normal"],
            )
        )
        elements.append(
            Paragraph(
                f"Edge-Adjusted Total (uncapped): {adjusted_risk}",
                self.styles["Normal"],
            )
        )
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Risk Overview by Severity", self.styles["Heading2"]))
        for sev, count in severity_stats.items():
            if count > 0:
                elements.append(
                    Paragraph(f"{sev.upper()}: {count}", self.styles["Normal"])
                )

        elements.append(Spacer(1, 0.2 * inch))
        elements.append(
            Paragraph(
                f"Total Findings: {stats.get('total_findings', 0)}", self.styles["Normal"]
            )
        )
        elements.append(
            Paragraph(
                f"URLs Scanned: {stats.get('urls_scanned')}", self.styles["Normal"]
            )
        )
        elements.append(
            Paragraph(
                f"Scan Duration: {stats.get('duration_seconds')} seconds",
                self.styles["Normal"],
            )
        )

        elements.append(PageBreak())

        # DETAILED FINDINGS
        elements.append(Paragraph("Detailed Findings", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.2 * inch))

        findings = self.report_data.get("findings", [])

        if not findings:
            elements.append(
                Paragraph(
                    "No security issues were detected during this scan.",
                    self.styles["Normal"],
                )
            )
        else:
            for idx, finding in enumerate(findings, 1):
                elements.append(
                    Paragraph(f"{idx}. {finding['title']}", self.styles["Heading2"])
                )
                elements.append(
                    Paragraph(
                        f"Severity: {finding['severity'].upper()}",
                        self.styles["Normal"],
                    )
                )

                edge_flag = finding.get("edge_infrastructure", False)
                raw_score = finding.get("raw_risk_score", finding.get("risk_score"))
                adjusted_score = finding.get("adjusted_risk_score", raw_score)

                elements.append(
                    Paragraph(
                        f"Edge Infrastructure: {'YES' if edge_flag else 'NO'}",
                        self.styles["Normal"],
                    )
                )

                if raw_score is not None:
                    elements.append(
                        Paragraph(
                            f"Risk Score (pre-edge): {raw_score}",
                            self.styles["Normal"],
                        )
                    )

                if adjusted_score is not None:
                    elements.append(
                        Paragraph(
                            f"Risk Score (post-edge): {adjusted_score}",
                            self.styles["Normal"],
                        )
                    )

                elements.append(
                    Paragraph(f"Affected URL: {finding['url']}", self.styles["Normal"])
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Description", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["description"], self.styles["Normal"])
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Attack Scenario", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("attack_scenario", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Defense Strategy", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("defense_strategy", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Mitigation Plan", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("mitigation_plan", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Remediation", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["remediation"], self.styles["Normal"])
                )
                elements.append(PageBreak())

        doc.build(elements)
        assert pdf_path.exists(), f"Failed to write {pdf_path}"
        return str(pdf_path)
