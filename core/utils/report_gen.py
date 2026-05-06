import os
from datetime import datetime
from typing import Dict, List, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch

class ReportGenerator:
    """ Generates forensic PDF reports for Watchtower. """

    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()

    def _add_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='TitleStyle',
            fontSize=24,
            leading=30,
            alignment=1,
            spaceAfter=20,
            textColor=colors.HexColor("#1a237e")
        ))
        self.styles.add(ParagraphStyle(
            name='HeaderStyle',
            fontSize=16,
            leading=20,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.HexColor("#0d47a1"),
            borderPadding=5
        ))

    def generate_summary_report(self, stats: Dict[str, Any], filename: str = None) -> str:
        """Generates a PDF summary report from today's stats."""
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph("Watchtower Forensic Summary", self.styles['TitleStyle']))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        # Overview Table
        story.append(Paragraph("Executive Overview", self.styles['HeaderStyle']))
        data = [
            ["Metric", "Value"],
            ["Total Packets", f"{stats.get('total_packets', 0):,}"],
            ["Total Bytes", f"{stats.get('total_bytes', 0) / (1024*1024):.2f} MB"],
            ["Total Flows", f"{stats.get('total_flows', 0):,}"],
            ["Active Entities", f"{len(stats.get('flow_records', []))}"], # Approximate
            ["Alerts Triggered", f"{len(stats.get('recent_alerts', []))}"]
        ]
        t = Table(data, colWidths=[2*inch, 3*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor("#1a237e")),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * inch))

        # Recent Alerts
        story.append(Paragraph("High Priority Alerts", self.styles['HeaderStyle']))
        alerts = stats.get('recent_alerts', [])
        if alerts:
            alert_data = [["Timestamp", "Type", "Source IP", "Severity"]]
            for a in alerts[:10]: # Top 10
                ts = datetime.fromtimestamp(a['timestamp']).strftime('%H:%M:%S')
                alert_data.append([ts, a['type'], a['entity_ip'], a['severity']])
            
            at = Table(alert_data, colWidths=[1.2*inch, 2.5*inch, 1.5*inch, 1*inch])
            at.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#c62828")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 8)
            ]))
            story.append(at)
        else:
            story.append(Paragraph("No alerts detected in this period.", self.styles['Normal']))

        doc.build(story)
        return filepath

    def generate_forensic_report(self, report, filename: str = None) -> str:
        """Generates a detailed forensic PDF report from a ForensicReport object."""
        if not filename:
            filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph(f"Watchtower Detailed Forensic Report", self.styles['TitleStyle']))
        story.append(Paragraph(f"Source: {report.source}", self.styles['Normal']))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        # Entities Table
        story.append(Paragraph("Identified Entities", self.styles['HeaderStyle']))
        entity_data = [["IP Address", "MAC Address", "Hostname / User", "Risk Score"]]
        
        for ip, entity in sorted(report.entities.items(), key=lambda item: item[1].risk_score, reverse=True):
            if entity.risk_score > 0 or entity.alerts or entity.user or entity.hostname:
                identity = entity.user or entity.hostname or entity.netbios_name or "Unknown"
                entity_data.append([ip, entity.mac or "N/A", identity, f"{entity.risk_score:.1f}"])
        
        if len(entity_data) > 1:
            et = Table(entity_data, colWidths=[1.5*inch, 1.5*inch, 2*inch, 1*inch])
            et.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ]))
            story.append(et)
        else:
            story.append(Paragraph("No significant entities found.", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3 * inch))

        # Alerts Section
        story.append(Paragraph("Forensic Alerts & Sigma Matches", self.styles['HeaderStyle']))
        alerts = []
        for entity in report.entities.values():
            for alert in entity.alerts:
                alerts.append({"ip": entity.ip, "alert": alert})
                
        if alerts:
            alerts.sort(key=lambda x: x["alert"].score, reverse=True)
            alert_data = [["Time", "Entity IP", "Type", "Severity", "Explanation"]]
            for a in alerts:
                alert = a["alert"]
                ts = datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S') if alert.timestamp else "N/A"
                alert_data.append([ts, a['ip'], alert.type, alert.severity, alert.explanation[:50] + "..."])
                
            at = Table(alert_data, colWidths=[0.8*inch, 1.2*inch, 1.5*inch, 0.8*inch, 2.5*inch])
            at.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#c62828")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 8)
            ]))
            story.append(at)
        else:
            story.append(Paragraph("No alerts generated during this analysis.", self.styles['Normal']))

        story.append(Spacer(1, 0.3 * inch))
        
        # Carved Files
        story.append(Paragraph("Carved Files & Evidence", self.styles['HeaderStyle']))
        files = []
        for entity in report.entities.values():
            for f in entity.carved_files:
                files.append({"ip": entity.ip, "file": f})
                
        if files:
            file_data = [["Entity IP", "Filename", "Size (bytes)", "SHA256"]]
            for f in files:
                cfile = f["file"]
                file_data.append([f['ip'], cfile.filename, str(cfile.size), cfile.sha256[:16] + "..."])
                
            ft = Table(file_data, colWidths=[1.2*inch, 2*inch, 1*inch, 2.5*inch])
            ft.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2e7d32")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 8)
            ]))
            story.append(ft)
        else:
            story.append(Paragraph("No files carved from this capture.", self.styles['Normal']))

        doc.build(story)
        return filepath
