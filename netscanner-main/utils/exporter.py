import csv
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class Exporter:
    @staticmethod
    def export_csv(filepath: str, data: List[Dict[str, Any]]) -> bool:
        if not data:
            return False
        try:
            keys = list(data[0].keys())
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(data)
            return True
        except Exception as e:
            print(f"CSV Export Error: {e}")
            return False

    @staticmethod
    def export_json(filepath: str, data: List[Dict[str, Any]]) -> bool:
        try:
            payload = {
                "exported_at": datetime.now().isoformat(),
                "device_count": len(data),
                "devices": data
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4)
            return True
        except Exception as e:
            print(f"JSON Export Error: {e}")
            return False

    @staticmethod
    def export_excel(filepath: str, data: List[Dict[str, Any]]) -> bool:
        if not OPENPYXL_AVAILABLE or not data:
            return False
        try:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Discovered Devices"

            # Header styling
            headers = list(data[0].keys())
            header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
            header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")

            ws.append([h.upper().replace("_", " ") for h in headers])
            for col in range(1, len(headers) + 1):
                cell = ws.cell(row=1, column=col)
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(horizontal="center", vertical="center")

            # Data rows
            thin_border = Border(
                left=Side(style='thin', color='CBD5E1'),
                right=Side(style='thin', color='CBD5E1'),
                top=Side(style='thin', color='CBD5E1'),
                bottom=Side(style='thin', color='CBD5E1')
            )

            for row_idx, item in enumerate(data, start=2):
                row_vals = [str(item.get(h, "")) for h in headers]
                ws.append(row_vals)
                for col_idx in range(1, len(headers) + 1):
                    c = ws.cell(row=row_idx, column=col_idx)
                    c.border = thin_border
                    if headers[col_idx-1] == "status":
                        if item.get("status") == "Online":
                            c.fill = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid")
                            c.font = Font(color="166534", bold=True)
                        else:
                            c.fill = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
                            c.font = Font(color="991B1B")

            # Auto-fit columns
            for col in ws.columns:
                max_len = max(len(str(cell.value or '')) for cell in col)
                col_letter = openpyxl.utils.get_column_letter(col[0].column)
                ws.column_dimensions[col_letter].width = max(max_len + 4, 12)

            wb.save(filepath)
            return True
        except Exception as e:
            print(f"Excel Export Error: {e}")
            return False

    @staticmethod
    def export_pdf(filepath: str, data: List[Dict[str, Any]], title="NetScope Pro - Device Discovery Report") -> bool:
        if not REPORTLAB_AVAILABLE or not data:
            return False
        try:
            doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            elements = []

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=20,
                textColor=colors.HexColor('#1E293B'),
                spaceAfter=6
            )
            subtitle_style = ParagraphStyle(
                'ReportSubtitle',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#64748B'),
                spaceAfter=15
            )

            elements.append(Paragraph(title, title_style))
            elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Devices: {len(data)}", subtitle_style))

            table_data = [["IP Address", "MAC Address", "Hostname", "Vendor", "Type", "Status", "Latency"]]
            for item in data:
                table_data.append([
                    str(item.get("ip", "")),
                    str(item.get("mac", "")),
                    str(item.get("hostname", ""))[:20],
                    str(item.get("vendor", ""))[:18],
                    str(item.get("device_type", "")),
                    str(item.get("status", "")),
                    f"{item.get('latency', 0):.1f} ms"
                ])

            t = Table(table_data, colWidths=[90, 110, 95, 95, 70, 50, 50])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (5, 1), (6, -1), 'CENTER'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F8FAFC'), colors.white]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))

            elements.append(t)
            doc.build(elements)
            return True
        except Exception as e:
            print(f"PDF Export Error: {e}")
            return False
