# cyberrisk_platform/modules/pdf_generator.py
from fpdf import FPDF
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv # Import load_dotenv
load_dotenv() # Load environment variables from .env


class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(255, 255, 255) # White text for header
        self.set_fill_color(30, 58, 93) # Dark blue background
        self.cell(0, 10, 'CyberScan Pro - Security Scan Report', 0, 1, 'C', 1)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(100, 100, 100) # Grey text for footer
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')
        self.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 0, 'R')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(230, 230, 230) # Light grey background
        self.set_text_color(0, 0, 0) # Black text
        self.cell(0, 8, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.set_text_color(0, 0, 0)
        self.multi_cell(0, 5, body)
        self.ln(4)

    def add_kpis(self, summary):
        self.chapter_title('Executive Summary')
        self.set_font('Arial', '', 10)
        self.set_text_color(0, 0, 0)

        data = [
            ("Security Posture", summary['posture']),
            ("Total Hosts Scanned", str(summary['total_hosts'])),
            ("Total Open Ports", str(summary['total_ports'])),
            ("Critical Hosts", str(summary['crit_hosts'])),
            ("High Risk Hosts", str(summary['high_hosts'])),
            ("VirusTotal Flagged IPs", str(summary['vt_flagged']))
        ]
        
        col_width = self.w / 2 - 20 # Adjust column width

        for label, value in data:
            self.set_font('Arial', 'B', 10)
            self.cell(col_width, 7, f"{label}:", 0, 0, 'L')
            self.set_font('Arial', '', 10)
            self.cell(col_width, 7, value, 0, 1, 'L')
        self.ln(5)

    def add_findings(self, findings):
        self.chapter_title('Key Findings')
        self.set_font('Arial', '', 10)
        for finding in findings:
            self.cell(5) # Indent
            self.multi_cell(0, 6, f"- {finding}")
        self.ln(5)

    def add_dataframe(self, title, df, col_widths, col_aligns=None, header_fill_color=(192, 192, 192), row_height=7, font_size=8):
        # Handle empty DataFrame gracefully
        if df.empty:
            self.chapter_title(title)
            self.set_font('Arial', '', font_size)
            self.cell(0, row_height, "No data available.", 0, 1, 'L')
            self.ln(4)
            return

        self.chapter_title(title)
        self.set_font('Arial', 'B', font_size)
        self.set_fill_color(*header_fill_color)
        self.set_text_color(0, 0, 0)

        # Print header
        for i, header in enumerate(df.columns):
            self.cell(col_widths[i], row_height, header, 1, 0, col_aligns[i] if col_aligns else 'C', 1)
        self.ln()

        self.set_font('Arial', '', font_size)
        
        fill = False
        for index, row in df.iterrows():
            if self.get_y() + row_height > self.page_break_trigger:
                self.add_page()
                self.set_font('Arial', 'B', font_size)
                self.set_fill_color(*header_fill_color)
                for i, header in enumerate(df.columns):
                    self.cell(col_widths[i], row_height, header, 1, 0, col_aligns[i] if col_aligns else 'C', 1)
                self.ln()
                self.set_font('Arial', '', font_size)
            
            self.set_fill_color(240, 240, 240) if fill else self.set_fill_color(255, 255, 255)
            
            for i, col_name in enumerate(df.columns):
                cell_value = str(row[col_name])
                self.cell(col_widths[i], row_height, cell_value, 1, 0, col_aligns[i] if col_aligns else 'L', fill)
            self.ln()
            fill = not fill


def generate_pdf_report(df: pd.DataFrame, summary: dict, host_summary_df: pd.DataFrame, scan_time: str) -> bytes:
    """
    Generates a PDF report from the scan results.
    Returns the PDF as bytes.
    """
    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Title and Scan Time
    pdf.set_font('Arial', 'B', 18)
    pdf.cell(0, 10, 'CyberScan Pro Report', 0, 1, 'C')
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 8, f'Scan Time: {scan_time}', 0, 1, 'C')
    pdf.ln(10)

    # Executive Summary (KPIs)
    pdf.add_kpis(summary)
    pdf.ln(5)

    # Key Findings
    pdf.add_findings(summary['findings'])
    pdf.ln(5)

    # High Risk Entries
    high_risk_df = df[df['severity'].isin(['High', 'Critical'])].copy()
    if not high_risk_df.empty:
        # Select relevant columns for PDF, shorten recommendation
        high_risk_df = high_risk_df[['ip', 'port', 'service', 'severity', 'risk_score', 'recommendation']]
        high_risk_df['recommendation'] = high_risk_df['recommendation'].apply(lambda x: (x[:70] + '...') if len(x) > 70 else x)
        
        col_widths = [25, 15, 25, 20, 15, 90] # Total 190mm
        col_aligns = ['L', 'C', 'L', 'C', 'C', 'L']
        pdf.add_dataframe('High Risk Entries', high_risk_df.head(10), col_widths, col_aligns, header_fill_color=(220, 50, 50), font_size=8) # Top 10 high risks
        pdf.ln(5)
    else:
        pdf.chapter_title('High Risk Entries')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 7, "No high or critical risk entries found in this scan.", 0, 1, 'L')
        pdf.ln(5)


    # Host Summary
    if not host_summary_df.empty:
        host_summary_for_pdf = host_summary_df[['ip', 'open_ports', 'max_risk', 'overall_severity', 'services']].copy()
        host_summary_for_pdf['services'] = host_summary_for_pdf['services'].apply(lambda x: (x[:80] + '...') if len(x) > 80 else x)
        
        col_widths = [30, 20, 20, 30, 90] # Total 190mm
        col_aligns = ['L', 'C', 'C', 'C', 'L']
        pdf.add_dataframe('Host Summary', host_summary_for_pdf, col_widths, col_aligns, header_fill_color=(100, 100, 100), font_size=8)
        pdf.ln(5)
    else:
        pdf.chapter_title('Host Summary')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 7, "No host summary data available.", 0, 1, 'L')
        pdf.ln(5)

    # Full Scan Results (optional, can be very long)
    # For brevity in PDF, only show top N or filtered data.
    if len(df) > 0:
        pdf.add_page()
        df_for_pdf = df[['ip', 'port', 'service', 'product', 'severity', 'risk_score']].copy()
        col_widths = [30, 15, 30, 40, 20, 15] # Total 150mm
        col_aligns = ['L', 'C', 'L', 'L', 'C', 'C']
        pdf.add_dataframe('Full Scan Results (Selected Columns)', df_for_pdf.head(20), col_widths, col_aligns, header_fill_color=(50, 120, 180), font_size=8)
        
        if len(df) > 20:
            pdf.ln(2)
            pdf.set_font('Arial', 'I', 8)
            pdf.multi_cell(0, 5, f'Note: Only the first 20 entries are shown in this summary table. For complete data, please refer to the CSV export.')
    else:
        pdf.chapter_title('Full Scan Results')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 7, "No full scan results to display.", 0, 1, 'L')
        pdf.ln(5)


    return pdf.output(dest='S').encode('latin1') # 'S' returns as bytes