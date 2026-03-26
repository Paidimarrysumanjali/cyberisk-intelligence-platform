# cyberrisk_platform/modules/emailer.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd
from dotenv import load_dotenv # Import load_dotenv
load_dotenv() # Load environment variables from .env


def send_alert_email(
    sender: str, password: str, recipient: str,
    df: pd.DataFrame, scan_time: str, summary: dict
) -> bool:
    """
    Send a styled HTML email report (alert or all-clear) based on scan findings.

    Args:
        sender:     Gmail address sending the report.
        password:   Gmail App Password (16 chars, no spaces).
        recipient:  Address to send the report to.
        df:         Full scan DataFrame.
        scan_time:  Timestamp string for the email subject.
        summary:    The summary dict from analyser.generate_summary.

    Returns: True on success, False on any error.
    """
    # Filter for High and Critical risks only for the table content
    high_risk_df = df[df['severity'].isin(['High', 'Critical'])].copy()
    count   = len(high_risk_df)
    
    # Helper for severity colors in HTML table
    def sev_col(s):
        if s == 'Critical': return '#dc2626'
        if s == 'High':     return '#ea580c'
        if s == 'Medium':   return '#ca8a04'
        return '#6b7280' # Default for Low or Unknown

    # Build table rows for high_risk_df
    rows_html = ''
    if not high_risk_df.empty:
        high_risk_df = high_risk_df.sort_values('risk_score', ascending=False)
        for idx, (_, row) in enumerate(high_risk_df.iterrows()):
            bg  = '#f9fafb' if idx % 2 == 0 else '#ffffff'
            rec = str(row.get('recommendation', ''))
            rec_display = (rec[:75] + '...') if len(rec) > 80 else rec
            
            rows_html += (
                f'<tr style="background:{bg};">'
                f'<td style="padding:10px;border-bottom:1px solid #e5e7eb;'
                f'font-family:monospace;color:#1e40af;">{row.get("ip","")}</td>'
                f'<td style="padding:10px;border-bottom:1px solid #e5e7eb;">'
                f'{row.get("port","")}</td>'
                f'<td style="padding:10px;border-bottom:1px solid #e5e7eb;">'
                f'{row.get("service","")}</td>'
                f'<td style="padding:10px;border-bottom:1px solid #e5e7eb;'
                f'color:{sev_col(row.get("severity",""))};font-weight:bold;">'
                f'{row.get("severity","")}</td>'
                f'<td style="padding:10px;border-bottom:1px solid #e5e7eb;'
                f'text-align:center;font-weight:bold;">{row.get("risk_score","")}</td>'
                f'<td style="padding:10px;border-bottom:1px solid #e5e7eb;'
                f'font-size:12px;color:#374151;">{rec_display}</td>'
                f'</tr>'
            )

    # Determine email subject and primary message based on overall posture
    if summary['posture'].startswith('CRITICAL'):
        subject_prefix = f'🚨 CRITICAL ALERT — {count} Critical/High Findings'
        primary_message = f'<p style="margin:0;color:#991b1b;font-weight:bold;">🚨 {summary["posture"]}. Immediate action required!</p>'
        banner_border_color = '#dc2626'
    elif summary['posture'].startswith('HIGH RISK'):
        subject_prefix = f'⚠️ HIGH RISK — {count} Critical/High Findings'
        primary_message = f'<p style="margin:0;color:#991b1b;font-weight:bold;">⚠️ {summary["posture"]}. Action required within 24 hours.</p>'
        banner_border_color = '#ea580c'
    elif summary['posture'].startswith('MODERATE'):
        subject_prefix = f'🟠 MODERATE RISK — {count} Critical/High Findings' if count > 0 else '🟠 MODERATE RISK — Review Findings'
        primary_message = f'<p style="margin:0;color:#ca8a04;font-weight:bold;">{summary["posture"]}. Review findings for potential improvements.</p>'
        banner_border_color = '#ca8a04'
    else: # LOW
        subject_prefix = '✅ ALL CLEAR — No Significant Findings'
        primary_message = f'<p style="margin:0;color:#16a34a;font-weight:bold;">✅ {summary["posture"]}. Your system appears secure!</p>'
        banner_border_color = '#16a34a'


    table_section = ""
    if count > 0:
        table_section = f"""
        <tr><td style="padding:24px 32px;">
        <p style="margin-bottom:15px; font-size:14px; color:#333;">
        The following critical/high-risk findings require attention:</p>
        <table width="100%" style="border:1px solid #e5e7eb; border-radius:6px;overflow:hidden;border-collapse:collapse;">
        <tr style="background:#1e3a5f;">
        <th style="padding:10px;color:#fff;text-align:left;font-size:12px;">IP</th>
        <th style="padding:10px;color:#fff;text-align:left;font-size:12px;">PORT</th>
        <th style="padding:10px;color:#fff;text-align:left;font-size:12px;">SERVICE</th>
        <th style="padding:10px;color:#fff;text-align:left;font-size:12px;">SEVERITY</th>
        <th style="padding:10px;color:#fff;text-align:center;font-size:12px;">SCORE</th>
        <th style="padding:10px;color:#fff;text-align:left;font-size:12px;">ACTION</th>
        </tr>{rows_html}
        </table></td></tr>
        """
    else:
        table_section = f"""
        <tr><td style="padding:24px 32px;">
        <p style="margin-bottom:15px; font-size:14px; color:#333;">
        No critical or high-risk vulnerabilities were detected in this scan. Regular monitoring is recommended.</p>
        </td></tr>
        """
    
    # --- FINAL FIX HERE: Define HTML snippets as variables to avoid f-string backslash issue ---
    red_span_html    = '<span style="color:#dc2626;">🔴</span>'
    orange_span_html = '<span style="color:#ea580c;">🟠</span>'
    yellow_span_html = '<span style="color:#ca8a04;">🟡</span>'
    green_span_html  = '<span style="color:#16a34a;">✅</span>'

    findings_html = "<ul>" + "".join([
        f"<li>{f.replace('🔴', red_span_html).replace('🟠', orange_span_html).replace('🟡', yellow_span_html).replace('✅', green_span_html)}</li>"
        for f in summary['findings']
    ]) + "</ul>"
    # --- END FINAL FIX ---


    # Full HTML body
    html = f"""<!DOCTYPE html><html><body style="margin:0;padding:0;
background:#f3f4f6;font-family:Arial,sans-serif;">
<table width="100%"><tr><td align="center" style="padding:30px 20px;">
<table width="680" style="background:#fff;border-radius:8px;
box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden;">
<tr><td style="background:linear-gradient(135deg,#1e3a5f,{banner_border_color});
padding:28px 32px;text-align:center;">
<h1 style="margin:0;color:#fff;font-size:22px;">🛡️ CyberScan Pro</h1>
<p style="margin:4px 0 0;color:#fca5a5;font-size:13px;text-transform:uppercase;
letter-spacing:2px;">Security Report & Alert</p>
</td></tr>
<tr><td style="background:#fef2f2;border-left:4px solid {banner_border_color};
padding:16px 32px;">
{primary_message}
<p style="margin:4px 0 0;color:#7f1d1d;font-size:13px;">
Scan time: <strong>{scan_time}</strong></p>
<p style="margin:4px 0 0;color:#7f1d1d;font-size:13px;">
Hosts Scanned: <strong>{summary["total_hosts"]}</strong> | Open Ports: <strong>{summary["total_ports"]}</strong>
</p>
</td></tr>
<tr><td style="padding:24px 32px;">
<h3 style="margin-top:0;">📋 Key Findings</h3>
{findings_html}
</td></tr>
{table_section}
<tr><td style="background:#f9fafb;padding:16px 32px;
border-top:1px solid #e5e7eb;text-align:center;">
<p style="margin:0;font-size:12px;color:#9ca3af;">
Generated by CyberScan Pro</p></td></tr>
</table></td></tr></table></body></html>"""

    # Plain text fallback
    plain = f'{subject_prefix} | {scan_time}\n'
    plain += f'\nSecurity Posture: {summary["posture"]}\n'
    plain += f'Total Hosts: {summary["total_hosts"]}, Total Ports: {summary["total_ports"]}\n'
    plain += f'Critical Hosts: {summary["crit_hosts"]}, High Risk Hosts: {summary["high_hosts"]}\n'
    plain += f'\nKey Findings:\n'
    for finding in summary['findings']:
        plain += f'  - {finding}\n'

    if count > 0:
        plain += '\nCritical/High Risk Entries:\n'
        for _, row in high_risk_df.iterrows():
            plain += f'  - IP: {row.get("ip")}, Port: {row.get("port")}, Service: {row.get("service")}, Severity: {row.get("severity")}, Risk Score: {row.get("risk_score")}\n'
            plain += f'    Recommendation: {str(row.get("recommendation", ""))[:150]}...\n\n'
    else:
        plain += '\nNo critical or high-risk entries detected in this scan.\n'
        
    plain += '\nGenerated by CyberScan Pro.\n'

    msg = MIMEMultipart('alternative')
    msg['From']    = sender
    msg['To']      = recipient
    msg['Subject'] = f'{subject_prefix} | {scan_time}'
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))

    try:
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls() # Secure the connection
        s.login(sender, password) # Login to Gmail
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False