# cyberrisk_platform/dashboard/pages/2_Analysis.py
import streamlit as st
import plotly.express as px
import sys, os
import pandas as pd
from dotenv import load_dotenv # Import load_dotenv
load_dotenv() # Load environment variables from .env

# Add the parent directory of 'modules' to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.analyser import build_host_summary, generate_summary
from modules.emailer import send_alert_email # For sending email directly from this page if preferred

# ── Credentials (for email sending) ───────────────────────────────────────────
# These now primarily read from environment variables (loaded by dotenv).
# For local VS Code, these will come from your .env file.
GMAIL_SENDER    = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASSWORD  = os.environ.get('GMAIL_PASSWORD', '')
GMAIL_RECIPIENT = os.environ.get('GMAIL_RECIPIENT', '')

st.title('🔍 Security Analysis')
st.caption('What was found, how bad it is, and what to do about it')

# ── Read scan data from session_state ─────────────────────────────────────────
df = st.session_state.get('df')
scan_time = st.session_state.get('scan_time', 'N/A')

if df is None or df.empty:
    st.info('No scan data loaded yet. Run a scan from the main page or load from scan history.')
    st.stop()  # stop rendering here — nothing below this line runs

host_sum = build_host_summary(df)
summary  = generate_summary(df, host_sum)

# ── SECURITY POSTURE BANNER ───────────────────────────────────────────────────
st.markdown(
    f'<div style="background:{summary["colour"]};padding:20px;'
    f'border-radius:8px;text-align:center;">'
    f'<h2 style="color:white;margin:0;">'
    f'Security Posture: {summary["posture"]}</h2></div>',
    unsafe_allow_html=True
)
st.divider()

# ── KPI CARDS ─────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric('🖥️ Hosts Scanned',  summary['total_hosts'])
c2.metric('🔓 Open Ports',     summary['total_ports'])
c3.metric('🚨 Critical Hosts', summary['crit_hosts'])
c4.metric('⚠️ High Risk Hosts', summary['high_hosts'])
c5.metric('🦠 VT Flagged',     summary['vt_flagged'])
st.divider()

# ── KEY FINDINGS ──────────────────────────────────────────────────────────────
st.subheader('📋 Key Findings')
for finding in summary['findings']:
    st.markdown(f'- {finding}')
st.divider()

# ── IMMEDIATE ACTIONS ─────────────────────────────────────────────────────────
st.subheader('🚀 Immediate Actions')
st.caption('Sorted by risk score — highest priority first. Click to expand for details.')

action_df = (
    df.sort_values('risk_score', ascending=False)
      .drop_duplicates(subset=['ip', 'service', 'recommendation']) # Unique recommendations per IP/Service
      [['ip','port','service','risk_score','severity','recommendation']]
      .head(15) # Show top 15 most critical actions
)

if not action_df.empty:
    for _, row in action_df.iterrows():
        sev_colour = {
            'Critical': '#dc2626', 'High': '#ea580c',
            'Medium':   '#ca8a04', 'Low':  '#16a34a'
        }.get(row['severity'], '#6b7280') # Default grey for unknown
        
        is_expanded = row['severity'] in ['Critical', 'High']

        with st.expander(
            f"[{row['severity']}] **{row['ip']}:{row['port']}** ({row['service']}) — Risk Score: **{row['risk_score']}**",
            expanded=is_expanded
        ):
            st.markdown(
                f'<span style="color:{sev_colour};font-weight:bold;">'
                f'What to do:</span> {row["recommendation"]}',
                unsafe_allow_html=True
            )
else:
    st.info('No specific immediate actions identified for the current filter/scan. All looks good!')

st.divider()

# ── Risk Overview Table ───────────────────────────────────────────────────────
st.subheader('Detailed Risk Overview')
st.caption('All identified ports and services, sortable and filterable.')
st.dataframe(
    df[['ip', 'port', 'protocol', 'service', 'product', 'version', 'severity', 'risk_score',
        'malicious_reports', 'suspicious_count', 'country', 'categories', 'recommendation']]
    .sort_values('risk_score', ascending=False)
    .reset_index(drop=True),
    use_container_width=True,
    column_config={
        "ip": st.column_config.TextColumn("IP", width="small"),
        "port": st.column_config.TextColumn("Port", width="tiny"),
        "protocol": st.column_config.TextColumn("Proto", width="tiny"),
        "service": st.column_config.TextColumn("Service", width="small"),
        "product": st.column_config.TextColumn("Product", width="small"),
        "version": st.column_config.TextColumn("Version", width="small"),
        "severity": st.column_config.TextColumn("Severity", width="small"),
        "risk_score": st.column_config.NumberColumn("Risk Score", format="%.1f", width="small"),
        "malicious_reports": st.column_config.NumberColumn("VT Malicious", width="small"),
        "suspicious_count": st.column_config.NumberColumn("VT Suspicious", width="small"),
        "country": st.column_config.TextColumn("Country", width="small"),
        "categories": st.column_config.TextColumn("VT Categories", width="medium"),
        "recommendation": st.column_config.TextColumn("Recommendation", width="large"),
    }
)
st.divider()

# ── RISK HEATMAP ──────────────────────────────────────────────────────────────
st.subheader('🗺️ Risk Heatmap: Exposure vs Threat')
st.caption('Top-right = worst. Bubble size = overall risk score. Hover for details.')

if 'exposure_score' in df.columns and 'threat_score' in df.columns:
    # Aggregate to one row per IP for the heatmap
    heat_df = df.groupby('ip').agg(
        max_exposure = ('exposure_score', 'max'),
        max_threat   = ('threat_score',   'max'),
        avg_risk     = ('risk_score',     'mean'), # Use average risk for bubble size for a clearer visual
        overall_severity = ('severity', lambda x: x.mode()[0] if not x.empty else 'Low'), # Most common severity
        services     = ('service', lambda x: ', '.join(sorted(set(x)))),
        malicious_reports = ('malicious_reports', 'max') # Max malicious reports for hover
    ).reset_index()
    
    # Ensure numerical columns are floats for plotly
    heat_df['max_exposure'] = heat_df['max_exposure'].astype(float)
    heat_df['max_threat'] = heat_df['max_threat'].astype(float)
    heat_df['avg_risk'] = heat_df['avg_risk'].astype(float)

    fig = px.scatter(
        heat_df,
        x='max_exposure',
        y='max_threat',
        size='avg_risk', # Bubble size based on average risk for that IP
        color='avg_risk', # Color based on average risk
        text='ip',
        hover_data={
            'ip': False, # Hide IP from hover data as it's the text label
            'services': True,
            'malicious_reports': True,
            'max_exposure': True,
            'max_threat': True,
            'avg_risk': True,
            'overall_severity': True,
        },
        color_continuous_scale='RdYlGn_r', # Red-Yellow-Green reversed (red for high risk)
        title='Host Risk: Exposure Score vs Threat Score',
        labels={
            'max_exposure': 'Max Exposure Score (Service Danger)',
            'max_threat':   'Max Threat Score (VirusTotal Findings)',
            'avg_risk':     'Average Risk Score'
        },
        size_max=50 # Max bubble size
    )
    fig.update_traces(
        textposition='top center',
        marker=dict(line=dict(width=1, color='DarkSlateGrey')) # Add border to bubbles
    )
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)', # Transparent background
        font_color='#e2e8f0', # Light font for dark theme
        height=550,
        xaxis_title="Max Exposure Score (How dangerous is the service)",
        yaxis_title="Max Threat Score (VirusTotal findings)",
        xaxis=dict(gridcolor='#2d3148'), # Darker grid lines
        yaxis=dict(gridcolor='#2d3148')
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info('Run a scan with the updated analyser to see the heatmap.')

st.divider()

# ── EMAIL ALERT SECTION ───────────────────────────────────────────────────────
st.subheader("📧 Send Report Email")
email_ready = bool(GMAIL_SENDER and GMAIL_PASSWORD and GMAIL_RECIPIENT)

if not email_ready:
    st.warning("⚠️ Email credentials are incomplete. Please set GMAIL_SENDER, GMAIL_PASSWORD (App Password), and GMAIL_RECIPIENT in your environment variables to enable email reports.")

send_email_button_label = (
    f"Send Report Email ({summary['posture']})"
)

send_btn = st.button(
    send_email_button_label,
    type="primary",
    disabled=not email_ready,
    use_container_width=True
)

if send_btn and email_ready:
    with st.spinner("Sending report email..."):
        # The emailer will handle the logic of alert vs. all-clear based on the summary
        result = send_alert_email(
            GMAIL_SENDER,
            GMAIL_PASSWORD,
            GMAIL_RECIPIENT,
            df, # Pass the full DataFrame
            scan_time,
            summary # Pass the generated summary
        )
    if result is True:
        st.success(f"✅ Report email sent successfully to {GMAIL_RECIPIENT}!")
    else:
        st.error(f"❌ Failed to send email: {result}")
        st.caption("Common fixes: Check your Gmail App Password is correct (16 characters, no spaces), make sure 2-Step Verification is ON for your Gmail account, and confirm recipient email is valid.")