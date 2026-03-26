# cyberrisk_platform/dashboard/content_pages/analysis_content.py
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import sys, os
import pandas as pd
from dotenv import load_dotenv 
load_dotenv()

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from modules.analyser import build_host_summary, generate_summary
from modules.emailer import send_alert_email

# ── Credentials (for email sending) ───────────────────────────────────────────
GMAIL_SENDER    = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASSWORD  = os.environ.get('GMAIL_PASSWORD', '')
GMAIL_RECIPIENT = os.environ.get('GMAIL_RECIPIENT', '')

def render_page():
    st.title('🔍 Security Analysis')
    st.caption('Comprehensive insights into your scanned network\'s security posture.')

    df = st.session_state.get('df')
    scan_time = st.session_state.get('scan_time', 'N/A')

    if df is None or df.empty:
        st.info('No scan data loaded yet. Run a scan from the main page or load from scan history.')
        return

    host_sum = build_host_summary(df)
    summary  = generate_summary(df, host_sum)

    # Chart colors to match dark theme
    CHART_BG = "#1e2130"
    GRID_COL = "#2d3148"
    FONT_COL = "#e2e8f0"


    # ── 1. SECURITY POSTURE BANNER ────────────────────────────────────────────────
    st.markdown(
        f'<div style="background:{summary["colour"]};padding:20px;'
        f'border-radius:8px;text-align:center;">'
        f'<h2 style="color:white;margin:0;">'
        f'Security Posture: {summary["posture"]}</h2></div>',
        unsafe_allow_html=True
    )
    st.divider()

    # ── 2. KPI CARDS ──────────────────────────────────────────────────────────────
    kpi_cols = st.columns(5)
    kpi_cols[0].metric('🖥️ Hosts Scanned',  summary['total_hosts'])
    kpi_cols[1].metric('🔓 Open Ports',     summary['total_ports'])
    kpi_cols[2].metric('🚨 Critical Hosts', summary['crit_hosts'])
    kpi_cols[3].metric('⚠️ High Risk Hosts', summary['high_hosts'])
    kpi_cols[4].metric('🦠 VT Flagged',     summary['vt_flagged'])
    st.divider()

    # ── 3. KEY FINDINGS ───────────────────────────────────────────────────────────
    st.subheader('📋 Key Findings')
    for finding in summary['findings']:
        st.markdown(f'- {finding}')
    st.divider()

    # ── 4. IMMEDIATE ACTIONS (Top N) ──────────────────────────────────────────────
    st.subheader('🚀 Immediate Actions')
    st.caption('Prioritized remediation tasks for critical and high-risk findings.')

    action_df = (
        df.sort_values('risk_score', ascending=False)
          .drop_duplicates(subset=['ip', 'service', 'recommendation'])
          [['ip','port','service','risk_score','severity','recommendation']]
          .head(7) # Show top 7 actions to keep it compact
    )

    if not action_df.empty:
        for _, row in action_df.iterrows():
            sev_colour = {
                'Critical': '#dc2626', 'High': '#ea580c',
                'Medium':   '#ca8a04', 'Low':  '#16a34a'
            }.get(row['severity'], '#6b7280')
            
            with st.expander(
                f"[{row['severity']}] **{row['ip']}:{row['port']}** ({row['service']}) — Risk: **{row['risk_score']}**",
                expanded=(row['severity'] in ['Critical', 'High']) # Expand critical/high by default
            ):
                st.markdown(
                    f'<span style="color:{sev_colour};font-weight:bold;">'
                    f'Action:</span> {row["recommendation"]}',
                    unsafe_allow_html=True
                )
    else:
        st.info('No specific immediate actions identified for this scan. Great job!')
    st.divider()

    # ── 5. EMAIL REPORT SECTION ───────────────────────────────────────────────────
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
        width='stretch'
    )

    if send_btn and email_ready:
        with st.spinner("Sending report email..."):
            result = send_alert_email(GMAIL_SENDER, GMAIL_PASSWORD, GMAIL_RECIPIENT, df, scan_time, summary)
        if result is True:
            st.success(f"✅ Report email sent successfully to {GMAIL_RECIPIENT}!")
        else:
            st.error(f"❌ Failed to send email: {result}")
            st.caption("Common fixes: Check your Gmail App Password is correct (16 characters, no spaces), make sure 2-Step Verification is ON for your Gmail account, and confirm recipient email is valid.")
    st.divider()

    # ── 6. INTERACTIVE CHARTS (More Detailed Bar Graphs) ──────────────────────────
    st.subheader('📈 Detailed Visualizations')
    st.caption('Hover for details • Drag to zoom • Double-click to reset • Click legend to toggle.')

    # Row 1: Open Ports per Host & Total Risk per Host
    chart_cols1 = st.columns(2)
    with chart_cols1[0]:
        st.markdown("##### Open Ports per Host")
        pc = df.groupby("ip")["port"].count().reset_index(name='Open Ports')
        fig_ports_per_host = px.bar(pc, x="ip", y="Open Ports", # CHANGED: x="IP" to x="ip"
                                      color="Open Ports", color_continuous_scale="Blues", text="Open Ports")
        fig_ports_per_host.update_traces(textposition="outside")
        fig_ports_per_host.update_layout(height=300, showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL, xaxis=dict(gridcolor=GRID_COL), yaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig_ports_per_host, width='stretch')

    with chart_cols1[1]:
        st.markdown("##### Total Risk Score per Host")
        rs = df.groupby("ip")["risk_score"].sum().reset_index(name='Total Risk')
        fig_risk_per_host = px.bar(rs, x="ip", y="Total Risk", # CHANGED: x="IP" to x="ip"
                                      color="Total Risk", color_continuous_scale="Reds", text="Total Risk")
        fig_risk_per_host.update_traces(textposition="outside")
        fig_risk_per_host.update_layout(height=300, showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL, xaxis=dict(gridcolor=GRID_COL), yaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig_risk_per_host, width='stretch')

    # Row 2: Services Exposed & Severity Distribution
    chart_cols2 = st.columns(2)
    with chart_cols2[0]:
        st.markdown("##### Top 10 Services Exposed")
        # Only consider 'open' state for services
        service_counts = df[df['state'] == 'open']['service'].value_counts().nlargest(10).reset_index(name='Count')
        service_counts.columns = ['Service', 'Count'] # Rename for clarity
        fig_services_exposed = px.bar(service_counts, x="Count", y="Service", orientation="h",
                                      color="Count", color_continuous_scale="Purples", text="Count")
        fig_services_exposed.update_layout(height=300, showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                           yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL), xaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig_services_exposed, width='stretch')

    with chart_cols2[1]:
        st.markdown("##### Severity Distribution")
        sev = df["severity"].value_counts().reset_index(name='Count')
        sev.columns = ["Severity", "Count"] # Rename for clarity
        fig_severity_dist = px.pie(sev, names="Severity", values="Count",
                               color="Severity", hole=0.5,
                               color_discrete_map={"Low": "#16a34a", "Medium": "#ca8a04", "High": "#ea580c", "Critical": "#dc2626"})
        fig_severity_dist.update_traces(textinfo="percent+label+value", marker=dict(line=dict(color=CHART_BG, width=2)))
        fig_severity_dist.update_layout(height=300, paper_bgcolor=CHART_BG, font_color=FONT_COL, legend=dict(bgcolor=CHART_BG))
        st.plotly_chart(fig_severity_dist, width='stretch')


    # Row 3: Top Risky Products & VirusTotal Categories
    chart_cols3 = st.columns(2)
    with chart_cols3[0]:
        st.markdown("##### Top Risky Products/Versions")
        # Filter for non-empty products and aggregate risk
        risky_products = df[df['product'] != '']
        if not risky_products.empty:
            product_risk = risky_products.groupby(['product', 'version'])['risk_score'].mean().reset_index(name='Avg Risk')
            # Combine product and version for display
            product_risk['Product (Version)'] = product_risk['product'] + (product_risk['version'].apply(lambda x: f' ({x})' if x else ''))
            product_risk = product_risk.sort_values('Avg Risk', ascending=False).head(10)
            
            fig_product_risk = px.bar(product_risk, x="Avg Risk", y="Product (Version)", orientation="h",
                                      color="Avg Risk", color_continuous_scale="Viridis", text="Avg Risk")
            fig_product_risk.update_layout(height=300, showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                           yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL), xaxis=dict(gridcolor=GRID_COL))
            st.plotly_chart(fig_product_risk, width='stretch')
        else:
            st.info("No product/version data to display.")

    with chart_cols3[1]:
        st.markdown("##### VirusTotal Categories Distribution")
        # Split categories and count them
        all_categories = df['categories'].dropna().astype(str).str.split(', ').explode()
        all_categories = all_categories[all_categories != ''].value_counts().nlargest(10).reset_index(name='Count')
        all_categories.columns = ['Category', 'Count']

        if not all_categories.empty:
            fig_vt_cats = px.bar(all_categories, x="Count", y="Category", orientation="h",
                                 color="Count", color_continuous_scale="Plasma", text="Count")
            fig_vt_cats.update_layout(height=300, showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                      yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL), xaxis=dict(gridcolor=GRID_COL))
            st.plotly_chart(fig_vt_cats, width='stretch')
        else:
            st.info("No VirusTotal categories to display.")

    st.divider()

    # ── 7. RISK HEATMAP ───────────────────────────────────────────────────────────
    st.subheader('🗺️ Risk Heatmap: Exposure vs Threat')
    st.caption('Top-right = worst. Bubble size = overall risk score. Hover for details.')

    if 'exposure_score' in df.columns and 'threat_score' in df.columns:
        heat_df = df.groupby('ip').agg(
            max_exposure = ('exposure_score', 'max'),
            max_threat   = ('threat_score',   'max'),
            avg_risk      = ('risk_score',     'mean'),
            overall_severity = ('severity', lambda x: x.mode()[0] if not x.empty else 'Low'),
            services     = ('service', lambda x: ', '.join(sorted(set(x)))),
            malicious_reports = ('malicious_reports', 'max')
        ).reset_index()
        
        heat_df['max_exposure'] = heat_df['max_exposure'].astype(float)
        heat_df['max_threat'] = heat_df['max_threat'].astype(float)
        heat_df['avg_risk'] = heat_df['avg_risk'].astype(float)

        fig_heatmap = px.scatter(
            heat_df,
            x='max_exposure',
            y='max_threat',
            size='avg_risk',
            color='avg_risk',
            text='ip',
            hover_data={
                'ip': False,
                'services': True,
                'malicious_reports': True,
                'max_exposure': True,
                'max_threat': True,
                'avg_risk': True,
                'overall_severity': True,
            },
            color_continuous_scale='RdYlGn_r',
            title='Host Risk: Exposure Score vs Threat Score',
            labels={
                'max_exposure': 'Max Exposure Score (Service Danger)',
                'max_threat':   'Max Threat Score (VirusTotal Findings)',
                'avg_risk':     'Average Risk Score'
            },
            size_max=50
        )
        fig_heatmap.update_traces(
            textposition='top center',
            marker=dict(line=dict(width=1, color='DarkSlateGrey'))
        )
        fig_heatmap.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color=FONT_COL,
            height=550,
            xaxis_title="Max Exposure Score (How dangerous is the service)",
            yaxis_title="Max Threat Score (VirusTotal findings)",
            xaxis=dict(gridcolor=GRID_COL),
            yaxis=dict(gridcolor=GRID_COL)
        )
        st.plotly_chart(fig_heatmap, width='stretch')
    else:
        st.info('Run a scan with the updated analyser to see the heatmap.')

    st.divider()

    # ── 8. DETAILED RISK OVERVIEW TABLE ───────────────────────────────────────────
    st.subheader('📊 Detailed Risk Overview Table')
    st.caption('All identified ports and services, sortable and filterable. Scroll to view more.')
    st.dataframe(
        df[['ip', 'port', 'protocol', 'service', 'product', 'version', 'severity', 'risk_score',
            'malicious_reports', 'suspicious_count', 'country', 'categories', 'recommendation']]
        .sort_values('risk_score', ascending=False)
        .reset_index(drop=True),
        width='stretch',
        height=400, # Fixed height for table
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