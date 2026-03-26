# cyberisk_platform/dashboard/app.py

import streamlit as st
import time, os, sys
import pandas as pd
import requests as _req 
from datetime import datetime
from dotenv import load_dotenv 
load_dotenv()

# Add the project root to Python path for general module imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import core modules
from modules.scanner  import run_nmap_scan, parse_nmap_xml, check_virustotal
from modules.analyser import enrich_dataframe, generate_summary, build_host_summary
from modules.database import save_scan
from modules.emailer import send_alert_email

# Import the new content modules
import dashboard.content_pages.analysis_content as analysis_page
import dashboard.content_pages.export_content as export_page
import dashboard.content_pages.scan_history_content as scan_history_page


st.set_page_config(page_title='CyberScan Pro', page_icon='🛡️', layout='wide')

# ── Credentials & Targets Configuration ───────────────────────────────────────
VT_KEY          = os.environ.get('VT_API_KEY', '')
API_KEY         = os.environ.get('CYBERSCAN_API_KEY', 'dev-key')
GMAIL_SENDER    = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASSWORD  = os.environ.get('GMAIL_PASSWORD', '')
GMAIL_RECIPIENT = os.environ.get('GMAIL_RECIPIENT', '')
INITIAL_TARGETS_STR = os.environ.get('SCAN_TARGETS', 'scanme.nmap.org')

# ── Session State Initialization ──────────────────────────────────────────────
for key, val in [
    ('df', None),
    ('scan_time', None),
    ('last_refreshed', None),
    ('selected_scan_id', None),
    ('scan_targets_input', INITIAL_TARGETS_STR),
    ('current_page', 'Home') # Initialize current page
]:
    if key not in st.session_state:
        st.session_state[key] = val

# ── Sidebar Layout (Custom Navigation Implemented) ────────────────────────────

# 1. CyberScan Pro Title and Tagline (NOW AT THE VERY TOP!)
st.sidebar.markdown(
    """
    <div style="text-align: center; margin-bottom: 20px;">
        <h2 style="color:#4f8ef7; margin:0; font-size: 2em;">🛡️ CyberScan Pro</h2>
        <p style="color:#e2e8f0; font-size: 0.9em; margin:0;">Network Reconnaissance & Threat Intelligence</p>
    </div>
    """,
    unsafe_allow_html=True
)
st.sidebar.divider()

# 2. Custom Navigation Links
# Map display names to internal page keys
PAGE_OPTIONS = {
    "Home": "Home",
    "Scan History": "Scan History",
    "Analysis": "Analysis",
    "Export": "Export"
}

selected_page_display = st.sidebar.radio(
    "Navigation",
    list(PAGE_OPTIONS.keys()),
    index=list(PAGE_OPTIONS.keys()).index(st.session_state.current_page),
    key="custom_navigation_radio",
)
st.session_state.current_page = PAGE_OPTIONS[selected_page_display]

st.sidebar.divider()

# 3. Scan Targets (Input)
st.sidebar.subheader('🎯 Scan Targets')
targets_input = st.sidebar.text_area(
    'Enter target IPs/Hostnames (comma-separated):',
    value=st.session_state.scan_targets_input,
    height=100,
    key='scan_targets_input_widget'
)
st.session_state.scan_targets_input = targets_input
current_targets_list = [t.strip() for t in targets_input.split(',') if t.strip()]
if not current_targets_list:
    current_targets_list = ['scanme.nmap.org'] # Fallback if user clears input
st.sidebar.caption(f'Targets to scan: {", ".join(current_targets_list)}')
st.sidebar.divider()

# 4. Scan Actions (Buttons)
st.sidebar.subheader('🚀 Scan Actions')
scan_btn    = st.sidebar.button('Run Full Scan',  width='stretch', type='primary')
clear_btn = st.sidebar.button('Clear Current Scan',   width='stretch')
st.sidebar.divider()

# 5. Status (Bottom of Sidebar)
st.sidebar.subheader('⚙️ Status')
if VT_KEY:
    st.sidebar.success('VirusTotal API key ready ✅')
else:
    st.sidebar.error('❌ VT_API_KEY not set in environment.')
if API_KEY:
    st.sidebar.success('CyberScan API key ready ✅')
else:
    st.sidebar.error('❌ CYBERSCAN_API_KEY not set.')
if GMAIL_SENDER and GMAIL_PASSWORD and GMAIL_RECIPIENT:
    st.sidebar.success('Email alerting credentials ready ✅')
else:
    st.sidebar.warning('⚠️ Email credentials incomplete. Alerting disabled.')

st.sidebar.divider()


# ── Main Content Area Rendering ───────────────────────────────────────────────

if st.session_state.current_page == "Home":
    st.title('🛡️ CyberScan Pro') 

    if st.session_state.last_refreshed:
        st.info(f'🕐 Last scan completed: {st.session_state.last_refreshed}')
    else:
        st.info('🕐 No scan data loaded yet. Use the sidebar to **Run Full Scan** or load from **Scan History**.')
    st.divider()

    # ── Scan Trigger Logic ────────────────────────────────────────────────────────
    if scan_btn or clear_btn:
        if clear_btn:
            st.session_state.df = None
            st.session_state.scan_time = None
            st.session_state.last_refreshed = None
            st.session_state.selected_scan_id = None
            st.rerun()

        if not VT_KEY:
            st.error('VirusTotal API key is missing. Please set VT_API_KEY in your .env file or environment variables.')
            st.stop()
        if not current_targets_list:
            st.error('No scan targets configured. Please enter targets in the sidebar.')
            st.stop()

        bar, status = st.progress(0), st.empty()
        all_nmap_rows = []
        total_steps = len(current_targets_list) * 2

        status.info('🔍 Starting Nmap scans...')
        for i, target in enumerate(current_targets_list):
            status.info(f'🔍 Nmap scanning target: **{target}** ({i+1}/{len(current_targets_list)})...')
            xml_file = run_nmap_scan(target)
            if xml_file:
                all_nmap_rows.extend(parse_nmap_xml(xml_file))
            bar.progress((i + 1) / total_steps)

        df_raw = pd.DataFrame(all_nmap_rows)

        if df_raw.empty or "ip" not in df_raw.columns:
            bar.empty()
            status.warning('⚠️ Nmap returned no open ports for any target. Check targets, network connectivity, or Nmap installation.')
            st.session_state.df = pd.DataFrame()
            st.stop()

        status.info('🦠 Starting VirusTotal enrichment...')
        vt_data = {}
        unique_ips = df_raw['ip'].unique()
        current_step_progress = len(current_targets_list)

        for j, ip in enumerate(unique_ips):
            status.info(f'🦠 Querying VirusTotal for IP: **{ip}** ({j+1}/{len(unique_ips)})...')
            vt_data[ip] = check_virustotal(ip, VT_KEY)
            bar.progress((current_step_progress + j + 1) / total_steps)
            if j < len(unique_ips) - 1:
                time.sleep(15)

        status.info('🧠 Performing risk analysis...')
        df_enriched = enrich_dataframe(df_raw, vt_data)

        st.session_state.df             = df_enriched
        st.session_state.scan_time      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        st.session_state.last_refreshed = datetime.now().strftime('%d %b %Y  %H:%M:%S')
        st.session_state.selected_scan_id = None

        status.info('💾 Saving scan results to database...')
        save_scan(df_enriched, current_targets_list)

        host_sum_for_summary = build_host_summary(df_enriched)
        scan_summary_for_email = generate_summary(df_enriched, host_sum_for_summary)

        status.info('📧 Sending email report...')
        if GMAIL_SENDER and GMAIL_PASSWORD and GMAIL_RECIPIENT:
            email_result = send_alert_email(
                GMAIL_SENDER,
                GMAIL_PASSWORD,
                GMAIL_RECIPIENT,
                df_enriched,
                st.session_state.scan_time,
                scan_summary_for_email
            )
            if email_result is True:
                status.success(f'📧 Email report sent successfully to {GMAIL_RECIPIENT}.')
            else:
                status.warning(f'⚠️ Failed to send email report: {email_result}. Please check email credentials.')
        else:
            status.warning('⚠️ Email credentials incomplete. Report not sent.')

        status.info('🌐 Pushing data to FastAPI API (if running)...')
        try:
            _req.post(
                'http://localhost:8000/load',
                json=df_enriched.to_dict(orient='records'),
                headers={'X-API-Key': API_KEY},
                timeout=5
            )
            status.success('🌐 Data successfully pushed to FastAPI API.')
        except _req.exceptions.ConnectionError:
            status.warning('⚠️ Could not connect to FastAPI API. Is it running? Data not pushed to API.')
        except _req.exceptions.Timeout:
            status.warning('⚠️ FastAPI API connection timed out. Data not pushed to API.')
        except _req.exceptions.HTTPError as e:
            status.warning(f'⚠️ FastAPI API returned an error: {e}. Data not pushed to API.')
        except Exception as e:
            status.warning(f'⚠️ An unexpected error occurred while pushing to FastAPI: {e}. Data not pushed to API.')

        bar.empty()
        status.success(f'Scan complete! Found {len(df_enriched)} ports across {df_enriched["ip"].nunique()} hosts.')
        st.rerun()

    # ── Main Dashboard Summary Display (UPDATED) ──────────────────────────────────
    df_current = st.session_state.df

    if df_current is None or df_current.empty:
        st.markdown("### Get Started")
        st.markdown("""
        To begin, use the sidebar controls:
        1.  **Enter Targets:** In the sidebar, provide IPs/Hostnames for scanning.
        2.  **Configure API Keys:** Ensure `VT_API_KEY` and `CYBERSCAN_API_KEY` are set in your `.env` file or environment variables.
        3.  **Run Scan:** Click **`🚀 Run Full Scan`**.
        """)
        st.markdown("Alternatively, if you have run scans before, navigate to **`📜 Scan History`** in the sidebar to load a previous report.")
    else:
        host_sum = build_host_summary(df_current)
        summary  = generate_summary(df_current, host_sum)

        st.subheader('Current Scan Posture:')
        st.markdown(
            f'<div style="background:{summary["colour"]};padding:16px;'
            f'border-radius:8px;text-align:center;">'
            f'<h3 style="color:white;margin:0;">'
            f'{summary["posture"]}</h3></div>',
            unsafe_allow_html=True
        )
        st.divider()

        st.subheader('Key Performance Indicators:')
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric('🖥️ Total Hosts',     summary['total_hosts'])
        c2.metric('🔓 Open Ports',     summary['total_ports'])
        c3.metric('🚨 Critical Hosts', summary['crit_hosts'])
        c4.metric('⚠️ High Risk Hosts', summary['high_hosts'])
        c5.metric('🦠 VT Flagged IPs',  summary['vt_flagged'])
        st.divider()

        st.info('👈 Use the sidebar navigation to view **`🔍 Analysis`** for detailed findings and recommendations, or **`📜 Scan History`** for past reports.')

elif st.session_state.current_page == "Scan History":
    scan_history_page.render_page()
elif st.session_state.current_page == "Analysis":
    analysis_page.render_page()
elif st.session_state.current_page == "Export":
    export_page.render_page()
