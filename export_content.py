# cyberrisk_platform/dashboard/content_pages/export_content.py
import streamlit as st
import pandas as pd
import sys, os
from dotenv import load_dotenv 
load_dotenv()

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from modules.analyser import build_host_summary, generate_summary
from modules.pdf_generator import generate_pdf_report


def render_page():
    st.title('💾 Export Results')
    st.caption('Download scan data in various formats.')

    df = st.session_state.get('df')
    scan_time = st.session_state.get('scan_time', 'N/A')

    if df is None or df.empty:
        st.info('No scan data loaded yet. Run a scan from the main page or load from scan history to enable exports.')
        return

    host_sum = build_host_summary(df)
    summary  = generate_summary(df, host_sum)

    st.subheader('CSV Data Exports')

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Full Scan Results**")
        st.caption("All hosts and ports from the current scan.")
        st.download_button(
            label="⬇️ Download Full Results (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"cyberscan_full_results_{scan_time.replace(':', '-')}.csv",
            mime="text/csv",
            width='stretch'
        )

    with col2:
        st.markdown("**Host Summary Report**")
        st.caption("One row per host with aggregated stats.")
        summary_export_df = host_sum[['ip', 'open_ports', 'max_risk', 'avg_risk', 'overall_severity', 'services']].copy()
        summary_export_df.columns = ["IP", "Open Ports", "Max Risk", "Avg Risk", "Overall Severity", "Services"]

        st.download_button(
            label="⬇️ Download Host Summary (CSV)",
            data=summary_export_df.to_csv(index=False).encode("utf-8"),
            file_name=f"cyberscan_host_summary_{scan_time.replace(':', '-')}.csv",
            mime="text/csv",
            width='stretch'
        )

    st.divider()

    st.subheader('PDF Report Generation')
    st.markdown("Generate a comprehensive PDF report summarizing the current scan's findings.")

    if st.button('📄 Generate PDF Report', type='primary', width='stretch'):
        with st.spinner("Generating PDF report..."):
            try:
                pdf_bytes = generate_pdf_report(df, summary, host_sum, scan_time)
                st.download_button(
                    label="⬇️ Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"cyberscan_report_{scan_time.replace(':', '-')}.pdf",
                    mime="application/pdf",
                    width='stretch'
                )
                st.success("PDF report generated successfully! Click the button above to download.")
            except Exception as e:
                st.error(f"Failed to generate PDF report: {e}")
                st.warning("Ensure all data is valid and fpdf2 library is correctly installed.")