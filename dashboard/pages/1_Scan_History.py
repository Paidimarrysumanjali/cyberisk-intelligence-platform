# cyberrisk_platform/dashboard/pages/1_Scan_History.py
import streamlit as st
import pandas as pd
import sys, os
from datetime import datetime
from dotenv import load_dotenv # Import load_dotenv
load_dotenv() # Load environment variables from .env

# Add the parent directory of 'modules' to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.database import load_history, load_scan_by_id

st.title('📜 Scan History')
st.caption('Browse and load past scan reports from the database.')

# Load scan summaries from the database
history_df = load_history()

if history_df.empty:
    st.info('No scan history found. Run a scan from the main page to start building your history!')
else:
    # Display scan history in an interactive table
    st.subheader('Past Scans')
    st.dataframe(
        history_df[['id', 'scan_time', 'targets', 'total_hosts', 'total_ports', 'high_risk', 'max_risk_score']].set_index('id'),
        use_container_width=True,
        # Allow selecting a row to view full details
        selection_mode="single-row",
        column_config={
            "scan_time": st.column_config.DatetimeColumn(
                "Scan Time", format="YYYY-MM-DD HH:mm:ss"
            ),
            "targets": st.column_config.TextColumn("Targets"),
            "total_hosts": st.column_config.NumberColumn("Hosts"),
            "total_ports": st.column_config.NumberColumn("Ports"),
            "high_risk": st.column_config.NumberColumn("High/Critical Ports"),
            "max_risk_score": st.column_config.NumberColumn("Max Risk", format="%.1f"),
        }
    )

    # Determine default selection for dropdown
    selected_id_from_session = st.session_state.get('selected_scan_id')
    scan_ids = history_df['id'].tolist()
    default_index = 0
    if selected_id_from_session in scan_ids:
        default_index = scan_ids.index(selected_id_from_session)
    elif scan_ids: # If no session ID or it's not in current history, pick the latest
        default_index = 0 # history_df is sorted by ID DESC, so 0 is latest

    selected_scan_id_from_dropdown = st.selectbox(
        'Select a Scan ID to view details:',
        options=scan_ids,
        index=default_index,
        format_func=lambda x: f"Scan ID: {x} - {history_df[history_df['id'] == x]['scan_time'].iloc[0]} - {history_df[history_df['id'] == x]['targets'].iloc[0]}"
    )
    
    # Update session state with the currently selected dropdown value
    st.session_state.selected_scan_id = selected_scan_id_from_dropdown

    # Load button
    if st.button(f'Load Scan ID {st.session_state.selected_scan_id} into Current View', type='primary'):
        with st.spinner(f'Loading full results for Scan ID {st.session_state.selected_scan_id}...'):
            full_scan_df = load_scan_by_id(st.session_state.selected_scan_id)
            if not full_scan_df.empty:
                st.session_state.df = full_scan_df
                st.session_state.scan_time = history_df[history_df['id'] == st.session_state.selected_scan_id]['scan_time'].iloc[0]
                st.session_state.last_refreshed = datetime.now().strftime('%d %b %Y  %H:%M:%S') # Update refreshed time
                st.success(f'Scan ID {st.session_state.selected_scan_id} loaded successfully! Navigate to "🔍 Analysis" for details.')
                st.rerun() # Rerun to ensure app.py and Analysis page update
            else:
                st.error(f'Failed to load data for Scan ID {st.session_state.selected_scan_id}. It might be corrupted or missing.')