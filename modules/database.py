# cyberrisk_platform/modules/database.py
import sqlite3
import pandas as pd
from datetime import datetime
import json # To store and retrieve DataFrame as JSON string
# No direct environment variable access here; values passed as arguments or from other modules.

DB_FILE = 'cyberscan.db'


def init_db():
    """Create the scans table if it does not exist. Safe to call every startup."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time      TEXT    NOT NULL,
            targets        TEXT,
            total_hosts    INTEGER,
            total_ports    INTEGER,
            high_risk      INTEGER,
            max_risk_score REAL,
            results_json   TEXT    NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_scan(df: pd.DataFrame, targets: list):
    """Persist a completed scan to the database. Called after every scan."""
    if df.empty:
        print("DataFrame is empty, not saving scan.")
        return

    conn = sqlite3.connect(DB_FILE)
    # Calculate high_risk count based on 'High' or 'Critical' severity
    high_risk_count = int(df['severity'].isin(['High', 'Critical']).sum())
    max_risk_score = float(df['risk_score'].max()) if not df['risk_score'].empty else 0.0

    conn.execute(
        '''INSERT INTO scans
           (scan_time, targets, total_hosts, total_ports, high_risk, max_risk_score, results_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ', '.join(targets),
            int(df['ip'].nunique()),
            len(df),
            high_risk_count,
            max_risk_score,
            df.to_json(orient='records'), # Store DataFrame as JSON string
        )
    )
    conn.commit()
    conn.close()


def load_history() -> pd.DataFrame:
    """Return scan summaries as a DataFrame — newest scan first."""
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        'SELECT id, scan_time, targets, total_hosts, '
        'total_ports, high_risk, max_risk_score '
        'FROM scans ORDER BY id DESC',
        conn
    )
    conn.close()
    return df


def load_scan_by_id(scan_id: int) -> pd.DataFrame:
    """Return full results for one scan ID. Used in the Scan History page."""
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        'SELECT results_json FROM scans WHERE id = ?', (scan_id,)
    ).fetchone()
    conn.close()
    if row and row[0]:
        try:
            return pd.read_json(row[0])
        except ValueError as e:
            print(f"Error reading JSON for scan ID {scan_id}: {e}")
            return pd.DataFrame()
    return pd.DataFrame()


# Initialise the database when this module is first imported
init_db()