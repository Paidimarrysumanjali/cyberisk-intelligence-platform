# cyberrisk_platform/api.py
from fastapi import FastAPI, HTTPException, Depends, Header, Request, status, Query, Path # Added Path here
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv # Import load_dotenv
load_dotenv() # Load environment variables from .env


# ── API key ───────────────────────────────────────────────────────────────────
# Reads API key from Colab Secrets or environment variable.
# Provides a 'dev-key' fallback for local development if not set.
# Note: For local VS Code, this will primarily read from your .env file.
try:
    from google.colab import userdata
    CYBERSCAN_API_KEY = (
        userdata.get('CYBERSCAN_API_KEY')
        or os.environ.get('CYBERSCAN_API_KEY', 'dev-key')
    )
except ImportError: # Not in Colab
    CYBERSCAN_API_KEY = os.environ.get('CYBERSCAN_API_KEY', 'dev-key')


# ── Rate limiter + app ────────────────────────────────────────────────────────
# Limits requests based on client IP address.
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title='CyberScan Pro API',
    version='1.0',
    description='Authenticated and rate-limited REST API for CyberScan Pro scan results.'
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── In-memory store for current scan data ─────────────────────────────────────
# This will hold the latest enriched scan results.
SCAN_DATA: List[Dict] = [] # Stored as plain dictionaries after Pydantic validation
LAST_SCAN_TIME: Optional[str] = None

# ── Pydantic model for a single scan record (enriched with analysis) ─────────
class ScanRecord(BaseModel):
    ip:                  str = Field(..., description="Target IP address")
    port:                str = Field(..., description="Open port number")
    protocol:            Optional[str] = Field('tcp', description="Network protocol (e.g., tcp, udp)")
    state:               Optional[str] = Field('open', description="Port state (e.g., open, closed, filtered)")
    service:             str = Field(..., description="Detected service (e.g., ssh, http)")
    product:             Optional[str] = Field('', description="Product running on the service (e.g., OpenSSH)")
    version:             Optional[str] = Field('', description="Version of the product")
    malicious_reports:   int = Field(0, description="Number of VirusTotal engines flagging the IP as malicious")
    suspicious_count:    int = Field(0, description="Number of VirusTotal engines flagging the IP as suspicious")
    harmless_count:      int = Field(0, description="Number of VirusTotal engines flagging the IP as harmless")
    community_score:     int = Field(0, description="VirusTotal community score (harmless - malicious votes)")
    country:             Optional[str] = Field('Unknown', description="Country of origin for the IP")
    network:             Optional[str] = Field('Unknown', description="Network/ISP associated with the IP")
    categories:          Optional[str] = Field('', description="Comma-separated list of VirusTotal categories (e.g., malware, phishing)")
    exposure_score:      float = Field(0.0, description="Calculated exposure risk score (0-10) for the service")
    threat_score:        float = Field(0.0, description="Calculated threat risk score (0-10) from VirusTotal data")
    context_score:       float = Field(0.0, description="Calculated contextual risk score (0-10) from country/categories")
    risk_score:          float = Field(0.0, description="Overall weighted risk score (0-10) for the record")
    severity:            str = Field('Low', description="Severity classification (Low, Medium, High, Critical)")
    recommendation:      Optional[str] = Field('', description="Actionable recommendation for the detected service/risk")

# ── Authentication Dependency ─────────────────────────────────────────────────
# This function is used as a dependency for protected endpoints.
# FastAPI will call it before the endpoint, and if it raises an HTTPException,
# the endpoint will not be executed.
def verify_key(x_api_key: str = Header(..., description='Your CyberScan API key')):
    """Validates the X-API-Key header against the configured API key."""
    if x_api_key != CYBERSCAN_API_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Invalid API key')

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get('/', summary='API Health Check (Public)', response_model=Dict[str, str])
def root():
    """
    Provides a public health check for the API.
    Returns status, version, and the number of records currently loaded.
    No authentication required.
    """
    return {
        'status': 'running',
        'version': app.version,
        'records_loaded': str(len(SCAN_DATA)), # Convert to string for consistent type in response_model
        'last_scan_time': LAST_SCAN_TIME if LAST_SCAN_TIME else 'N/A',
        'auth_required': 'X-API-Key header is required for all other endpoints.'
    }


@app.post('/load',
          dependencies=[Depends(verify_key)],
          status_code=status.HTTP_200_OK,
          response_model=Dict[str, int],
          summary='Load Scan Data (Protected, Rate-limited)')
@limiter.limit('20/minute') # Limit to 20 requests per minute from a single IP
def load_data(request: Request, records: List[ScanRecord]):
    """
    Loads fresh enriched scan results into the API's in-memory data store.
    This endpoint is typically called by the Streamlit dashboard after a new scan.
    Requires authentication via `X-API-Key` header.
    Pydantic validates every incoming record automatically.
    """
    global SCAN_DATA, LAST_SCAN_TIME
    SCAN_DATA = [r.dict() for r in records] # Convert Pydantic models to dicts for storage
    LAST_SCAN_TIME = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return {
        'status_code': status.HTTP_200_OK,
        'records_loaded': len(SCAN_DATA),
        'unique_hosts': len({r['ip'] for r in SCAN_DATA})
    }


@app.get('/results',
         dependencies=[Depends(verify_key)],
         response_model=Dict[str, List[ScanRecord]],
         summary='Get All Scan Results (Protected, Rate-limited)')
@limiter.limit('60/minute') # Limit to 60 requests per minute
def get_results(
    request: Request,
    severity: Optional[str] = Query(None, description="Filter by severity (Low, Medium, High, Critical)"),
    min_risk: float = Query(0.0, description="Only return records with risk_score greater than or equal to this value")
):
    """
    Retrieves the latest enriched scan results with optional filtering.
    Requires authentication via `X-API-Key` header.
    - **severity**: Filters records by a specific severity level.
    - **min_risk**: Filters records by a minimum risk score.
    """
    if not SCAN_DATA:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No scan data loaded yet. Run a scan in the dashboard first.')

    filtered_data = [r for r in SCAN_DATA if r['risk_score'] >= min_risk]
    if severity:
        # Case-insensitive comparison for severity
        filtered_data = [r for r in filtered_data if r['severity'].lower() == severity.lower()]

    return {'results': filtered_data}


@app.get('/results/{ip_address}',
         dependencies=[Depends(verify_key)],
         response_model=Dict[str, List[ScanRecord]],
         summary='Get Results for Specific IP (Protected)')
def get_ip_results(ip_address: str = Path(..., description="The target IP address")): # Changed Field to Path
    """
    Retrieves all scan records associated with a specific IP address.
    Requires authentication via `X-API-Key` header.
    """
    if not SCAN_DATA:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No scan data loaded yet.')

    matches = [r for r in SCAN_DATA if r['ip'] == ip_address]
    if not matches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'No scan results found for IP: {ip_address}')

    return {'results': matches}


@app.get('/analysis',
         dependencies=[Depends(verify_key)],
         response_model=Dict[str, Dict], # Response model will be more complex, but this is a placeholder
         summary='Get Aggregated Scan Analysis (Protected, Rate-limited)')
@limiter.limit('30/minute') # Limit to 30 requests per minute
def get_analysis(request: Request):
    """
    Returns aggregated statistics and summary information from the latest scan.
    Requires authentication via `X-API-Key` header.
    """
    if not SCAN_DATA:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No scan data loaded yet. Run a scan in the dashboard first.')

    df = pd.DataFrame(SCAN_DATA)
    
    # Calculate summary statistics
    total_records = len(df)
    total_hosts = df['ip'].nunique()
    
    by_severity = df['severity'].value_counts().to_dict()
    
    max_risk = df['risk_score'].max() if not df.empty else 0.0
    avg_risk = df['risk_score'].mean() if not df.empty else 0.0

    return {
        'summary': {
            'total_records': total_records,
            'total_hosts': total_hosts,
            'by_severity': by_severity,
            'max_risk_score': round(float(max_risk), 1),
            'avg_risk_score': round(float(avg_risk), 1),
            'critical_hosts': int(df[df['severity'] == 'Critical']['ip'].nunique()),
            'high_risk_hosts': int(df[df['severity'] == 'High']['ip'].nunique()),
            'vt_flagged_ips': int(df[df['malicious_reports'] > 0]['ip'].nunique()),
            'scan_time': LAST_SCAN_TIME
        }
    }