# cyberrisk_platform/modules/analyser.py
import pandas as pd
# No direct environment variable access here; values passed as arguments or from other modules.

# ── Service risk weights (0-10) ───────────────────────────────────────────────
# These are the EXPOSURE dimension weights.
# Higher = more dangerous to have open on the internet.
SERVICE_RISK = {
    'telnet':    10,  # plaintext — credentials visible on the network
    'rdp':        9,  # Remote Desktop — #1 ransomware entry point
    'smb':        9,  # EternalBlue/WannaCry vector, often used for lateral movement
    'ftp':        8,  # plaintext — commonly exploited for unauthorized access
    'vnc':        8,  # remote access — often misconfigured with weak passwords
    'mongodb':    8,  # no auth by default, frequently exposed
    'redis':      8,  # no auth by default, often exposed to command injection
    'mysql':      7,  # database — should never be internet-facing
    'mssql':      7,  # database — often targeted for data exfiltration
    'postgresql': 7,  # database
    'smtp':       4,  # can relay spam, source of email spoofing
    'ssh':        3,  # encrypted but brute-force target, often misconfigured
    'http':       2,  # depends what is running, can expose web app vulnerabilities
    'https':      1,  # encrypted — lowest inherent risk, but still depends on content
    'dns':        1,  # often UDP, but can be targeted for DDoS amplification
    'rpcbind':    6,  # RPC services can lead to privilege escalation
    'snmp':       5,  # can leak sensitive network information
    'netbios-ssn':9,  # same as SMB (port 445) for Windows sharing
    'microsoft-ds':9, # same as SMB (port 445) for Windows sharing
    'msrpc':      8,  # Microsoft RPC services, potential for vulnerabilities
    'cups':       3,  # printer service, sometimes abused
    'ldap':       6,  # directory services, often contain sensitive info
    'ldaps':      4,  # encrypted LDAP, still sensitive
}

# Specific port numbers that are dangerous regardless of service name
# Common default ports for services known to be risky if exposed
DANGEROUS_PORTS = {
    '21', '23', '25', '80', '135', '139', '445', '1433', '3306', '3389',
    '5900', '6379', '27017', '5432', '111', '161', '162', '389', '636'
}

# Countries with higher rates of malicious traffic in public threat intel feeds
HIGH_RISK_COUNTRIES = {'CN','RU','KP','IR','NG','UA','VN','RO','BY','PK','TR'}

# Plain-English actions for each service
RECOMMENDATIONS = {
    'telnet':  'DISABLE IMMEDIATELY — replace with SSH. Telnet sends passwords in plaintext, making credential theft trivial.',
    'ftp':     'Replace with SFTP or FTPS. Plain FTP credentials are visible on the network and it often lacks strong authentication.',
    'rdp':     'Restrict to VPN only. Enable Network Level Authentication (NLA) and use strong, unique passwords. Monitor login attempts closely to detect brute-force attacks.',
    'vnc':     'Ensure a strong, complex password is set. Consider VPN-only access and implement multi-factor authentication if possible.',
    'smb':     'Block port 445 at the firewall perimeter. Verify MS17-010 patch is applied and restrict SMB access to trusted internal networks only.',
    'ssh':     'Disable password login — use SSH keys only. Consider changing to a non-standard port and implement rate limiting for connection attempts.',
    'smtp':    'Disable open relay. Ensure SPF, DKIM, and DMARC records are configured to prevent email spoofing and spam.',
    'mysql':   'This port should NOT be internet-facing. Restrict access to localhost or a private network. Use strong, unique database credentials.',
    'mssql':   'This port should NOT be internet-facing. Use Windows Authentication and restrict access to trusted internal hosts.',
    'mongodb': 'Set authentication immediately. MongoDB has no auth enabled by default, making it highly vulnerable if exposed.',
    'redis':   'Bind to localhost only. Set a strong password. Never expose to internet, as it can be exploited for arbitrary command execution.',
    'postgresql':'This port should NOT be internet-facing. Restrict access to trusted internal networks and ensure strong authentication.',
    'http':    'Check for directory listing, default credentials, and outdated web server software. Ensure only necessary content is exposed.',
    'https':   'Verify TLS version — disable TLS 1.0/1.1 and prefer TLS 1.2/1.3. Check certificate expiry, chain, and ensure strong ciphers are used.',
    'rpcbind': 'Restrict access to trusted internal networks. Ensure all RPC services are patched and configured securely.',
    'snmp':    'Disable if not strictly necessary. If in use, ensure strong community strings (v3) and restrict access to monitoring systems only.',
    'ldap':    'Restrict access to trusted internal networks. Use LDAPS (encrypted) instead of plain LDAP and enforce strong authentication.',
}


def _exposure_score(service: str, port: str) -> float:
    """How dangerous is this open service? Returns 0-10."""
    base       = SERVICE_RISK.get(service.lower(), 2) # Default to 2 for unknown services
    port_bonus = 1 if str(port) in DANGEROUS_PORTS else 0
    return min(10.0, base + port_bonus)


def _threat_score(malicious: int, suspicious: int) -> float:
    """How threatening is this IP according to VirusTotal? Returns 0-10."""
    score = malicious * 2 + suspicious * 0.5
    return min(10.0, score)


def _context_score(country: str, categories: str, community_score: int) -> float:
    """Contextual risk from country, VT categories, and community votes. Returns 0-10."""
    score = 0.0
    if country in HIGH_RISK_COUNTRIES:
        score += 3
    bad_cats = {'malware', 'phishing', 'spam', 'botnet', 'command and control', 'abuse', 'hacktool'}
    found_cats = {c.strip().lower() for c in categories.split(',') if c.strip()}
    score += len(found_cats.intersection(bad_cats)) * 2
    if community_score < -5:
        score += 2
    elif community_score < 0:
        score += 1
    return min(10.0, score)


def _classify(score: float) -> str:
    """Convert numeric score to severity label."""
    if score >= 8:   return 'Critical'
    elif score >= 6: return 'High'
    elif score >= 3: return 'Medium'
    else:            return 'Low'


def enrich_dataframe(df: pd.DataFrame, vt_data: dict) -> pd.DataFrame:
    """
    Add all analysis columns to the scan DataFrame.

    Args:
        df:      Raw Nmap DataFrame from parse_nmap_xml()
        vt_data: {ip: vt_dict} from check_virustotal()

    Returns:
        Enriched DataFrame with these new columns:
        malicious_reports, suspicious_count, harmless_count, community_score,
        country, network, categories,
        exposure_score, threat_score, context_score,
        risk_score, severity, recommendation
    """
    df = df.copy()

    # Merge VT data
    if vt_data:
        vt_df = pd.DataFrame.from_dict(vt_data, orient='index').rename_axis('ip').reset_index()
        df = df.merge(vt_df, on='ip', how='left')

    # Fill missing VT data with safe defaults
    defaults = {
        'malicious_reports': 0, 'suspicious_count': 0, 'harmless_count': 0,
        'community_score': 0,   'country': 'Unknown',  'network': 'Unknown',
        'categories': ''
    }
    for col, val in defaults.items():
        if col not in df.columns:
            df[col] = val
        else:
            df[col] = df[col].fillna(val)

    for col in ['malicious_reports', 'suspicious_count', 'harmless_count', 'community_score']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(defaults[col]).astype(int)

    # Three dimension scores
    df['exposure_score'] = df.apply(
        lambda r: _exposure_score(str(r.get('service', 'unknown')), str(r.get('port', 'unknown'))), axis=1)
    df['threat_score'] = df.apply(
        lambda r: _threat_score(
            r['malicious_reports'],
            r['suspicious_count']), axis=1)
    df['context_score'] = df.apply(
        lambda r: _context_score(
            str(r.get('country',         'Unknown')),
            str(r.get('categories',      '')),
            r['community_score']), axis=1)

    # Weighted final score
    df['risk_score'] = (
        df['exposure_score'] * 0.45 +
        df['threat_score']   * 0.35 +
        df['context_score']  * 0.20
    ).round(1)

    df['severity']       = df['risk_score'].apply(_classify)
    df['recommendation'] = df['service'].apply(
        lambda s: RECOMMENDATIONS.get(str(s).lower(),
                  'Review this service. Ensure it is necessary, patched, and securely configured. Check logs for unusual activity.'))
    return df


def build_host_summary(df: pd.DataFrame) -> pd.DataFrame:
    """One row per host with aggregated stats."""
    if df.empty:
        return pd.DataFrame(columns=[
            'ip', 'open_ports', 'max_risk', 'avg_risk', 'critical_count',
            'high_count', 'malicious', 'country', 'services', 'products', 'overall_severity'
        ])

    summary = df.groupby('ip').agg(
        open_ports     = ('port',             'count'),
        max_risk       = ('risk_score',        'max'),
        avg_risk       = ('risk_score',        'mean'),
        critical_count = ('severity', lambda x: (x == 'Critical').sum()),
        high_count     = ('severity', lambda x: (x == 'High').sum()),
        # Max malicious reports across all ports for that IP
        malicious      = ('malicious_reports', 'max'),
        country        = ('country',           lambda x: x.mode()[0] if not x.empty else 'Unknown'), # Most common country, or first if all same
        services       = ('service',  lambda x: ', '.join(sorted(set(x)))),
        # Filter empty strings before joining products
        products       = ('product',  lambda x: ', '.join(sorted(s for s in set(x) if s))),
    ).reset_index()
    summary['avg_risk']         = summary['avg_risk'].round(1)
    summary['overall_severity'] = summary['max_risk'].apply(_classify)
    return summary.sort_values('max_risk', ascending=False).reset_index(drop=True)


def generate_summary(df: pd.DataFrame, host_df: pd.DataFrame) -> dict:
    """
    Generate structured data for the Analysis page.
    Returns a dict with posture, KPIs, findings list, and top risks.
    """
    # Handle empty DataFrame gracefully
    if df.empty:
        return {
            'posture':       'NO DATA — Run a scan first',
            'colour':        '#6b7280',
            'total_hosts':   0,
            'total_ports':   0,
            'crit_hosts':    0,
            'high_hosts':    0,
            'vt_flagged':    0,
            'findings':      ['ℹ️ No scan data available. Please run a scan to get insights.'],
            'top_risks':     pd.DataFrame(columns=['ip','port','service','risk_score','severity']),
        }

    crit_hosts = int((host_df['overall_severity'] == 'Critical').sum())
    high_hosts = int((host_df['overall_severity'] == 'High').sum())
    vt_flagged = int((df['malicious_reports'] > 0).sum())

    if crit_hosts > 0:
        posture, colour = 'CRITICAL — Immediate action required', '#dc2626'
    elif high_hosts > 0:
        posture, colour = 'HIGH RISK — Action required within 24 hours', '#ea580c'
    elif len(df) > 0:
        posture, colour = 'MODERATE — Review findings', '#ca8a04'
    else: # Fallback, though df.empty handled above
        posture, colour = 'LOW — No significant findings', '#16a34a'

    # Key findings — plain-language bullets
    findings = []

    # Finding 1: Plaintext protocols
    plaintext_services = ['telnet', 'ftp', 'http', 'smtp', 'ldap']
    plaintext_df = df[df['service'].isin(plaintext_services) & (df['state'] == 'open')]
    if not plaintext_df.empty:
        # Get unique services that are actually open
        open_plaintext_svcs = sorted(plaintext_df['service'].unique())
        if 'http' in open_plaintext_svcs: # Only flag http if no https is also open for that IP:port
            http_only_ips_ports = []
            for idx, row in plaintext_df[plaintext_df['service'] == 'http'].iterrows():
                if not ((df['ip'] == row['ip']) & (df['port'] == row['port']) & (df['service'] == 'https')).any():
                    http_only_ips_ports.append(f"{row['ip']}:{row['port']}")
            if http_only_ips_ports:
                findings.append(f'🔴 Unencrypted (HTTP) services found without HTTPS alternative on {len(http_only_ips_ports)} entries. Credentials or sensitive data may be transmitted in plaintext.')
        
        other_plaintext_svcs = [s for s in open_plaintext_svcs if s != 'http']
        if other_plaintext_svcs:
            findings.append(f'🔴 Plaintext protocols open ({", ".join(other_plaintext_svcs)}) — credentials or data sent unencrypted, highly vulnerable to interception.')

    # Finding 2: VirusTotal flags
    flagged_ips = df[df['malicious_reports'] > 0]['ip'].unique()
    if len(flagged_ips):
        findings.append(f'🔴 {len(flagged_ips)} IP(s) flagged malicious by VirusTotal: {", ".join(flagged_ips)}. Investigate immediately.')

    # Finding 3: Database ports exposed
    db_services = df[df['service'].isin(['mysql','mssql','mongodb','redis','postgresql']) & (df['state'] == 'open')]
    if not db_services.empty:
        findings.append(f'🟠 Database ports exposed ({", ".join(db_services["service"].unique())}) — these should ideally NOT be internet-facing. Restrict access and ensure strong authentication.')

    # Finding 4: Risky countries
    # Ensure 'country' column exists and is not all 'Unknown'
    if 'country' in df.columns and not df['country'].isin(['Unknown']).all():
        risky_countries_ips = df[df['country'].isin(HIGH_RISK_COUNTRIES) & (df['malicious_reports'] > 0)]['ip'].unique()
        if len(risky_countries_ips):
            findings.append(f'🟠 {len(risky_countries_ips)} host(s) registered in high-risk countries and flagged by VirusTotal. Heightened scrutiny required.')

    # Finding 5: Suspicious but not confirmed malicious
    if 'suspicious_count' in df.columns:
        suspicious_ips = df[(df['malicious_reports'] == 0) & (df['suspicious_count'] > 2)]['ip'].unique()
        if len(suspicious_ips):
            findings.append(f'🟡 {len(suspicious_ips)} host(s) show significant suspicious activity on VirusTotal but not confirmed malicious — monitor closely and consider blocking.')

    # Finding 6: Remote access services (RDP, VNC, SSH) exposed
    remote_access_services = ['rdp', 'vnc', 'ssh']
    exposed_remote = df[df['service'].isin(remote_access_services) & (df['state'] == 'open')]
    if not exposed_remote.empty:
        # Group by IP and service to avoid redundant messages for same service on same IP
        unique_remote_exposures = exposed_remote[['ip', 'service']].drop_duplicates()
        if not unique_remote_exposures.empty:
            message_parts = []
            for _, row in unique_remote_exposures.iterrows():
                message_parts.append(f"{row['service']} on {row['ip']}")
            findings.append(f'🟠 Remote access services exposed ({", ".join(message_parts)}) — secure with VPN, strong MFA, and restrict access where possible.')


    if not findings:
        findings.append('✅ No critical or high-risk findings detected in this scan. Good security posture!')

    return {
        'posture':       posture,
        'colour':        colour,
        'total_hosts':   int(df['ip'].nunique()),
        'total_ports':   len(df),
        'crit_hosts':    crit_hosts,
        'high_hosts':    high_hosts,
        'vt_flagged':    vt_flagged,
        'findings':      findings,
        'top_risks':     df.nlargest(5, 'risk_score')[['ip','port','service','risk_score','severity', 'recommendation']],
    }