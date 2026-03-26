# cyberrisk_platform/modules/scanner.py
import subprocess
import xml.etree.ElementTree as ET
import requests
import os
import time
from dotenv import load_dotenv # Import load_dotenv
load_dotenv() # Load environment variables from .env

# Directory to save Nmap XML outputs
SCAN_DIR = 'scan_results'
os.makedirs(SCAN_DIR, exist_ok=True)


def run_nmap_scan(target: str) -> str:
    """
    Run Nmap and save output as XML. Returns path to the XML file.
    -Pn  skip host discovery (required for targets that block ICMP)
    -sV  detect service versions — gives us product and version fields
    -oX  XML output so we can parse it precisely
    """
    # Sanitize target for filename (replace characters that might be problematic in paths)
    sanitized_target = target.replace("/", "_").replace(":", "_").replace(".", "_")
    xml_file = os.path.join(SCAN_DIR, f'{sanitized_target}.xml')
    
    try:
        # Using subprocess.run with check=True to catch non-zero exit codes
        subprocess.run(
            ['nmap', '-Pn', '-sV', '-oX', xml_file, target],
            capture_output=True,
            check=True,
            text=True # Decode stdout/stderr as text
        )
        return xml_file
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed for {target}: {e.stderr}")
        return ""
    except FileNotFoundError:
        print("Error: 'nmap' command not found. Please ensure Nmap is installed and in your system's PATH.")
        return ""
    except Exception as e:
        print(f"An unexpected error occurred during Nmap scan for {target}: {e}")
        return ""


def parse_nmap_xml(xml_file: str) -> list:
    """
    Parse Nmap XML into a list of dicts.
    Extracts: ip, port, protocol, state, service, product, version
    """
    if not os.path.exists(xml_file):
        return []
    rows = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            address_elem = host.find('address')
            if address_elem is None:
                continue

            ip = address_elem.get('addr')
            if not ip:
                continue

            for port in host.findall('.//port'):
                svc   = port.find('service')
                state = port.find('state')
                rows.append({
                    'ip':       ip,
                    'port':     port.get('portid', 'unknown'),
                    'protocol': port.get('protocol', 'tcp'),
                    'state':    state.get('state', 'unknown') if state is not None else 'unknown',
                    'service':  svc.get('name',    'unknown') if svc is not None else 'unknown',
                    'product':  svc.get('product', '')        if svc is not None else '',
                    'version':  svc.get('version', '')        if svc is not None else '',
                })
    except ET.ParseError as e:
        print(f"Error parsing Nmap XML file {xml_file}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while parsing Nmap XML {xml_file}: {e}")
    return rows


def check_virustotal(ip: str, api_key: str) -> dict:
    """
    Query VirusTotal for one IP. Returns a rich dict with 7 fields.
    If the API call fails or key is missing, returns safe zero defaults.
    """
    default = {
        'malicious_reports': 0,
        'suspicious_count':  0,
        'harmless_count':    0,
        'community_score':   0,
        'country':           'Unknown',
        'network':           'Unknown',
        'categories':        '',
    }
    if not api_key:
        return default

    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': api_key},
            timeout=10
        )
        
        if r.status_code == 404: # IP not found in VT
            return default
        if r.status_code == 401: # Invalid API Key
            print("VirusTotal API key is invalid. Please check your VT_API_KEY environment variable.")
            return default
        if r.status_code != 200:
            print(f"VirusTotal API call failed for {ip} with status {r.status_code}: {r.text}")
            return default

        attrs = r.json().get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})

        cats    = attrs.get('categories', {})
        cat_str = ', '.join(sorted(set(cats.values()))) if cats else ''

        votes   = attrs.get('total_votes', {})
        c_score = votes.get('harmless', 0) - votes.get('malicious', 0)

        return {
            'malicious_reports': stats.get('malicious',  0),
            'suspicious_count':  stats.get('suspicious', 0),
            'harmless_count':    stats.get('harmless',   0),
            'community_score':   c_score,
            'country':           attrs.get('country',  'Unknown'),
            'network':           attrs.get('network',  'Unknown'),
            'categories':        cat_str,
        }
    except requests.exceptions.RequestException as e:
        print(f"Network error during VirusTotal check for {ip}: {e}")
        return default
    except Exception as e:
        print(f"An unexpected error occurred during VirusTotal check for {ip}: {e}")
        return default