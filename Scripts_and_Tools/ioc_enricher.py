import requests
import json
import time

# ==========================================
# ⚙️ API Configuration
# ==========================================
# Replace these variables with your own API Keys
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

# IOCs extracted from the ClickFix tactical analysis
IOCS = {
    "ips": ["216.238.90.145"],
    "domains": ["cta.berlmember.com", "connect-to-cdn.info"]
}

# ==========================================
# 🔍 Query Functions
# ==========================================

def check_virustotal(indicator, indicator_type):
    """Queries the VirusTotal v3 API for IPs or Domains."""
    print(f"[*] Querying VirusTotal for {indicator_type}: {indicator}...")
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            print(f"    [+] Detections: {stats['malicious']} engines flagged it as malicious.")
            print(f"    [+] General Reputation: {data['data']['attributes'].get('reputation', 'N/A')}")
        elif response.status_code == 401:
            print("    [-] Error: Invalid VirusTotal API Key.")
        else:
            print(f"    [-] VT Query Error: HTTP {response.status_code}")
    except Exception as e:
        print(f"    [-] Exception connecting to VT: {e}")

def check_shodan(ip):
    """Queries the Shodan REST API to analyze an IP's exposure."""
    print(f"[*] Querying Shodan for IP: {ip}...")
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            org = data.get('org', 'Unknown')
            os = data.get('os', 'Unknown')
            ports = data.get('ports', [])
            vulns = data.get('vulns', [])
            
            print(f"    [+] Organization/ISP: {org}")
            print(f"    [+] Operating System: {os}")
            print(f"    [+] Open Ports: {ports}")
            if vulns:
                print(f"    [!] Detected Vulnerabilities (CVEs): {vulns}")
        elif response.status_code == 401:
            print("    [-] Error: Invalid Shodan API Key.")
        elif response.status_code == 404:
            print("    [+] No results in Shodan (IP might not be scanned or active).")
        else:
            print(f"    [-] Shodan Query Error: HTTP {response.status_code}")
    except Exception as e:
        print(f"    [-] Exception connecting to Shodan: {e}")

# ==========================================
# 🚀 Main Execution
# ==========================================

def main():
    print("\n" + "="*50)
    print(" CTI Automator: IOC Enrichment (ClickFix) ")
    print("="*50 + "\n")

    # Validate if keys were configured
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY" or SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
        print("[!] WARNING: You must configure your API Keys before running the script in production.\n")

    # IP Address Analysis
    if IOCS["ips"]:
        print("--- Analyzing IP Addresses ---")
        for ip in IOCS["ips"]:
            check_virustotal(ip, "ip_addresses")
            check_shodan(ip)
            time.sleep(15) # Pause to avoid Rate Limits on free APIs
            print("")

    # Domain Analysis
    if IOCS["domains"]:
        print("--- Analyzing Domains ---")
        for domain in IOCS["domains"]:
            check_virustotal(domain, "domains")
            time.sleep(15)
            print("")
            
    print("[*] Enrichment completed.")

if __name__ == "__main__":
    main()
