import nmap
import requests
import os
import time
from pprint import pprint

# NVD API setup: Try environment variable first, fallback to hardcoded key
NVD_API_KEY = os.getenv('NVD_API_KEY')  # Looks for env variable set via export/set
if not NVD_API_KEY:
    NVD_API_KEY = 'your-api-key-here'  # Replace with your actual NVD API key if not using env variable
NVD_VULN_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
HEADERS = {"apiKey": NVD_API_KEY}

# Common product to CPE mapping (extend as needed)
PRODUCT_TO_CPE = {
    "apache httpd": {"vendor": "apache", "product": "http_server"},
    "nginx": {"vendor": "nginx", "product": "nginx"},
    "openssh": {"vendor": "openbsd", "product": "openssh"},
    "mysql": {"vendor": "mysql", "product": "mysql"},
    "squid-http": {"vendor": "squid-cache", "product": "squid"}  
}

def get_cpe_name(product, version):
    """Construct or fetch CPE name for a given product and version."""
    product = product.lower()
    if product in PRODUCT_TO_CPE:
        cpe_data = PRODUCT_TO_CPE[product]
        return f"cpe:2.3:a:{cpe_data['vendor']}:{cpe_data['product']}:{version}:*:*:*:*:*:*:*"
    
    # Fallback: Search NVD CPE API if not in mapping
    params = {"keywordSearch": product, "resultsPerPage": 10}
    try:
        response = requests.get(NVD_CPE_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        cpe_data = response.json()
        for cpe in cpe_data.get("cpes", []):
            cpe_name = cpe["cpeName"]
            if version in cpe_name:  # Match version for accuracy
                return cpe_name
    except requests.RequestException as e:
        print(f"Error searching CPE for {product}: {e}")
    return None  # Return None if no match found

def check_vulnerabilities(cpe_name):
    """Query NVD for vulnerabilities associated with a CPE name."""
    if not cpe_name:
        return []
    
    params = {"cpeName": cpe_name, "resultsPerPage": 50}
    vulnerabilities = []
    
    try:
        response = requests.get(NVD_VULN_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        vuln_data = response.json()
        
        for vuln in vuln_data.get("vulnerabilities", []):
            cve = vuln["cve"]
            cve_id = cve["id"]
            description = cve["descriptions"][0]["value"]
            severity = "N/A"
            if "cvssMetricV31" in cve["metrics"]:
                severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in cve["metrics"]:
                severity = cve["metrics"]["cvssMetricV2"][0]["severity"]
            
            vulnerabilities.append({
                "cve_id": cve_id,
                "severity": severity,
                "description": description
            })
        time.sleep(0.2)  # Respect NVD API rate limits (5-10 requests/sec with key)
    except requests.RequestException as e:
        print(f"Error querying vulnerabilities for {cpe_name}: {e}")
    
    return vulnerabilities

def scan_target(target_ip):
    """Perform Nmap scan and vulnerability assessment."""
    nm = nmap.PortScanner()
    
    # Run Nmap scan with -A (OS, version, script, traceroute), -T4 (timing), -Pn (no ping)
    print(f"Scanning {target_ip}... (this may take a few minutes)")
    nm.scan(target_ip, arguments='-A -T4 -Pn')
    
    # Check if scan succeeded
    if target_ip not in nm.all_hosts():
        print(f"No response from {target_ip}. Is it up?")
        return
    
    # Parse and display scan results
    host = nm[target_ip]
    print(f"\nHost: {target_ip}")
    print(f"State: {host.state()}")
    
    # OS Detection
    if "osmatch" in host and host["osmatch"]:
        os_info = host["osmatch"][0]
        print(f"OS: {os_info['name']} (Accuracy: {os_info['accuracy']}%)")
    
    # Port and Service Information with Vulnerabilities
    for proto in host.all_protocols():
        print(f"\nProtocol: {proto}")
        ports = host[proto].keys()
        for port in sorted(ports):
            state = host[proto][port]['state']
            if state == "open":
                service = host[proto][port].get('name', 'unknown')
                product = host[proto][port].get('product', 'unknown')
                version = host[proto][port].get('version', '')
                
                print(f"Port: {port}/{proto}")
                print(f"  State: {state}")
                print(f"  Service: {service}")
                print(f"  Product: {product}")
                print(f"  Version: {version}")
                
                # Vulnerability Assessment
                cpe_name = get_cpe_name(product, version)
                if cpe_name:
                    print(f"  CPE Name: {cpe_name}")
                    vulns = check_vulnerabilities(cpe_name)
                    if vulns:
                        print("  Vulnerabilities:")
                        for vuln in vulns:
                            print(f"    CVE: {vuln['cve_id']}")
                            print(f"    Severity: {vuln['severity']}")
                            print(f"    Description: {vuln['description'][:100]}...")  # Truncate for brevity
                    else:
                        print("  No known vulnerabilities found.")
                else:
                    print("  Could not determine CPE name for vulnerability check.")

def main():
    """Main function to run the scanner."""
    print("=== Port Scanner with Vulnerability Assessment ===")
    target_ip = input("Enter target IP address: ")
    
    try:
        scan_target(target_ip)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
