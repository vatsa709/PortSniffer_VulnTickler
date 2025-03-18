# PortSniffer_VulnTickler

# Port Scanner with Vulnerability Assessment

This Python script performs aggressive scan and integrates vulnerability assessment using the National Vulnerability Database (NVD) API. It identifies open ports, detects operating systems, determines service versions, and checks for known vulnerabilities in the identified services.

## Features
- **Port Scanning**: Identifies open, closed, or filtered TCP and UDP ports.
- **OS Detection**: Determines the operating system of the target host.
- **Service Version Detection**: Identifies the software running on open ports and their versions.
- **Vulnerability Assessment**: Checks for known vulnerabilities in the identified services using the NVD API.
- **User-Friendly Output**: Provides detailed reports on open ports, services, versions, and vulnerabilities.

## Prerequisites
Before using this tool, ensure you have the following:
- **Python 3.x**: Install Python from [python.org](https://www.python.org/downloads/) if it’s not already on your system.
- **Nmap**: Download and install Nmap from [nmap.org](https://nmap.org/download.html) and ensure it’s added to your system’s PATH.
- **NVD API Key**: Request a free API key from [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key).

## Installation
Follow these steps to set up the project on your machine:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/PortSniffer_VulnTickler.git
   cd PortSniffer_VulnTickler
2. Install Dependencies: Install the required Python libraries using pip:
pip install python-nmap requests

3. Set Up NVD API Key: 
set NVD_API_KEY=your-api-key-here

Usage
Here’s how to run and use the script:

Run the Script: Execute the script from the command line:

python3 port_scanner.py
Enter Target IP: When prompted, input the IP address you have permission to scan (e.g., 192.168.1.1).

View Results: The script will output details about open ports, services, versions, and vulnerabilities.
Example Output

Here’s what you might see after running the script: 
=== Port Scanner with Vulnerability Assessment ===
Enter target IP address: 10.10.10.10
Scanning 10.10.10.10... (this may take a few minutes)

Host: 10.10.10.10
State: up
OS: Linux 2.6.X (Accuracy: 95%)

Protocol: tcp
Port: 80/tcp
  State: open
  Service: http
  Product: Apache httpd
  Version: 2.4.51
  CPE Name: cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*
  Vulnerabilities:
    CVE: CVE-2021-44228
    Severity: CRITICAL
    Description: Apache Log4j2 vulnerability allowing remote code execution...
