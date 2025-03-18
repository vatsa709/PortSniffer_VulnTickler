# PortSniffer_VulnTickler

# Port Scanner with Vulnerability Assessment

This Python script scans and integrates vulnerability assessment using the National Vulnerability Database (NVD) API. It identifies open ports, detects operating systems, determines service versions, and checks for known vulnerabilities in the identified services.

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
   ```

2. **Install Dependencies**:
   Install the required Python libraries using pip:
   ```bash
   pip install python-nmap requests
   ```

3. **Set Up NVD API Key**:
   Configure your NVD API key as an environment variable (recommended for security):
   - **Linux/Mac**:
     ```bash
     export NVD_API_KEY='your-api-key-here'
     ```
   Alternatively, you can hardcode the API key in the script (less secure):
   ```python
   NVD_API_KEY = 'your-api-key-here'
   ```

## Usage
Here’s how to run and use the script:

1. **Run the Script**:
   Execute the script from the command line:
   ```bash
   python3 port_scanner.py
   ```

2. **Enter Target IP**:
   When prompted, input the IP address you have permission to scan (e.g., `10.10.10.10`).  

3. **View Results**:
   The script will output details about open ports, services, versions, and vulnerabilities.

## Example Output
Here’s what you might see after running the script:
```
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
```

## Acknowledgments
- [Nmap](https://nmap.org/) for its scanning capabilities.
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for providing vulnerability data.
```

### Notes for Use
- **Replace Placeholders**: Update `your-username` and `your-repo-name` in the `git clone` command with your actual GitHub username and repository name.
- **Copy and Paste**: This content is fully formatted and can be directly copied into your `README.md` file without additional edits (aside from the placeholders).

This version ensures a professional, clear, and comprehensive README for your project!
