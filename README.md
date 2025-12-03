# Vulnerability Scanner

A Python-based network vulnerability scanner that identifies open ports, detects service versions, and matches them against known CVEs from the National Vulnerability Database.

> [!WARNING]
>This tool should only be used on systems you own or have permission to test. Unauthorized scanning may be illegal in your jurisdiction.

## Description

**What it does:**

This vulnerability scanner performs automated security assessments of network targets. It scans for open ports, identifies running services and their versions, then cross-references this information against a database of known vulnerabilities from the National Vulnerability Database (NVD). The tool generates detailed reports showing which services are vulnerable, their severity levels, and recommended mitigations.

**How it works:**

1. Scans the target system using nmap to identify open ports
2. Detects service versions from banner information and service fingerprints
3. Loads the local CVE database and matches discovered services against known vulnerabilities
4. Calculates risk scores based on vulnerability severity (Critical, High, Medium, Low)
5. Generates comprehensive reports in multiple formats (console, JSON, CSV, or web dashboard)

**Key Features:**

- Port scanning with automatic service detection
- Version-based CVE matching against NVD database
- Risk scoring and severity-based prioritization
- Multiple interfaces: Command-line, REST API, and Web Dashboard
- Offline scanning capability after initial database setup
- Support for custom port ranges

## Getting Started

### Dependencies

* Python 3.10 or higher
* nmap (system package - must be installed separately)
* Operating System: Windows 10/11, macOS, or Linux
* Internet connection (required only for initial CVE database setup)

Python packages (installed via requirements.txt):
* requests - For NVD API communication
* python-nmap - Port scanning integration
* packaging - Version comparison
* pandas - Data handling
* flask - REST API framework
* flask-cors - API cross-origin support
* streamlit - Web dashboard framework

### Installing

**Step 1: Install nmap**

nmap must be installed on your system before using this scanner.

*Windows:*
1. Download installer from https://nmap.org/download.html
2. Run installer and follow prompts
3. Verify installation: `nmap --version`

*macOS:*
```bash
brew install nmap
```

*Linux (Ubuntu/Debian):*
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Step 2: Install Python dependencies**

```bash
pip install -r requirements.txt
```

**Step 3: Generate CVE Database**

This step is required before first use. The script fetches vulnerability data from the National Vulnerability Database and saves it locally.

```bash
python scripts/fetch_nvd.py
```

This process takes approximately a minute, due to NVD API rate limiting. It creates a file `data/cve_database.csv` containing 25 recent CVEs for common services (OpenSSH, Apache, nginx, MySQL, vsftpd, ProFTPD).

### Executing program

The scanner provides three interfaces: Command-Line, REST API, and Web Dashboard.

#### Command Line Interface

Basic scan with default ports:
```bash
python cli.py --target 127.0.0.1
```

Scan specific ports:
```bash
python cli.py --target 127.0.0.1 --ports 22,80,443,3306
```

Save results to JSON file:
```bash
python cli.py --target 127.0.0.1 --output json --file results.json
```

Save results to CSV file:
```bash
python cli.py --target 127.0.0.1 --output csv --file results.csv
```

*Note: Output files are automatically saved to the `outputs/` directory.*

#### REST API

Start the API server:
```bash
python -m api.app
```

The API will be available at `http://127.0.0.1:5000`

Check API health:
```bash
curl http://127.0.0.1:5000/health
```

Get API information:
```bash
curl http://127.0.0.1:5000/
```

Perform a scan:
```bash
curl -X POST http://127.0.0.1:5000/scan -H "Content-Type: application/json" -d "{\"target\": \"127.0.0.1\"}"
```

The API returns results in JSON format including open ports, vulnerabilities found, and risk assessment.

#### Web Dashboard

Start the dashboard:
```bash
python -m streamlit run dashboard/app.py
```

The dashboard will automatically open in your browser at `http://localhost:8501`

Features:
- Enter target IP address in the center input field
- Optional: Enable custom ports and specify which ports to scan
- Click "Scan" button to begin analysis
- View results with visual charts and interactive tables
- Risk assessment displays overall risk level and score
- Severity distribution shown as bar chart
- Open ports and vulnerabilities displayed in sortable tables

#### Testing

Run all unit tests:
```bash
python -m unittest discover tests
```

Run specific test file:
```bash
python -m unittest tests/test_version_matcher.py
```

Tests verify:
- Version range parsing and comparison logic
- IP address validation
- Service name normalization
- CVE matching accuracy
## Configuration

The scanner can be customized by modifying configuration parameters in the source files.

### CVE Database Settings

**File:** `scripts/fetch_nvd.py`

**Customize CVE collection:**
```python
# Line 116: Modify services and CVE count per service
services = [
    ('OpenSSH', 5),
    ('Apache HTTP', 5),
    ('nginx', 4),
    ('MySQL', 5),
    ('vsftpd', 3),
    ('ProFTPD', 3)
   ]
```

> [!TIP]
> Increase the numbers to fetch more CVEs per service, or add new services to the list. Note that fetching more CVEs will increase database generation time due to API rate limiting.

### Default Scan Ports

**File:** `scanner/port_scanner.py`

**Customize default ports:**
```python
# Line 9: Modify the default port list
DEFAULT_PORTS = [21, 22, 80, 443, 3306, 3389, 5432, 8080]
```

Common port additions:
- `21` - FTP
- `22` - SSH
- `23` - Telnet
- `25` - SMTP
- `53` - DNS
- `110` - POP3
- `143` - IMAP
- `443` - HTTPS
- `3306` - MySQL
- `3389` - RDP
- `5432` - PostgreSQL
- `8080` - HTTP Alt

> [!NOTE]
> Adding more ports increases scan time proportionally. For faster scans, reduce the port list or use the `--ports` CLI option.

### Risk Scoring Weights

**File:** `scanner/risk_scorer.py`

**Customize severity weights:**
```python
# Line 6: Modify severity point values
SEVERITY_WEIGHTS = {
    'LOW': 1,
    'MEDIUM': 3,
    'HIGH': 5,
    'CRITICAL': 8,
    'Unknown': 2
}
```

**Customize risk level thresholds:**
```python
# Line 52: Modify risk level ranges
def get_risk_level(total_score):
    if total_score == 0:
        return 'No vulnerabilities found'
    elif total_score <= 5:
        return 'Low Risk'
    elif total_score <= 15:
        return 'Medium Risk'
    elif total_score <= 30:
        return 'High Risk'
    else:
        return 'Critical Risk'
```

> [!TIP]
> Adjust these values to make risk assessment more or less sensitive based on your security requirements.

### Scan Timeout Settings

**File:** `scanner/port_scanner.py`

**Customize nmap timing:**
```python
# Line 41: Modify nmap arguments
    network_scanner.scan(target_ip, ports_string, arguments='-sV -T4')
# -T4 is aggressive timing (faster but more detectable)
# -T3 is normal timing (balanced)
# -T2 is polite timing (slower but stealthier)
```

> [!CAUTION]
> Aggressive timing (-T5, -T4) is faster but more likely to be detected by intrusion detection systems. Use polite timing (-T2, -T1) for stealth, but expect longer scan times.

## Help

**Problem: "CVE database not found"**

*Solution:* Run the database generation script:
```bash
python scripts/fetch_nvd.py
```

**Problem: "Nmap error: nmap program was not found in path"**

*Solution:* Install nmap on your system. See the Installing section for platform-specific instructions.

**Problem: "Permission denied" when scanning**

*Solution:* Some ports require elevated privileges. Run as administrator on Windows, or use `sudo` on Linux/macOS.

**Problem: "ModuleNotFoundError: No module named 'scanner'"**

*Solution:* Ensure you're running commands from the project root directory. For API and Dashboard, use the module syntax:
```bash
python -m api.app
python -m streamlit run dashboard/app.py
```

**Problem: No vulnerabilities found**

This may indicate:
- The target has no open ports in the scanned range
- Services running don't match CVEs in the database
- A firewall is blocking the scan
- Services are running but version detection failed

> [!TIP]
> Specify fewer ports using the `--ports` option to speed up scanning if no services are found.

## Project Structure

```
vulnerability-scanner/
├── api/
│   ├── __init__.py
│   └── app.py              # Flask REST API
├── dashboard/
│   ├── __init__.py
│   └── app.py              # Streamlit web interface
├── data/
│   ├── __init__.py
│   └── cve_database.csv    # CVE database (generated)
├── outputs/                # Scan results saved here
├── scanner/
│   ├── __init__.py
│   ├── cve_loader.py       # Loads and filters CVE database
│   ├── main_scanner.py     # Orchestrates scan workflow
│   ├── port_scanner.py     # Nmap integration and port scanning
│   ├── risk_scorer.py      # Calculates risk scores
│   └── version_matcher.py  # Version comparison logic
├── scripts/
│   ├── __init__.py
│   └── fetch_nvd.py        # Downloads CVE data from NVD
├── tests/
│   ├── __init__.py
│   ├── test_validators.py
│   └── test_version_matcher.py
├── cli.py                  # Command-line interface
├── requirements.txt        # Python dependencies
├── .gitignore
└── README.md
```

## Author

Illia Ivanov 

Fort Hays State University

INF601 - Advanced Programming with Python