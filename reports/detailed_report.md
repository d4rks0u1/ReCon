# ReCon Tool Technical Analysis Report (24-Page Structure)

## 1. Project Architecture Overview
```bash
ReCon/
├── main.py                # Main entry point
├── config.py              # Configuration settings
├── requirements.txt       # Dependencies
├── Modules/               # Core reconnaissance components
│   ├── __init__.py
│   ├── dns_info.py
│   ├── github_dorking.py
│   ├── nmap_scanner.py
│   ├── whois_lookup.py
│   └── Port Scanner/
│       └── app.py
├── utils/                 # Support utilities
│   ├── logger.py
│   └── reporter.py
└── reports/               # Generated output files

## 2. Core Utility Implementations

### 2.1 Logging System (utils/logger.py)
```python
import logging
import os
from config import LOG_FILE, LOG_LEVEL

def setup_logging():
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()
```

### 2.2 Reporting System (utils/reporter.py)
```python
def save_report(data, target, module_name, format="json"):
    # Handles report generation in JSON/HTML formats
    # Creates standardized filenames with timestamps
    # Implements error handling for file operations
    
def generate_overall_report(all_results, target, format="json"):
    # Aggregates module results into comprehensive report
    # Generates HTML with styled output for readability
    # Maintains consistent formatting across modules
```

## 3. Core Module Implementations

### 3.1 WHOIS Lookup Module (Modules/whois_lookup.py)
```python
import whois
import json
from utils.logger import logger

class WhoisLookup:
    """
    Performs WHOIS lookups for a given domain or IP address.
    MITRE ATT&CK Technique: T1591.002 - Gather Victim Org Information
    """
    def __init__(self):
        self.technique_id = "T1591.002"
        self.technique_name = "WHOIS Lookup"
        logger.info(f"Initialized {self.technique_name} module ({self.technique_id})")

    def run(self, target):
        """
        Executes the WHOIS lookup.
        Returns structured data including:
        - Domain registration details
        - Registrar information
        - Nameservers
        - Contact information
        """
        results = {
            "target": target,
            "technique_id": self.technique_id,
            "data": {},
            "error": None
        }
        try:
            w = whois.whois(target)
            results["data"] = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "name_servers": w.name_servers,
                "org": w.org,
                "country": w.country
            }
        except Exception as e:
            results["error"] = str(e)
        return results
```

### 3.2 Port Scanner Implementation (Modules/Port Scanner/app.py)
```python
import nmap
from utils.logger import logger

class NmapScanner:
    """
    Network port scanning using Nmap
    MITRE ATT&CK Technique: T1046 - Network Service Discovery
    """
    def __init__(self):
        self.technique_id = "T1046"
        self.scanner = nmap.PortScanner()
        
    def run(self, target):
        """
        Performs comprehensive port scan:
        1. TCP SYN Scan (-sS)
        2. Service Version Detection (-sV)
        3. OS Fingerprinting (-O)
        4. Outputs results in parseable format
        """
        logger.info(f"Starting Nmap scan on {target}")
        scan_results = self.scanner.scan(
            hosts=target,
            arguments='-sS -sV -O -T4'
        )
        return {
            "target": target,
            "technique_id": self.technique_id,
            "open_ports": scan_results['scan'][target]['tcp'],
            "os_guess": scan_results['scan'][target]['osmatch'][0]['name'],
            "scan_stats": scan_results['nmap']['scanstats']
        }
```

### 3.3 DNS Information Module (Modules/dns_info.py)
```python
import dns.resolver
import dns.reversename
from utils.logger import logger

class DNSInformation:
    """
    Collects DNS records and performs reverse lookups
    MITRE ATT&CK Technique: T1590.002 - Network Information Discovery
    """
    def __init__(self):
        self.technique_id = "T1590.002"
        self.record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

    def run(self, target):
        """
        Executes DNS reconnaissance:
        - Queries multiple record types
        - Handles reverse DNS lookups for IPs
        - Implements error handling for failed queries
        """
        results = {
            "target": target,
            "technique_id": self.technique_id,
            "data": {}
        }
        
        try:
            if self._is_ip(target):
                ptr = self._reverse_lookup(target)
                results["data"]["PTR"] = ptr if ptr else "Not found"
            else:
                for rt in self.record_types:
                    records = self._query(target, rt)
                    results["data"][rt] = records if records else "No records"
        except Exception as e:
            logger.error(f"DNS module error: {e}")
            
        return results

    # Helper methods would follow...
```

## 4. Utility Module Deep Dives

### 4.1 logger.py Analysis
**Explanation of the Code**  
Central logging system handling both file and console output with configurable levels.

🔑 **Key Imports**
```python
import logging
import os
from config import LOG_FILE, LOG_LEVEL
```

🧠 **Code Breakdown**
1. **Initialization**
```python
def setup_logging():
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
    )
    return logging.getLogger(__name__)
```
- Dynamically sets log level from config
- Uses dual handlers for file and console logging
- Standardizes log format across modules

2. **Usage**
```python
logger = setup_logging()
logger.info("Initialized logging system")
```
- Provides singleton logger instance
- Used across all modules for consistent logging

### 4.2 reporter.py Analysis
**Explanation of the Code**  
Report generation system supporting JSON/HTML formats with timestamped filenames.

🔑 **Key Imports**
```python
import json
import os
from datetime import datetime
from config import REPORT_DIR
```

🧠 **Code Breakdown**
1. **File Handling**
```python
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)
```
- Ensures report directory exists
- Creates nested directories if needed

2. **HTML Generation**
```python
html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        pre {{ background-color: #eee; padding: 10px; }}
    </style>
</head>
<body>
    <pre>{json.dumps(data, indent=4)}</pre>
</body>
</html>'''
```
- Creates responsive HTML templates
- Embeds JSON data with syntax highlighting
- Uses CSS for readable formatting

## 5. Main Entry Point Analysis

### 5.1 main.py Deep Dive
**Explanation of the Code**  
Orchestrates reconnaissance workflow and handles CLI interactions. Coordinates module execution and report generation.

🔑 **Key Imports**
```python
import argparse       # Command-line argument parsing
import pyfiglet       # ASCII banner generation
from Modules import WhoisLookup, SubdomainEnumeration, DNSInformation
from utils.logger import logger  # Centralized logging
```

🧠 **Code Breakdown**
1. **Path Configuration**
```python
sys.path.append(os.path.join(os.path.dirname(__file__), 'Modules'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
```
- Ensures module imports work from different execution contexts
- Dynamically adds project directories to Python path

2. **User Interface**
```python
def show_banner():
    banner = pyfiglet.figlet_format("ReCon", font="slant")
    print(Fore.CYAN + banner + Style.RESET_ALL)

def show_help_menu():
    print(Fore.GREEN + "\n--- ReCon Help Menu ---")
    print("Usage: python main.py <target> [options]")
```
- Creates branded ASCII art banner
- Implements color-coded help system using Colorama

3. **Argument Parsing**
```python
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("target", nargs='?', help="Target IP/domain")
parser.add_argument("-m", "--modules", nargs='+', default=["all"],
                    help="Modules to execute")
parser.add_argument("-f", "--format", choices=["json", "html"],
                    default="json", help="Report format")
```
- Configures CLI options with help texts
- Supports module selection and output formats
- Implements custom help command with --help-menu

4. **Module Execution**
```python
available_modules = {
    "whois": WhoisLookup(),
    "subdomain": SubdomainEnumeration(),
    "dns": DNSInformation(),
    "nmap": NmapScanner(),
    "github": GitHubDorking(),
    "shodan": ShodanQuery()
}

if "all" in modules_to_run:
    modules_to_run = available_modules.keys()
```
- Maps module names to class instances
- Handles "all" keyword to run complete reconnaissance
- Implements special handling for API-dependent modules

5. **Reporting System**
```python
if save_individual_reports:
    save_report(module_results, target, module_name, report_format)

overall_report_path = generate_overall_report(all_results, target, report_format)
```
- Generates timestamped report filenames
- Supports concurrent JSON/HTML output formats
- Maintains consistent formatting across modules

## 6. MITRE ATT&CK Mapping Table
| Module            | Technique ID    | Tactic          | Description                                                                 |
|-------------------|-----------------|-----------------|-----------------------------------------------------------------------------|
| WHOIS Lookup      | T1591.002       | Reconnaissance  | Gathers organizational info through domain registration records            |
| DNS Enumeration   | T1590.002       | Discovery       | Maps network infrastructure via DNS record analysis                        |
| Nmap Scanning     | T1046           | Discovery       | Identifies active services and network vulnerabilities                     |
| GitHub Dorking    | T1593.001       | Reconnaissance  | Discovers sensitive info in version control systems                        |
| Shodan Query      | T1596           | Reconnaissance  | Leverages IoT search engine to identify internet-exposed assets            |
