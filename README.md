# ReCon - MITRE Reconnaissance Tool

ReCon is an automated reconnaissance framework designed to assist security professionals and ethical hackers in gathering information about target systems and organizations. It maps various reconnaissance techniques to the MITRE ATT&CK framework, providing a structured approach to intelligence gathering.

## Features

-   **Modular Design**: Easily extendable with new reconnaissance modules.
-   **MITRE ATT&CK Mapping**: Each module is mapped to relevant MITRE ATT&CK techniques.
-   **Flexible Targeting**: Supports both domain names and IP addresses as targets.
-   **Selective Module Execution**: Run specific modules or all available modules.
-   **Report Generation**: Generate comprehensive reports in JSON or HTML format.
-   **Individual Module Reports**: Option to save reports for each module separately.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/d4rks0u1/ReCon.git
    cd ReCon
    ```

2.  **Install dependencies**:
    It is recommended to use a virtual environment.
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    
    pip install -r requirements.txt
    ```
    **Note**: Some modules, like `nmap`, require external tools to be installed on your system. Ensure Nmap is installed and accessible in your PATH for the Nmap module to function correctly.

## Usage

ReCon is a command-line tool.

### Basic Usage

```bash
python main.py <target> [options]
```

### Arguments

-   `<target>`: The target IP address or domain (e.g., `example.com` or `192.168.1.1`). This is a required argument unless you are only displaying the help menu.

### Options

-   `-m, --modules <module1> [module2 ...]`: Specify one or more modules to run (e.g., `whois dns nmap`). Use `all` to run all available modules (this is the default behavior if no modules are specified).
-   `-f, --format {json,html}`: Choose the output report format. Options are `json` or `html`. The default is `json`.
-   `-s, --save-individual`: Use this flag to save individual module reports in addition to the overall consolidated report.
-   `--help-menu`: Display a detailed help menu with usage examples and module descriptions.
-   `-h, --help`: Show a basic help message and exit.

### Available Modules

-   `whois`: Performs WHOIS lookups for domains/IPs.
-   `subdomain`: Enumerates subdomains for a given domain.
-   `dns`: Gathers DNS information (A, MX, NS, TXT records).
-   `nmap`: Performs Nmap scans (requires Nmap to be installed on your system).
-   `github`: Conducts GitHub dorking to find sensitive information.
-   `shodan`: Queries Shodan for target information (requires a Shodan API key configured).

### Examples

1.  **Run all modules on a domain, save JSON report (default behavior)**:
    ```bash
    python main.py example.com
    ```

2.  **Run only the Nmap scan on an IP address**:
    ```bash
    python main.py 192.168.1.1 -m nmap
    ```

3.  **Run WHOIS and DNS modules on a domain, save individual and overall HTML reports**:
    ```bash
    python main.py example.com -m whois dns -f html -s
    ```

4.  **Display the detailed help menu**:
    ```bash
    python main.py --help-menu
    ```

## Reporting

All reconnaissance results are consolidated into an overall report. You can choose between JSON and HTML formats. If `--save-individual` is specified, each module's results will also be saved as separate reports. Reports are typically saved in a `reports/` directory within the tool's root.

## Author

-   github.com/d4rks0u1
