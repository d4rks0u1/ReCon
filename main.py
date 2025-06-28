import argparse
import os
import sys
from colorama import Fore, Style, init
import pyfiglet

# Ensure modules and utils are in path for direct execution or testing
# In a proper package, this might be handled differently (e.g., pip install -e .)
sys.path.append(os.path.join(os.path.dirname(__file__), 'Modules'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

from utils.logger import logger
from utils.reporter import save_report, generate_overall_report
from Modules import WhoisLookup, SubdomainEnumeration, DNSInformation, NmapScanner, GitHubDorking, ShodanQuery

init(autoreset=True) # Initialize Colorama

def show_banner():
    banner = pyfiglet.figlet_format("ReCon", font="slant")
    print(Fore.CYAN + banner)
    print(Fore.GREEN + "MITRE Recon Tool - Offensive Reconnaissance Framework")
    print(Fore.YELLOW + "Author: github.com/d4rks0u1" + Style.RESET_ALL)

def show_help_menu():
    print(Fore.GREEN + "\n--- ReCon Help Menu ---" + Style.RESET_ALL)
    print(Fore.YELLOW + "Usage: python main.py <target> [options]" + Style.RESET_ALL)
    print("\n" + Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("  <target>              Target IP address or domain (e.g., example.com or 192.168.1.1)")

    print("\n" + Fore.CYAN + "Options:" + Style.RESET_ALL)
    print("  -m, --modules <module1> [module2 ...]  Specify modules to run (e.g., whois dns nmap).")
    print("                                         Use 'all' to run all available modules (default).")
    print("  -f, --format {json,html}               Output report format (json or html). Default is 'json'.")
    print("  -s, --save-individual                  Save individual module reports in addition to the overall report.")
    print("  --help-menu                            Display this detailed help menu.")
    print("  -h, --help                             Show basic help message and exit.")

    print("\n" + Fore.CYAN + "Available Modules:" + Style.RESET_ALL)
    print("  whois       - Performs WHOIS lookups for domains/IPs.")
    print("  subdomain   - Enumerates subdomains for a given domain.")
    print("  dns         - Gathers DNS information (A, MX, NS, TXT records).")
    print("  nmap        - Performs Nmap scans (requires Nmap to be installed).")
    print("  github      - Conducts GitHub dorking to find sensitive information.")
    print("  shodan      - Queries Shodan for target information (requires Shodan API key).")

    print("\n" + Fore.CYAN + "Examples:" + Style.RESET_ALL)
    print("  " + Fore.WHITE + "python main.py example.com" + Style.RESET_ALL)
    print("    Run all modules on example.com, save JSON report.")
    print("  " + Fore.WHITE + "python main.py 192.168.1.1 -m nmap" + Style.RESET_ALL)
    print("    Run only Nmap scan on 192.168.1.1.")
    print("  " + Fore.WHITE + "python main.py example.com -m whois dns -f html -s" + Style.RESET_ALL)
    print("    Run WHOIS and DNS modules on example.com, save individual and overall HTML reports.")
    print("  " + Fore.WHITE + "python main.py --help-menu" + Style.RESET_ALL)
    print("    Display this detailed help menu.")
    print("\n" + Fore.GREEN + "For more information, visit: github.com/d4rks0u1" + Style.RESET_ALL)

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Tool mapping to MITRE ATT&CK techniques.", add_help=False)
    parser.add_argument("target", nargs='?', help="Target IP address or domain (e.g., example.com or 192.168.1.1)")
    parser.add_argument("-m", "--modules", nargs='+', default=["all"],
                        help="Specify modules to run (e.g., whois dns nmap). Use 'all' for all modules.")
    parser.add_argument("-f", "--format", choices=["json", "html"], default="json",
                        help="Output report format (json or html).")
    parser.add_argument("-s", "--save-individual", action="store_true",
                        help="Save individual module reports in addition to the overall report.")
    parser.add_argument("--help-menu", action="store_true",
                        help=argparse.SUPPRESS) # Hide from default help

    # Add standard -h/--help
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show basic help message and exit.')

    args = parser.parse_args()

    if args.help_menu:
        show_help_menu()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target
    modules_to_run = args.modules
    report_format = args.format
    save_individual_reports = args.save_individual

    target = args.target
    modules_to_run = args.modules
    report_format = args.format
    save_individual_reports = args.save_individual

    logger.info(f"Starting reconnaissance for target: {target}")
    logger.info(f"Modules selected: {', '.join(modules_to_run)}")
    logger.info(f"Report format: {report_format}")

    available_modules = {
        "whois": WhoisLookup(),
        "subdomain": SubdomainEnumeration(),
        "dns": DNSInformation(),
        "nmap": NmapScanner(),
        "github": GitHubDorking(),
        "shodan": ShodanQuery()
    }

    all_results = {}

    if "all" in modules_to_run:
        modules_to_run = available_modules.keys()

    for module_name in modules_to_run:
        if module_name in available_modules:
            module_instance = available_modules[module_name]
            logger.info(f"Running module: {module_instance.technique_name} ({module_instance.technique_id})")
            
            # Special handling for modules that might need different arguments or target types
            if module_name == "github":
                # GitHub dorking typically targets organizations or domains, not IPs
                # For simplicity, we'll pass the main target, but a more robust solution
                # might require separate input for GitHub dorking.
                module_results = module_instance.run(target)
            elif module_name == "shodan":
                # Shodan queries can be complex; for now, we'll query the target directly
                # A more advanced implementation might allow custom Shodan queries via CLI
                module_results = module_instance.run(target)
            else:
                module_results = module_instance.run(target)
            
            all_results[module_name] = module_results
            
            if save_individual_reports:
                save_report(module_results, target, module_name, report_format)
            
            if module_results.get("error"):
                logger.error(f"Module {module_name} completed with errors: {module_results['error']}")
            else:
                logger.info(f"Module {module_name} completed successfully.")
        else:
            logger.warning(f"Unknown module specified: {module_name}. Skipping.")

    if all_results:
        logger.info("Generating overall report...")
        overall_report_path = generate_overall_report(all_results, target, report_format)
        if overall_report_path:
            print(Fore.GREEN + f"\nOverall report saved to: {overall_report_path}" + Style.RESET_ALL)
    else:
        logger.warning("No modules were run, no overall report generated.")

    logger.info("Reconnaissance complete.")

if __name__ == "__main__":
    main()
