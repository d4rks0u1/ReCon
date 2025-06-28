import subprocess
import json
from utils.logger import logger

class SubdomainEnumeration:
    """
    Performs subdomain enumeration using external tools like subfinder.
    MITRE ATT&CK Technique: T1590.002 - Gather Victim Network Information: DNS
    """
    def __init__(self):
        self.technique_id = "T1590.002"
        self.technique_name = "Subdomain Enumeration"
        logger.info(f"Initialized {self.technique_name} module ({self.technique_id})")

    def run(self, target):
        """
        Executes subdomain enumeration using subfinder.
        :param target: The domain to enumerate subdomains for.
        :return: A dictionary containing enumerated subdomains.
        """
        logger.info(f"Performing subdomain enumeration for target: {target}")
        results = {
            "target": target,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "data": [],
            "error": None
        }
        try:
            # Ensure subfinder is installed and in PATH
            # You might need to install it: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            command = ["subfinder", "-d", target, "-silent"]
            process = subprocess.run(command, capture_output=True, text=True, check=True)
            subdomains = process.stdout.strip().split('\n')
            subdomains = [s for s in subdomains if s] # Filter out empty strings
            results["data"] = subdomains
            logger.info(f"Subdomain enumeration successful for {target}. Found {len(subdomains)} subdomains.")
        except FileNotFoundError:
            results["error"] = "subfinder not found. Please install it and ensure it's in your PATH."
            logger.error(results["error"])
        except subprocess.CalledProcessError as e:
            results["error"] = f"subfinder command failed: {e.stderr.strip()}"
            logger.error(f"Error during subdomain enumeration for {target}: {e.stderr.strip()}")
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Error during subdomain enumeration for {target}: {e}")
        return results

if __name__ == "__main__":
    # Example Usage
    sub_enum_scanner = SubdomainEnumeration()
    target_domain = "example.com" # Replace with a domain you have permission to test

    enum_results = sub_enum_scanner.run(target_domain)
    print(f"\n--- Subdomain Enumeration Results for {target_domain} ---")
    print(json.dumps(enum_results, indent=4))
