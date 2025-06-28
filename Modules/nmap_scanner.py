import nmap
import json
from utils.logger import logger

class NmapScanner:
    """
    Performs Nmap scans for a given target.
    MITRE ATT&CK Technique: T1595.002 - Active Scanning: Vulnerability Scanning
    """
    def __init__(self):
        self.technique_id = "T1595.002"
        self.technique_name = "Nmap Scan"
        self.nm = nmap.PortScanner()
        logger.info(f"Initialized {self.technique_name} module ({self.technique_id})")

    def run(self, target, arguments="-sV -O"):
        """
        Executes an Nmap scan.
        :param target: The IP address or hostname to scan.
        :param arguments: Nmap arguments (e.g., "-sV -O" for service version and OS detection).
        :return: A dictionary containing Nmap scan results.
        """
        logger.info(f"Performing Nmap scan for target: {target} with arguments: {arguments}")
        results = {
            "target": target,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "data": {},
            "error": None
        }
        try:
            self.nm.scan(target, arguments=arguments)
            scan_results = {}
            for host in self.nm.all_hosts():
                # Get addresses safely
                addresses = {}
                try:
                    if hasattr(self.nm[host], 'all_addresses'):
                        addresses = self.nm[host].all_addresses()
                    else:
                        # Fallback to get addresses from the host key itself
                        addresses = {"ipv4": host}
                except:
                    addresses = {"ipv4": host}
                
                host_info = {
                    "status": self.nm[host].state(),
                    "addresses": addresses,
                    "hostnames": self.nm[host].hostnames(),
                    "os_match": self.nm[host].get('osmatch', []),
                    "ports": {}
                }
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        host_info["ports"][f"{port}/{proto}"] = self.nm[host][proto][port]
                scan_results[host] = host_info
            results["data"] = scan_results
            logger.info(f"Nmap scan successful for {target}")
        except nmap.PortScannerError as e:
            results["error"] = f"Nmap scan failed: {e}"
            logger.error(f"Nmap scan failed for {target}: {e}")
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Error during Nmap scan for {target}: {e}")
        return results

if __name__ == "__main__":
    # Example Usage
    nmap_scanner = NmapScanner()
    target_ip = "127.0.0.1" # Replace with an IP you have permission to scan

    scan_results = nmap_scanner.run(target_ip, arguments="-F") # -F for fast scan
    print(f"\n--- Nmap Scan Results for {target_ip} ---")
    print(json.dumps(scan_results, indent=4))
