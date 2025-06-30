from utils.logger import logger
import subprocess
import platform

class NetworkMapper:
    def __init__(self):
        self.technique_id = "T1595"
        self.technique_name = "Network Infrastructure Mapping"
        
    def run(self, target):
        results = {
            "dns_info": "",
            "traceroute": "",
            "nmap_scan": "",
            "errors": []
        }
        
        try:
            logger.info(f"Starting network mapping for {target}")
            results["dns_info"] = self.get_dns_info(target)
            results["traceroute"] = self.run_traceroute(target)
            results["nmap_scan"] = self.run_nmap_scan(target)
        except Exception as e:
            logger.error(f"Network mapping failed: {str(e)}")
            results["errors"].append(str(e))
            
        return results

    def get_dns_info(self, target):
        try:
            result = subprocess.run(["nslookup", target], 
                                  capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            logger.error(f"DNS lookup failed: {str(e)}")
            return ""

    def run_traceroute(self, target):
        try:
            cmd = ["tracert"] if platform.system() == "Windows" else ["traceroute"]
            cmd.append(target)
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            logger.error(f"Traceroute failed: {str(e)}")
            return ""

    def run_nmap_scan(self, target):
        try:
            result = subprocess.run(["nmap", "-sS", "-sV", "-O", target],
                                  capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            return ""
