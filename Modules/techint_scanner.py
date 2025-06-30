from utils.logger import logger
import subprocess

class TechIntScanner:
    def __init__(self):
        self.technique_id = "T1592"
        self.technique_name = "Gather Victim Host Information"
        
    def run(self, target):
        results = {
            "whois_info": "",
            "ssl_cert": "",
            "cdn_info": {},
            "errors": []
        }
        
        try:
            logger.info(f"Starting technical intelligence gathering on {target}")
            results["whois_info"] = self.get_whois(target)
            results["ssl_cert"] = self.get_ssl_cert(target)
            results["cdn_info"] = self.check_cdn(target)
        except Exception as e:
            logger.error(f"Tech int scan failed: {str(e)}")
            results["errors"].append(str(e))
            
        return results

    def get_whois(self, domain):
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
            return ""

    def get_ssl_cert(self, domain):
        try:
            result = subprocess.run(["openssl", "s_client", "-connect", f"{domain}:443"], 
                                  capture_output=True, text=True, timeout=15)
            return result.stdout
        except Exception as e:
            logger.error(f"SSL cert check failed: {str(e)}")
            return ""

    def check_cdn(self, domain):
        try:
            cdn_info = {}
            
            # Ping test
            ping_result = subprocess.run(["ping", "-c", "3", domain], 
                                       capture_output=True, text=True)
            cdn_info["ping"] = ping_result.stdout
            
            # HTTP headers check
            curl_result = subprocess.run(["curl", "-I", domain], 
                                       capture_output=True, text=True)
            cdn_info["headers"] = curl_result.stdout
            
            return cdn_info
        except Exception as e:
            logger.error(f"CDN check failed: {str(e)}")
            return {}
