from utils.logger import logger

class IdentityScanner:
    def __init__(self):
        self.technique_id = "T1589"
        self.technique_name = "Gather Victim Identity Information"
        
    def run(self, target):
        """Main method to run the identity scanning module"""
        results = {
            "emails": [],
            "usernames": [],
            "names": [],
            "errors": []
        }
        
        try:
            logger.info(f"Starting identity scan for {target}")
            results.update(self.scan_web_content(target))
            results.update(self.check_whois(target))
            logger.info("Identity scan completed successfully")
        except Exception as e:
            logger.error(f"Identity scan failed: {str(e)}")
            results["errors"].append(str(e))
            
        return results

    def scan_web_content(self, url):
        """Scan web content for personal identifiers"""
        import re
        import requests
        
        results = {}
        try:
            response = requests.get(url, timeout=10)
            content = response.text

            results["emails"] = list(set(re.findall(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)))
                
            results["usernames"] = list(set(re.findall(
                r"user(?:name)?[\"':\s=]{1,5}([a-zA-Z0-9_]+)", content)))
                
            results["names"] = list(set(re.findall(
                r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", content)))

        except Exception as e:
            logger.error(f"Web content scan failed: {str(e)}")
            
        return results

    def check_whois(self, domain):
        """Perform WHOIS lookup for domain registration info"""
        import subprocess
        
        try:
            result = subprocess.run(["whois", domain], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=15)
            return {"whois_info": result.stdout}
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
            return {"whois_info": "", "errors": [str(e)]}
