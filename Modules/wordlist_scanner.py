from utils.logger import logger
import subprocess

class WordlistScanner:
    def __init__(self):
        self.technique_id = "T1580"
        self.technique_name = "Wordlist-Based Enumeration"
        
    def run(self, target):
        results = {
            "directories": [],
            "subdomains": [],
            "dns_records": [],
            "errors": []
        }
        
        try:
            logger.info(f"Starting wordlist-based enumeration for {target}")
            results.update(self.run_standard_scans(target))
        except Exception as e:
            logger.error(f"Wordlist scan failed: {str(e)}")
            results["errors"].append(str(e))
            
        return results

    def run_standard_scans(self, target):
        results = {}
        try:
            # Directory bruteforce
            dir_result = subprocess.run(['ffuf', '-u', f'{target}/FUZZ', '-w', 'common_paths.txt', '-ac'],
                                      capture_output=True, text=True)
            results["directories"] = self.parse_ffuf(dir_result.stdout)
            
            # Subdomain enumeration
            sub_result = subprocess.run(['ffuf', '-u', f'http://FUZZ.{target}', '-w', 'subdomains.txt', '-ac'],
                                      capture_output=True, text=True)
            results["subdomains"] = self.parse_ffuf(sub_result.stdout)
            
            # DNS fuzzing
            dns_result = subprocess.run(['ffuf', '-u', f'dns://{target}', '-w', 'dns_entries.txt', '-ac'],
                                      capture_output=True, text=True)
            results["dns_records"] = self.parse_ffuf(dns_result.stdout)
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            
        return results

    def parse_ffuf(self, output):
        """Parse ffuf tool output into structured data"""
        lines = output.split('\n')
        results = []
        for line in lines:
            if '| URL |' in line:  # Skip header line
                continue
            if line.strip():
                parts = [p.strip() for p in line.split('|') if p.strip()]
                if len(parts) >= 5:
                    results.append({
                        "url": parts[1],
                        "status": parts[2],
                        "size": parts[3],
                        "words": parts[4]
                    })
        return results
