import whois
import json
from utils.logger import logger

class WhoisLookup:
    """
    Performs WHOIS lookups for a given domain or IP address.
    MITRE ATT&CK Technique: T1591.002 - Gather Victim Org Information: Identify Business Relationships
    """
    def __init__(self):
        self.technique_id = "T1591.002"
        self.technique_name = "WHOIS Lookup"
        logger.info(f"Initialized {self.technique_name} module ({self.technique_id})")

    def run(self, target):
        """
        Executes the WHOIS lookup.
        :param target: The domain or IP address to lookup.
        :return: A dictionary containing WHOIS information.
        """
        logger.info(f"Performing WHOIS lookup for target: {target}")
        results = {
            "target": target,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "data": {},
            "error": None
        }
        try:
            w = whois.whois(target)
            if w:
                results["data"] = {
                    "domain_name": w.domain_name,
                    "registrar": w.registrar,
                    "whois_server": w.whois_server,
                    "referral_url": w.referral_url,
                    "updated_date": str(w.updated_date),
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers": w.name_servers,
                    "emails": w.emails,
                    "org": w.org,
                    "address": w.address,
                    "city": w.city,
                    "state": w.state,
                    "zipcode": w.zipcode,
                    "country": w.country
                }
                logger.info(f"WHOIS lookup successful for {target}")
            else:
                results["error"] = "No WHOIS data found or domain does not exist."
                logger.warning(f"No WHOIS data found for {target}")
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Error during WHOIS lookup for {target}: {e}")
        return results

if __name__ == "__main__":
    # Example Usage
    whois_scanner = WhoisLookup()
    domain_target = "google.com"
    ip_target = "8.8.8.8" # WHOIS for IPs might be different/less detailed via python-whois

    domain_results = whois_scanner.run(domain_target)
    print(f"\n--- WHOIS Results for {domain_target} ---")
    print(json.dumps(domain_results, indent=4))

    # ip_results = whois_scanner.run(ip_target)
    # print(f"\n--- WHOIS Results for {ip_target} ---")
    # print(json.dumps(ip_results, indent=4))
