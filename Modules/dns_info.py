import dns.resolver
import dns.reversename
import json
from utils.logger import logger

class DNSInformation:
    """
    Gathers various DNS records for a given domain.
    MITRE ATT&CK Technique: T1590.002 - Gather Victim Network Information: DNS
    """
    def __init__(self):
        self.technique_id = "T1590.002"
        self.technique_name = "DNS Information"
        self.record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CNAME"]
        logger.info(f"Initialized {self.technique_name} module ({self.technique_id})")

    def _query_dns(self, target, record_type):
        """Helper to query a specific DNS record type."""
        try:
            answers = dns.resolver.resolve(target, record_type)
            return [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.Timeout:
            logger.warning(f"DNS query for {target} ({record_type}) timed out.")
            return []
        except Exception as e:
            logger.error(f"Error querying DNS for {target} ({record_type}): {e}")
            return []

    def _reverse_dns_lookup(self, ip_address):
        """Performs a reverse DNS lookup for an IP address."""
        try:
            addr = dns.reversename.from_address(ip_address)
            return str(dns.resolver.resolve(addr, "PTR")[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception as e:
            logger.error(f"Error during reverse DNS lookup for {ip_address}: {e}")
            return None

    def run(self, target):
        """
        Executes DNS information gathering.
        :param target: The domain or IP address to gather DNS info for.
        :return: A dictionary containing DNS records.
        """
        logger.info(f"Gathering DNS information for target: {target}")
        results = {
            "target": target,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "data": {},
            "error": None
        }

        if self._is_ip_address(target):
            # If target is an IP, perform reverse DNS lookup
            ptr_record = self._reverse_dns_lookup(target)
            if ptr_record:
                results["data"]["PTR"] = ptr_record
                logger.info(f"Reverse DNS lookup successful for {target}: {ptr_record}")
            else:
                results["data"]["PTR"] = "No PTR record found or error."
                logger.warning(f"No PTR record found for {target}")
        else:
            # If target is a domain, query various record types
            for record_type in self.record_types:
                if record_type == "PTR": # PTR is for reverse lookups, handled separately
                    continue
                records = self._query_dns(target, record_type)
                if records:
                    results["data"][record_type] = records
                    logger.info(f"Found {len(records)} {record_type} records for {target}")
                else:
                    results["data"][record_type] = "No records found."
                    logger.debug(f"No {record_type} records found for {target}")

        if not results["data"]:
            results["error"] = "No DNS information could be retrieved."
            logger.warning(f"No DNS information could be retrieved for {target}")

        return results

    def _is_ip_address(self, target):
        """Checks if the target is an IP address."""
        try:
            dns.resolver.resolve(target, 'A') # Try resolving as a domain
            return False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # If it's not a domain, it might be an IP
            try:
                import ipaddress
                ipaddress.ip_address(target)
                return True
            except ValueError:
                return False
        except Exception:
            # Any other error, assume it's not a valid domain or IP for now
            return False

if __name__ == "__main__":
    # Example Usage
    dns_scanner = DNSInformation()
    domain_target = "google.com"
    ip_target = "8.8.8.8"

    domain_results = dns_scanner.run(domain_target)
    print(f"\n--- DNS Information Results for {domain_target} ---")
    print(json.dumps(domain_results, indent=4))

    ip_results = dns_scanner.run(ip_target)
    print(f"\n--- DNS Information Results for {ip_target} ---")
    print(json.dumps(ip_results, indent=4))
