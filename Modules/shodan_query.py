import json
import shodan
from utils.logger import logger
from config import SHODAN_API_KEY

class ShodanQuery:
    """
    Performs queries against the Shodan API.
    MITRE ATT&CK Technique: T1595.002 - Active Scanning: Vulnerability Scanning
    """
    def __init__(self):
        self.technique_id = "T1595.002"
        self.technique_name = "Shodan Query"
        self.api = None
        if SHODAN_API_KEY and SHODAN_API_KEY != "YOUR_SHODAN_API_KEY":
            try:
                self.api = shodan.Shodan(SHODAN_API_KEY)
                logger.info(f"Initialized {self.technique_name} module ({self.technique_id}) with Shodan API key.")
            except Exception as e:
                logger.error(f"Failed to initialize Shodan API: {e}. Please check your SHODAN_API_KEY in config.py")
        else:
            logger.warning(f"Shodan API key not configured in config.py. Shodan queries will not work.")

    def run(self, query_string, limit=10):
        """
        Executes a Shodan search query.
        :param query_string: The search query (e.g., "apache country:US").
        :param limit: Maximum number of results to retrieve.
        :return: A dictionary containing Shodan search results.
        """
        logger.info(f"Performing Shodan query for: '{query_string}' with limit: {limit}")
        results = {
            "query": query_string,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "data": [],
            "error": None
        }

        if not self.api:
            results["error"] = "Shodan API not initialized. Check SHODAN_API_KEY in config.py."
            logger.error(results["error"])
            return results

        try:
            # Search Shodan
            # For large queries, consider using shodan.helpers.iterate_files or shodan.helpers.iterate_event
            # For this example, we'll use search directly with a limit
            search_results = self.api.search(query_string, limit=limit)
            
            for match in search_results['matches']:
                # Extract relevant information from each match
                host_info = {
                    "ip_str": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "os": match.get("os"),
                    "country_name": match.get("country_name"),
                    "hostnames": match.get("hostnames"),
                    "domains": match.get("domains"),
                    "data": match.get("data"), # Raw banner data
                    "vulns": match.get("vulns", []) # List of CVEs
                }
                results["data"].append(host_info)
            
            logger.info(f"Shodan query successful for '{query_string}'. Found {len(results['data'])} results.")

        except shodan.exception.APIError as e:
            results["error"] = f"Shodan API Error: {e}"
            logger.error(f"Shodan API Error for query '{query_string}': {e}")
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Error during Shodan query for '{query_string}': {e}")
        
        return results

if __name__ == "__main__":
    # Example Usage
    shodan_scanner = ShodanQuery()
    
    # Example: Search for Apache servers in Germany
    query = "apache country:DE"
    shodan_results = shodan_scanner.run(query, limit=5)
    print(f"\n--- Shodan Query Results for '{query}' ---")
    print(json.dumps(shodan_results, indent=4))

    # Example: Search for specific IP
    # ip_query = "207.241.224.2" # Example IP (shodan.io)
    # ip_results = shodan_scanner.run(ip_query, limit=1)
    # print(f"\n--- Shodan Query Results for '{ip_query}' ---")
    # print(json.dumps(ip_results, indent=4))
