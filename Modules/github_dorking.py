import requests
import json
from utils.logger import logger
from config import GITHUB_TOKEN

class GitHubDorking:
    """
    Performs GitHub dorking to find sensitive information.
    MITRE ATT&CK Technique: T1592.002 - Gather Victim Host Information: DNS/Other
    """
    def __init__(self):
        self.technique_id = "T1592.002"
        self.technique_name = "GitHub Dorking"
        self.base_url = "https://api.github.com/search/code"
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN and GITHUB_TOKEN != "YOUR_GITHUB_PERSONAL_ACCESS_TOKEN":
            self.headers["Authorization"] = f"token {GITHUB_TOKEN}"
        logger.info(f"Initialized {self.technique_name} module ({self.technique_id})")

    def run(self, target_org_or_domain, keywords=None, file_extensions=None, max_results=10):
        """
        Executes GitHub dorking queries.
        :param target_org_or_domain: The organization or domain to search for.
        :param keywords: List of keywords to search for (e.g., ["password", "api_key"]).
        :param file_extensions: List of file extensions to limit the search (e.g., ["json", "yml"]).
        :param max_results: Maximum number of results to retrieve.
        :return: A dictionary containing GitHub dorking results.
        """
        logger.info(f"Performing GitHub dorking for target: {target_org_or_domain}")
        results = {
            "target": target_org_or_domain,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "data": [],
            "error": None
        }

        if not keywords:
            keywords = ["password", "api_key", "secret", "config", "credentials", "env"]
        if not file_extensions:
            file_extensions = ["json", "yml", "yaml", "txt", "sh", "bash", "env", "ini", "conf"]

        queries = []
        for keyword in keywords:
            for ext in file_extensions:
                queries.append(f'"{keyword}" in:file extension:{ext} org:{target_org_or_domain}')
                queries.append(f'"{keyword}" in:file extension:{ext} "{target_org_or_domain}"') # For domain-based search

        unique_items = set() # To store unique items (e.g., file URLs)

        for query in queries:
            params = {"q": query, "per_page": min(max_results, 100)} # GitHub API max per_page is 100
            try:
                response = requests.get(self.base_url, headers=self.headers, params=params)
                response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
                search_results = response.json()

                for item in search_results.get("items", []):
                    item_data = {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "repository": item.get("repository", {}).get("full_name"),
                        "html_url": item.get("html_url"),
                        "score": item.get("score")
                    }
                    # Add to a set to ensure uniqueness based on html_url
                    unique_items.add(json.dumps(item_data, sort_keys=True))
                    if len(unique_items) >= max_results:
                        break
                if len(unique_items) >= max_results:
                    break

            except requests.exceptions.RequestException as e:
                results["error"] = f"Request error during GitHub dorking: {e}"
                logger.error(f"Request error during GitHub dorking for query '{query}': {e}")
                break # Stop on first request error
            except json.JSONDecodeError:
                results["error"] = "Failed to decode JSON response from GitHub API."
                logger.error(f"Failed to decode JSON response for query '{query}'. Response: {response.text}")
                break
            except Exception as e:
                results["error"] = str(e)
                logger.error(f"Error during GitHub dorking for query '{query}': {e}")
                break

        results["data"] = [json.loads(item) for item in unique_items]
        logger.info(f"GitHub dorking completed for {target_org_or_domain}. Found {len(results['data'])} potential items.")
        return results

if __name__ == "__main__":
    # Example Usage
    github_dorker = GitHubDorking()
    target_org = "octocat" # Replace with a target organization or domain
    # You can also specify custom keywords and extensions
    # keywords = ["password", "api_key"]
    # file_extensions = ["txt", "log"]

    dorking_results = github_dorker.run(target_org, max_results=5)
    print(f"\n--- GitHub Dorking Results for {target_org} ---")
    print(json.dumps(dorking_results, indent=4))
