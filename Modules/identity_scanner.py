import re
import requests
from bs4 import BeautifulSoup
import subprocess 


def extract_identity_info():
    url = input("Enter URL to scrape: ")
    print(f"[+] Crawling {url} for identity info...")

    try:
        response = requests.get(url, timeout=10)
        content = response.text

        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)
        usernames = re.findall(r"user(?:name)?[\"':\s=]{1,5}([a-zA-Z0-9_]+)", content)
        names = re.findall(r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", content)

        print("[+] Potential Emails Found:")
        for email in set(emails):
            print("  -", email)

        print("\n[+] Potential Usernames:")
        for user in set(usernames):
            print("  -", user)

        print("\n[+] Potential Full Names:")
        for name in set(names):
            print("  -", name)

    except Exception as e:
        print(f"[-] Error occurred: {e}")

def scan_host():
    host = input("Enter IP/Domain: ")
    print(f"[+] Gathering host information for {host}")
    subprocess.run(["whois", host])
