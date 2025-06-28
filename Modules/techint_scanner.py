import subprocess

def query_open_sources():
    domain = input("Enter domain or IP: ")
    print("[+] Running OSINT Enumeration")

    print("\n[+] WHOIS Info:")
    subprocess.run(["whois", domain])

    print("\n[+] Checking Certificates:")
    subprocess.run(["openssl", "s_client", "-connect", f"{domain}:443"])

    print("\n[+] CDN Check (Ping + Header Check):")
    subprocess.run(["ping", "-c", "3", domain])
    subprocess.run(["curl", "-I", domain])

    print("\n[+] Searching Leak Databases (placeholder):")
    print("[!] Integrate with HaveIBeenPwned or public breach lists manually.")
