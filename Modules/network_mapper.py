import subprocess

def map_network():
    target = input("Enter target domain or IP: ")
    print(f"[+] Mapping network: {target}")

    print("\n[+] Gathering DNS Info...")
    subprocess.run(["nslookup", target])

    print("\n[+] Checking Network Topology (traceroute)...")
    subprocess.run(["traceroute", target] if not target.startswith("win") else ["tracert", target])

    print("\n[+] Identifying IPs and Security Appliances...")
    subprocess.run(["nmap", "-sS", "-sV", "-O", target])
