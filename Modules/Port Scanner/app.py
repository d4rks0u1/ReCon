import nmap
import os
import subprocess

def run(ip):
    print(f"[+] Starting Nmap scan on {ip}")
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-sS -sV -O --top-ports 100")
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                service = nm[host][proto][port]['name']
                print(f"Port: {port}/tcp  Service: {service}")
    print("[+] Scan completed.")

def search_exploits(service_name):
    print(f"[+] Searching exploits for service: {service_name}")
    try:
        output = subprocess.check_output(['searchsploit', service_name])
        print(output.decode())
    except Exception as e:
        print(f"Error: {e}")
