import subprocess

def run_fuzzer():
    print("[+] Starting Wordlist-based fuzzing")
    print("Choose a module:")
    print("1. Directory Bruteforce")
    print("2. Subdomain Enumeration")
    print("3. DNS Record Fuzzing")
    choice = input("Enter choice (1-3): ")

    target = input("Enter target URL or domain: ")
    wordlist = input("Enter path to wordlist: ")

    if choice == "1":
        dir_bruteforce(target, wordlist)
    elif choice == "2":
        subdomain_enum(target, wordlist)
    elif choice == "3":
        dns_fuzz(target, wordlist)
    else:
        print("[-] Invalid choice.")

def dir_bruteforce(target, wordlist):
    print(f"[+] Running directory scan on {target}")
    subprocess.run(['ffuf', '-u', f'{target}/FUZZ', '-w', wordlist])

def subdomain_enum(domain, wordlist):
    print(f"[+] Enumerating subdomains for {domain}")
    subprocess.run(['ffuf', '-u', 'http://FUZZ.' + domain, '-w', wordlist])

def dns_fuzz(domain, wordlist):
    print(f"[+] Fuzzing DNS records for {domain}")
    subprocess.run(['ffuf', '-u', 'http://FUZZ.' + domain, '-w', wordlist])
