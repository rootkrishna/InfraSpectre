# InfraSpectre - Infra Recon & Vuln Scanner
# Developed by Krishna Dubey

import socket
import requests
import whois
import dns.resolver
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""{Fore.CYAN}
     _____        __              _____                  __          
    /  _  \ _____/  |_  ____     /     \ _____    ____ |  | __ ____  
   /  /_\  \\\\__  \   __\/ __ \   /  \ /  \\\\__  \ _/ ___\|  |/ // __ \ 
  /    |    \/ __ \|  | \  ___/  /    Y    \/ __ \\\\  \___|    <\  ___/ 
  \____|__  (____  /__|  \___  > \____|__  (____  /\___  >__|_ \\\\___  >
          \/     \/          \/          \/     \/     \/     \/    \/
      {Style.BRIGHT + Fore.YELLOW}InfraSpectre - Infra Recon & Vuln Scanner
{Style.RESET_ALL}
"""

def resolve_dns(target):
    print(f"{Fore.MAGENTA}[*] Resolving DNS records...")
    try:
        a = dns.resolver.resolve(target, 'A')
        for rdata in a:
            print(f"{Fore.GREEN}[A Record] {rdata.address}")
        try:
            mx = dns.resolver.resolve(target, 'MX')
            for rdata in mx:
                print(f"{Fore.GREEN}[MX Record] {rdata.exchange} (Priority {rdata.preference})")
        except:
            print(f"{Fore.RED}No MX records found.")
    except Exception as e:
        print(f"{Fore.RED}[DNS Error] {e}")

def get_headers(target):
    print(f"\n{Fore.MAGENTA}[*] Fetching HTTP headers...")
    try:
        res = requests.get(f"http://{target}", timeout=5)
        print(f"{Fore.GREEN}[+] Status Code: {res.status_code}")
        for header, val in res.headers.items():
            print(f"{Fore.YELLOW}{header}: {val}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching headers: {e}")

def port_scan(target):
    print(f"\n{Fore.MAGENTA}[*] Scanning top ports on {target}...")
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,3306,8080]
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            res = s.connect_ex((target, port))
            if res == 0:
                print(f"{Fore.GREEN}[OPEN] Port {port}")
            s.close()
        except:
            pass

def whois_lookup(target):
    print(f"\n{Fore.MAGENTA}[*] Performing WHOIS lookup...")
    try:
        domain_info = whois.whois(target)
        print(f"{Fore.YELLOW}Domain Name: {domain_info.domain_name}")
        print(f"Registrar: {domain_info.registrar}")
        print(f"Creation Date: {domain_info.creation_date}")
        print(f"Expiration Date: {domain_info.expiration_date}")
        print(f"Emails: {domain_info.emails}")
    except Exception as e:
        print(f"{Fore.RED}[!] WHOIS Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="InfraSpectre - Recon Tool by Krishna Dubey")
    parser.add_argument("-t", "--target", help="Target IP/Domain", required=True)
    parser.add_argument("-m", "--mode", help="Mode: all, dns, headers, whois, ports", default="all")
    args = parser.parse_args()

    target = args.target
    mode = args.mode

    print(BANNER)
    print(f"{Fore.BLUE}[+] Target: {target}")
    try:
        ip = socket.gethostbyname(target)
        print(f"{Fore.CYAN}[+] Resolved IP: {ip}")
    except:
        print(f"{Fore.RED}[!] Unable to resolve IP.")
        return

    if mode == "all":
        resolve_dns(target)
        get_headers(target)
        port_scan(target)
        whois_lookup(target)
    elif mode == "dns":
        resolve_dns(target)
    elif mode == "headers":
        get_headers(target)
    elif mode == "whois":
        whois_lookup(target)
    elif mode == "ports":
        port_scan(target)
    else:
        print(f"{Fore.RED}[!] Invalid mode. Use: all, dns, headers, whois, ports")

if __name__ == "__main__":
    main()
