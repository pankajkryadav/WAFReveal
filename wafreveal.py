import argparse
import configparser
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

from modules import dns_history, subdomain_search, favicon_search, dns_records
from utils import validator

def load_config():
    """Loads API keys and settings from config.ini."""
    config = configparser.ConfigParser()
    try:
        config.read('config.ini')
        api_keys = config['api_keys']
        settings = config['settings']
        return api_keys, settings
    except (FileNotFoundError, KeyError):
        # Fallback to empty configs if file or keys missing
        return {}, {}


def check_port(ip, port, timeout=2):
    """Checks if a TCP port is open on a given IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def get_active_ips(ips, timeout=2):
    """Filters a set of IPs, returning only those with port 80 or 443 open."""
    active = set()
    print(f"{Fore.CYAN}[*] Filtering {len(ips)} potential IPs for active web ports (80/443)...")
    
    def check_ip(ip):
        if check_port(ip, 80, timeout) or check_port(ip, 443, timeout):
            return ip
        return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_ip, ips)
        for res in results:
            if res:
                active.add(res)
    return active


def expand_to_cidr24(ips):
    """Expands a set of IPs to their /24 CIDR blocks (excluding CDN or invalid IPs)."""
    cidr_ips = set()
    subnets = set()
    for ip in ips:
        # Simple IPv4 check
        parts = ip.split('.')
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
            subnets.add(subnet)
            
    print(f"{Fore.CYAN}[*] Expanding to /24 subnets. Found {len(subnets)} unique subnets to scan...")
    for subnet in subnets:
        for i in range(1, 255):
            cidr_ips.add(f"{subnet}.{i}")
    return cidr_ips


def find_origin_ip(domain, api_keys, settings, no_api=False, scan_cidr=False):
    """
    Orchestrates the search for the origin IP for a single domain.

    Args:
        domain (str): The target domain.
        api_keys (dict): Dictionary of API keys.
        settings (dict): Dictionary of tool settings.
        no_api (bool): If True, skip API-dependent modules.
        scan_cidr (bool): If True, expand discovered IPs to /24 subnets and scan them.

    Returns:
        list: A list of verified origin IP addresses.
    """
    print(f"\n{Style.BRIGHT}{Fore.CYAN}[*] Starting advanced origin scan for: {domain}")
    potential_ips = set()
    verified_ips = []
    proxy = settings.get('proxy') or None

    # --- Discovery Phase ---
    
    # 0. Base Domain and WWW Resolution
    potential_ips.update(subdomain_search.resolve_hostname(domain))
    potential_ips.update(subdomain_search.resolve_hostname(f"www.{domain}"))
    
    # 1. Passive DNS Records (MX & SPF) - API-less
    potential_ips.update(dns_records.find_from_mx(domain))
    
    spf_entries = dns_records.find_from_spf(domain)
    for entry in spf_entries:
        if '/' in entry:
            parts = entry.split('/')
            base_ip = parts[0]
            potential_ips.add(base_ip)
        else:
            potential_ips.add(entry)

    # 2. Subdomains Certificate Transparency Logs (crt.sh) - API-less
    potential_ips.update(subdomain_search.find_from_crtsh(domain))

    # 3. Subdomains Wordlist Probing - API-less
    potential_ips.update(subdomain_search.find_from_subdomains(domain))


    # 4. API-Dependent Checks (Shodan and SecurityTrails)
    if not no_api:
        st_key = api_keys.get('securitytrails')
        if st_key and st_key != "YOUR_SECURITYTRAILS_API_KEY":
            potential_ips.update(dns_history.find_from_securitytrails(domain, st_key))
            
        shodan_key = api_keys.get('shodan')
        if shodan_key and shodan_key != "YOUR_SHODAN_API_KEY":
            potential_ips.update(favicon_search.find_from_favicon(domain, shodan_key, proxy))

    # Remove CDNs from potential list early to save scan time
    potential_ips = {ip for ip in potential_ips if not validator.is_cdn_ip(ip)}

    if not potential_ips:
        print(f"{Fore.YELLOW}[-] No potential IPs found for {domain}.")
        return []

    print(f"{Fore.CYAN}[*] Found {len(potential_ips)} unique potential base IPs.")

    # --- Optional /24 CIDR Subnet Scan ---
    if scan_cidr:
        expanded_ips = expand_to_cidr24(potential_ips)
        # Filter CDNs on expanded list
        expanded_ips = {ip for ip in expanded_ips if not validator.is_cdn_ip(ip)}
        print(f"{Fore.CYAN}[*] Scanning expanded {len(expanded_ips)} CIDR IPs...")
        # Check active ports 80/443 on all expanded CIDR addresses
        active_ips = get_active_ips(expanded_ips)
    else:
        # Check active ports on discovered potential IPs
        active_ips = get_active_ips(potential_ips)

    if not active_ips:
        print(f"{Fore.YELLOW}[-] No active web hosts detected on potential IPs/subnets.")
        return []

    print(f"{Fore.CYAN}[*] {len(active_ips)} IPs have open ports 80/443. Starting origin verification...")

    # --- Validation Phase ---
    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_ip = {executor.submit(validator.is_origin_ip, domain, ip, proxy): ip for ip in active_ips}
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result():
                    print(f"{Style.BRIGHT}{Fore.GREEN}[+] Verified Origin IP for {domain}: {ip}")
                    verified_ips.append(ip)
            except Exception as exc:
                print(f"{Fore.RED}[!] Error validating IP {ip}: {exc}")
    
    if not verified_ips:
        print(f"{Fore.YELLOW}[-] Could not verify any origin IPs for {domain}.")
    
    return verified_ips


def main():
    parser = argparse.ArgumentParser(
        description="WAFReveal - Advanced Alive Origin IP Finder Tool. Developed by Pankaj Kr Yadav."
    )
    parser.add_argument('-d', '--domain', help='Single domain to scan.')
    parser.add_argument('-l', '--list', help='File containing a list of domains to scan.')
    parser.add_argument('-c', '--scan-cidr', action='store_true', help='Expand discovered IPs to their /24 subnets and scan them.')
    parser.add_argument('--no-api', action='store_true', help='Run without API keys (skips Shodan and SecurityTrails).')
    parser.add_argument('-oJ', '--output-json', help='Output results to a JSON file.')
    parser.add_argument('-oT', '--output-txt', help='Output results to a TXT file.')
    
    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.error("No target specified. Use -d for a single domain or -l for a list.")

    api_keys, settings = load_config()
    targets = []
    if args.domain:
        targets.append(args.domain)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: Input file '{args.list}' not found.")
            exit(1)

    all_results = {}
    for target in targets:
        all_results[target] = find_origin_ip(target, api_keys, settings, args.no_api, args.scan_cidr)

    if args.output_json:
        with open(args.output_json, 'w') as f:
            json.dump(all_results, f, indent=4)
        print(f"\n{Style.BRIGHT}{Fore.GREEN}[+] JSON results saved to {args.output_json}")

    if args.output_txt:
        with open(args.output_txt, 'w') as f:
            for domain, ips in all_results.items():
                if ips:
                    f.write(f"{domain}:\n")
                    for ip in ips:
                        f.write(f"  - {ip}\n")
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] TXT results saved to {args.output_txt}")


if __name__ == '__main__':
    main()