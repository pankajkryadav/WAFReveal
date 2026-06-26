import socket
import requests
import dns.resolver

COMMON_SUBDOMAINS = [
    'www', 'origin', 'origin-www', 'direct', 'direct-connect', 'cdn-origin',
    'ftp', 'dev', 'staging', 'test', 'webmail', 'mail', 'remote'
]

def get_resolver():
    """Returns a dns.resolver.Resolver configured with public DNS servers."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    resolver.timeout = 3
    resolver.lifetime = 3
    return resolver

def resolve_hostname(hostname):
    """Resolves a hostname using custom public resolver or fallback socket."""
    ips = set()
    resolver = get_resolver()
    try:
        answers = resolver.resolve(hostname, 'A')
        for rdata in answers:
            ips.add(str(rdata))
    except Exception:
        try:
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
        except Exception:
            pass
    return ips

def find_from_crtsh(domain):
    """
    Scrapes crt.sh (Certificate Transparency logs) to find subdomains,
    then resolves them to discover potential origin IPs.

    Args:
        domain (str): The target domain.

    Returns:
        set: A set of unique IP addresses found.
    """
    subdomains = set()
    found_ips = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    print(f"[*] Querying crt.sh certificate transparency logs for {domain}...")
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                # name_value can contain multiple domains separated by newlines
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    sub = sub.strip().lower()
                    if sub and not sub.startswith('*.'):
                        subdomains.add(sub)
                
                common_name = entry.get('common_name', '')
                if common_name:
                    common_name = common_name.strip().lower()
                    if not common_name.startswith('*.'):
                        subdomains.add(common_name)
                        
            print(f"  [+] Found {len(subdomains)} unique subdomains from crt.sh.")
        else:
            print(f"  [-] crt.sh returned status code {response.status_code}.")
    except Exception as e:
        print(f"  [-] Error querying crt.sh: {e}")

    if subdomains:
        print(f"[*] Resolving discovered subdomains from crt.sh...")
        for sub in subdomains:
            ips = resolve_hostname(sub)
            found_ips.update(ips)
                
    return found_ips


def find_from_subdomains(domain):
    """
    Looks for IPs by resolving common subdomains.

    Args:
        domain (str): The target domain.

    Returns:
        set: A set of unique IP addresses found.
    """
    found_ips = set()
    print(f"[*] Probing common subdomain list for {domain}...")
    for sub in COMMON_SUBDOMAINS:
        hostname = f"{sub}.{domain}"
        ips = resolve_hostname(hostname)
        for ip in ips:
            print(f"  [+] Found potential IP via {hostname}: {ip}")
            found_ips.add(ip)
            
    return found_ips
