import re
import socket
import dns.resolver

def get_resolver():
    """Returns a dns.resolver.Resolver configured with public DNS servers."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    resolver.timeout = 5
    resolver.lifetime = 5
    return resolver

def find_from_mx(domain):
    """
    Retrieves IP addresses of the mail servers (MX records) configured for the domain.
    
    Args:
        domain (str): Target domain.
        
    Returns:
        set: A set of IP addresses.
    """
    ips = set()
    print(f"[*] Querying MX records for {domain}...")
    resolver = get_resolver()
    try:
        answers = resolver.resolve(domain, 'MX')
        mx_hosts = [str(rdata.exchange).rstrip('.') for rdata in answers]
        for host in mx_hosts:
            try:
                # Explicitly resolve the MX host IP using our public resolver to avoid gaierror timeouts
                try:
                    ip_answers = resolver.resolve(host, 'A')
                    for ip_rdata in ip_answers:
                        ip = str(ip_rdata)
                        ips.add(ip)
                        print(f"  [+] Found MX host {host} with IP: {ip}")
                except Exception:
                    # Fallback to standard socket resolution if resolver fails
                    addr_info = socket.getaddrinfo(host, None)
                    for item in addr_info:
                        ip = item[4][0]
                        ips.add(ip)
                        print(f"  [+] Found MX host {host} with IP (socket): {ip}")
            except Exception:
                continue
    except Exception:
        # No MX records or query failure
        pass
    return ips

def find_from_spf(domain, max_depth=3, current_depth=0):
    """
    Recursively parses SPF (TXT) records of the domain to extract IPv4/IPv6 addresses and ranges.
    
    Args:
        domain (str): Target domain.
        max_depth (int): Max recursion depth for 'include' directives.
        current_depth (int): Current recursion depth.
        
    Returns:
        set: A set of IP addresses and CIDR notations.
    """
    ips = set()
    if current_depth > max_depth:
        return ips
        
    if current_depth == 0:
        print(f"[*] Querying SPF TXT records for {domain}...")
        
    resolver = get_resolver()
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = ''.join([part.decode('utf-8') for part in rdata.strings])
            if txt_record.startswith('v=spf1'):
                # Extract direct ip4 and ip6 notations
                ip4_matches = re.findall(r'ip4:([^\s]+)', txt_record)
                for item in ip4_matches:
                    ips.add(item)
                    
                ip6_matches = re.findall(r'ip6:([^\s]+)', txt_record)
                for item in ip6_matches:
                    ips.add(item)
                
                # Recursively parse includes
                includes = re.findall(r'include:([^\s]+)', txt_record)
                for inc_domain in includes:
                    ips.update(find_from_spf(inc_domain, max_depth, current_depth + 1))
    except Exception:
        pass
        
    if current_depth == 0 and ips:
        print(f"  [+] Found {len(ips)} potential IPs/ranges in SPF records.")
    return ips

