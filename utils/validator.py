import re
import socket
import ssl
import requests
import dns.resolver
from . import http_client

CDN_KEYWORDS = [
    'cloudflare', 'cloudfront', 'fastly', 'akamai', 'incapsula', 'sucuri', 
    'edgecast', 'limelight', 'netdna', 'keycdn', 'stackpath', 'imperva'
]

def is_cdn_ip(ip):
    """
    Checks if the IP belongs to a known CDN using reverse DNS lookup.
    
    Args:
        ip (str): IP address to check.
        
    Returns:
        bool: True if CDN, False otherwise.
    """
    try:
        # Reverse DNS lookup
        addr = socket.getfqdn(ip)
        for keyword in CDN_KEYWORDS:
            if keyword in addr.lower():
                return True
    except Exception:
        pass
    return False


def get_title_from_html(html_content):
    """Extracts the <title> tag content from HTML."""
    if not html_content:
        return None
    match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None


def check_ssl_cert(ip, domain):
    """
    Retrieves the SSL/TLS certificate from the IP directly and checks if
    the target domain is in the Subject Alternative Names (SAN) or Common Name (CN).
    
    Args:
        ip (str): The IP to probe.
        domain (str): The domain to match.
        
    Returns:
        bool: True if matched, False otherwise.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Accept self-signed / expired certs
    
    try:
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                # Parse binary cert to find strings matching the domain
                # Since ssl.CERT_NONE doesn't return a dict, we extract from DER or use getpeercert(True)
                # and do a simple bytes check, or getpeercert() with check_hostname=False
                # Actually, wrapping with server_hostname=domain can sometimes return a dict 
                # if we change verify_mode or just check the subject.
                # Let's fallback to checking the raw cert text representation
                # We can also do a standard socket check and get the dict if we use a customized context:
                pass
    except Exception:
        pass

    # A simpler and very robust way in Python is to connect with getpeercert() using ssl
    try:
        # Try getting the cert dict using standard ssl
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(5)
        conn.connect((ip, 443))
        cert = conn.getpeercert(binary_form=False)
        conn.close()
        
        if cert:
            # Check Common Name (CN)
            subject = cert.get('subject', [])
            for rdn in subject:
                for item in rdn:
                    if item[0] == 'commonName':
                        val = item[1].lower()
                        if val == domain or (val.startswith('*.') and domain.endswith(val[2:])):
                            return True
            # Check Subject Alternative Names (SAN)
            san = cert.get('subjectAltName', [])
            for item in san:
                if item[0] == 'DNS':
                    val = item[1].lower()
                    if val == domain or (val.startswith('*.') and domain.endswith(val[2:])):
                        return True
    except Exception:
        pass
    return False


def is_origin_ip(domain, ip, proxy=None):
    """
    Verifies if an IP is the origin for a domain using several heuristic checks:
    1. SSL/TLS Certificate Match (Common Name / SAN).
    2. HTML Title comparison.
    3. HTTP Redirection to target domain.

    Args:
        domain (str): The target domain (e.g., example.com).
        ip (str): The potential origin IP to test.
        proxy (str): Optional proxy server.

    Returns:
        bool: True if the IP is a likely origin, False otherwise.
    """
    if is_cdn_ip(ip):
        print(f"  [-] IP {ip} identified as CDN. Filtering out.")
        return False

    # 1. High Confidence Check: SSL certificate matching
    if check_ssl_cert(ip, domain):
        return True

    # Get target domain info to compare titles
    target_url = f"https://{domain}"
    response_domain = http_client.send_request(target_url, proxy)
    title_domain = None
    if response_domain and response_domain.text:
        title_domain = get_title_from_html(response_domain.text)

    # 2. Heuristic HTTP/HTTPS Validation
    headers = {
        'Host': domain, 
        'User-Agent': http_client.random.choice(http_client.USER_AGENTS)
    }
    
    # Try HTTPS then HTTP
    for scheme in ["https", "http"]:
        ip_url = f"{scheme}://{ip}"
        
        # Check without following redirects (to catch direct Host validation redirection)
        response_ip = http_client.send_request(
            ip_url, 
            proxy=proxy, 
            headers=headers, 
            verify=False, 
            allow_redirects=False, 
            timeout=8
        )
        
        if not response_ip:
            continue
            
        # Check if redirect points directly to our target domain or its schema
        location = response_ip.headers.get('Location', '')
        if response_ip.status_code in [301, 302, 307, 308] and location:
            # e.g., location is "https://example.com/" or "/index.html" but Host header handles it
            if domain in location or location.startswith('/') or location.startswith(f'http://{domain}') or location.startswith(f'https://{domain}'):
                return True
                
        # Check title matching
        if response_ip.text:
            title_ip = get_title_from_html(response_ip.text)
            if title_ip and title_domain and title_ip.lower() == title_domain.lower():
                return True

    return False