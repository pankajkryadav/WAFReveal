import shodan
import mmh3
import codecs
from utils import http_client

def find_from_favicon(domain, api_key, proxy=None):
    """
    Finds IPs by searching for the domain's favicon hash on Shodan.

    Args:
        domain (str): The target domain.
        api_key (str): Your Shodan API key.
        proxy (str): Optional proxy server.

    Returns:
        set: A set of unique IP addresses found.
    """
    found_ips = set()
    if not api_key or api_key == "YOUR_SHODAN_API_KEY":
        print("[-] Shodan API key not configured. Skipping favicon search.")
        return found_ips

    try:
        # Fetch the favicon
        favicon_url = f"https://{domain}/favicon.ico"
        response = http_client.send_request(favicon_url, proxy)
        if not response or not response.content:
            return found_ips

        # Calculate the hash shodan expects
        favicon_b64 = codecs.encode(response.content, 'base64')
        icon_hash = mmh3.hash(favicon_b64)

        # Search Shodan
        print(f"[*] Searching Shodan for favicon hash: {icon_hash}...")
        api = shodan.Shodan(api_key)
        results = api.search(f'http.favicon.hash:{icon_hash}')
        
        for match in results.get('matches', []):
            ip = match.get('ip_str')
            if ip:
                print(f"  [+] Found potential IP via Shodan: {ip}")
                found_ips.add(ip)

    except shodan.APIError as e:
        print(f"[-] Shodan API error: {e}")
    except Exception as e:
        # print(f"[-] An unexpected error occurred during favicon search: {e}") # Optional: for debugging
        pass

    return found_ips