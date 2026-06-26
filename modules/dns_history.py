import requests

def find_from_securitytrails(domain, api_key):
    """
    Finds historical DNS A records for a domain using the SecurityTrails API.

    Args:
        domain (str): The target domain.
        api_key (str): Your SecurityTrails API key.

    Returns:
        set: A set of unique IP addresses found.
    """
    found_ips = set()
    if not api_key or api_key == "YOUR_SECURITYTRAILS_API_KEY":
        print("[-] SecurityTrails API key not configured. Skipping DNS history.")
        return found_ips

    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    headers = {"accept": "application/json", "APIKEY": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        for record in data.get('records', []):
            for ip in record.get('values', []):
                found_ips.add(ip.get('ip'))
                
    except requests.exceptions.RequestException as e:
        if e.response and e.response.status_code == 429:
             print("[-] SecurityTrails API limit reached.")
        # else:
            # print(f"[-] Error querying SecurityTrails: {e}") # Optional: for debugging
            
    return found_ips