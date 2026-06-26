import requests
import random
import urllib3

# Suppress insecure request warnings from urllib3 since we validate SSL-less raw IP access
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
]

def send_request(url, proxy=None, headers=None, verify=True, allow_redirects=True, timeout=10):
    """
    Sends a GET request to a URL with a random User-Agent and configurable options.

    Args:
        url (str): The URL to request.
        proxy (str): Optional proxy URL.
        headers (dict): Optional custom headers.
        verify (bool): Whether to verify SSL certificates.
        allow_redirects (bool): Whether to follow redirects.
        timeout (int): Request timeout in seconds.

    Returns:
        requests.Response: The response object, or None on error.
    """
    request_headers = {'User-Agent': random.choice(USER_AGENTS)}
    if headers:
        request_headers.update(headers)
        
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    
    try:
        response = requests.get(
            url, 
            headers=request_headers, 
            proxies=proxies, 
            timeout=timeout, 
            verify=verify, 
            allow_redirects=allow_redirects
        )
        return response
    except requests.exceptions.RequestException:
        return None