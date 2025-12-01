# api_clients.py
#________________________

import requests
from urllib.parse import quote_plus

HEADERS = {"User-Agent": "Kov/1.0"}

def hackertarget_http_headers(domain):
    # returns raw
    try:
        url = f"https://api.hackertarget.com/httpheaders/?q={quote_plus(domain)}"
        r = requests.get(url, timeout=10, headers=HEADERS)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_whatweb(domain):
    try:
        url = f"https://api.hackertarget.com/whatweb/?q={quote_plus(domain)}"
        r = requests.get(url, timeout=12, headers=HEADERS)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_dnslookup(domain):
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={quote_plus(domain)}"
        r = requests.get(url, timeout=12, headers=HEADERS)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_hostsearch(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote_plus(domain)}"
        r = requests.get(url, timeout=12, headers=HEADERS)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_whois(domain):
    try:
        url = f"https://api.hackertarget.com/whois/?q={quote_plus(domain)}"
        r = requests.get(url, timeout=12, headers=HEADERS)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def securityheaders_dot_com(domain):
    try:
        
        url = f"https://securityheaders.com/?q={quote_plus(domain)}&followRedirects=on"
        r = requests.get(url, timeout=12, headers=HEADERS)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def ip_api_info(ip_or_host):
    
    try:
        
        url = f"http://ip-api.com/json/{quote_plus(ip_or_host)}"
        r = requests.get(url, timeout=8, headers=HEADERS)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None
