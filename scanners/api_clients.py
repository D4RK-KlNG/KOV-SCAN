# scanners/api_clients.py

import requests
from urllib.parse import quote_plus

HEADERS = {"User-Agent": "KovScanner/2.0"}

def hackertarget_http_headers(domain):
    try:
        url = f"https://api.hackertarget.com/httpheaders/?q={quote_plus(domain)}"
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_whatweb(domain):
    try:
        url = f"https://api.hackertarget.com/whatweb/?q={quote_plus(domain)}"
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_dnslookup(domain):
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={quote_plus(domain)}"
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_hostsearch(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote_plus(domain)}"
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def hackertarget_whois(domain):
    try:
        url = f"https://api.hackertarget.com/whois/?q={quote_plus(domain)}"
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def securityheaders_dot_com(domain):
    try:
        url = f"https://securityheaders.com/?q={quote_plus(domain)}&followRedirects=on"
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def ip_api_info(ip_or_host):
    try:
        url = f"http://ip-api.com/json/{quote_plus(ip_or_host)}"
        r = requests.get(url, headers=HEADERS, timeout=8)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def threatminer_domain_report(domain):
    try:
        url = f"https://api.threatminer.org/v2/domain.php?q={quote_plus(domain)}&rt=1"
        r = requests.get(url, timeout=10, headers=HEADERS)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def wayback_snapshot(domain):
    try:
        url = f"http://archive.org/wayback/available?url={quote_plus(domain)}"
        r = requests.get(url, timeout=10, headers=HEADERS)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def urlscan_search(domain):
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote_plus(domain)}"
        r = requests.get(url, timeout=10, headers=HEADERS)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None
