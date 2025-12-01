
import socket
import ssl
import re
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

from .api_clients import (
    hackertarget_http_headers,
    hackertarget_whatweb,
    hackertarget_dnslookup,
    hackertarget_hostsearch,
    hackertarget_whois,
    securityheaders_dot_com,
    ip_api_info
)

# Helper:
def normalize_url(raw):
    if not raw:
        return None
    raw = raw.strip().strip('\'"')
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"

def get_host(base):
    return urlparse(base).netloc

def dns_lookup(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def fetch_get(base, timeout=8):
    try:
        r = requests.get(base, timeout=timeout, allow_redirects=True, headers={"User-Agent":"Kov/1.0"})
        return r
    except:
        return None

def ssl_summary(host):
    try:
        hostname = host.split(":")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(6)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        if not cert:
            return {}
        subj = {}
        for rdn in cert.get("subject", ()):
            subj.update(rdn[0])
        issuer = {}
        for rdn in cert.get("issuer", ()):
            issuer.update(rdn[0])
        return {
            "subject": subj.get("commonName") or subj.get("CN",""),
            "issuer": issuer.get("commonName") or issuer.get("CN",""),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
        }
    except:
        return {}

def analyze_html_snippet(html):
    notes = []
    if not html:
        return notes
    soup = BeautifulSoup(html, "html.parser")
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        notes.append(f"Generator: {gen['content']}")
    forms = soup.find_all("form")
    if forms:
        notes.append(f"Forms: {len(forms)}")
        login_like = 0
        csrf_like = 0
        for f in forms:
            for inp in f.find_all("input"):
                name = (inp.get("name") or "").lower()
                typ = (inp.get("type") or "").lower()
                if "password" in typ or "password" in name:
                    login_like += 1
                if "csrf" in name or "token" in name:
                    csrf_like += 1
        if login_like:
            notes.append(f"Login-like forms: {login_like}")
        if csrf_like:
            notes.append(f"CSRF-like fields: {csrf_like}")
    if soup.find("script", src=re.compile(r"jquery", re.I)):
        notes.append("jQuery present")
    if "wp-content" in (html or "").lower():
        notes.append("WordPress detected")
    return notes

# common path check
COMMON_PATHS = ["admin", "login", "wp-login.php", "wp-admin/", ".env", "config.php", ".git/", "backup.zip", "phpinfo.php"]
def check_common_paths(base):
    found = []
    for p in COMMON_PATHS:
        try:
            url = urljoin(base + "/", p)
            r = requests.head(url, timeout=4, allow_redirects=True, headers={"User-Agent":"kov/1.0"})
            if r is not None and r.status_code < 400:
                found.append((p, r.status_code))
        except:
            pass
    return found

# robots/sitemap
def check_robots_sitemap(base):
    results = []
    try:
        r = requests.get(urljoin(base, "/robots.txt"), timeout=5, headers={"User-Agent":"Kov/1.0"})
        if r.status_code == 200 and r.text.strip():
            results.append("robots.txt")
    except:
        pass
    try:
        r = requests.get(urljoin(base, "/sitemap.xml"), timeout=5, headers={"User-Agent":"Kov/1.0"})
        if r.status_code == 200:
            results.append("sitemap.xml")
    except:
        pass
    return results

# port
COMMON_PORTS = [21,22,25,53,80,110,143,443,3306,8080,8443]
def port_reachability(host):
    ip = dns_lookup(host)
    open_ports = []
    if not ip:
        return open_ports
    for p in COMMON_PORTS:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip, p))
            open_ports.append(p)
            s.close()
        except:
            pass
    return open_ports

# all-in-one
def all_in_one_passive(raw_target):
    base = normalize_url(raw_target)
    if not base:
        return {"error":"Invalid target"}
    host = get_host(base)
    ip = dns_lookup(host) or "no-dns"
    result = {"target": host, "base": base, "ip": ip}

    # local fetch
    r = fetch_get(base)
    if r:
        result["http_status"] = r.status_code
        result["headers"] = dict(r.headers)
        ct = r.headers.get("Content-Type","")
        result["content_type"] = ct
        result["html_snippet"] = r.text[:150000] if ct.lower().startswith("text/html") else ""
    else:
        result["http_status"] = "no-response"
        result["headers"] = {}
        result["content_type"] = ""
        result["html_snippet"] = ""

    # local passive
    result["ssl"] = ssl_summary(host) if base.lower().startswith("https://") else {}
    result["html_notes"] = analyze_html_snippet(result["html_snippet"])
    result["common_paths"] = check_common_paths(base)
    result["robots_sitemap"] = check_robots_sitemap(base)
    result["ports"] = port_reachability(host)

    
    result["api_http_headers"] = hackertarget_http_headers(host)
    result["api_whatweb"] = hackertarget_whatweb(host)
    result["api_dnslookup"] = hackertarget_dnslookup(host)
    result["api_hostsearch"] = hackertarget_hostsearch(host)
    result["api_whois"] = hackertarget_whois(host)
    result["api_securityheaders_html"] = securityheaders_dot_com(host)
    result["api_ipinfo"] = ip_api_info(host) or ip_api_info(ip) or {}

    #
    result["summary"] = f"{host} | HTTP:{result.get('http_status')} | IP:{ip} | Ports:{len(result.get('ports',[]))} | Paths:{len(result.get('common_paths',[]))}"
    return result
