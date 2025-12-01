# scanners/passive_checks.py


import socket
import ssl
import re
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import datetime

from .api_clients import (
    hackertarget_http_headers,
    hackertarget_whatweb,
    hackertarget_dnslookup,
    hackertarget_hostsearch,
    hackertarget_whois,
    securityheaders_dot_com,
    ip_api_info,
    threatminer_domain_report,
    wayback_snapshot,
    urlscan_search
)


# Extended common paths
# -------------------------
COMMON_PATHS = [
    # Login/admin
    "admin", "administrator", "admin.php", "login", "login.php", "wp-login.php", "wp-admin/",
    "cpanel", "panel", "dashboard", "user/login", "admin/login", "backend", "manage",

    # Sensitive config leaks
    ".env", "config.php", "config.json", "database.yaml", "db.php", "credentials.txt",
    "settings.php", "wp-config.php", "local.settings.json", "web.config",

    # Backups & dumps
    "backup.zip", "backup.tar", "backup.tar.gz", "db_backup.sql", "database.sql",
    "dump.sql", "backup.old", "site-backup.zip",

    # Git/SVN leak
    ".git/", ".git/HEAD", ".svn/", ".hg/", ".DS_Store",

    # Frameworks
    "phpinfo.php", "info.php", "__debug__", "debug", "vendor/", "storage/logs/laravel.log",
    "server-status", "server-info", "aspnet_client/",

    # API
    "api", "api/v1", "graphql", "swagger", "openapi.json",

    # CMS
    "wp-content/", "wp-includes/", "joomla/", "drupal/",

    # Assets & misc
    ".well-known/security.txt", ".well-known/assetlinks.json", "robots.txt", "sitemap.xml",
]


# Helpers
# -------------------------
UA = {"User-Agent": "Kov/1.0"}

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
        r = requests.get(base, timeout=timeout, allow_redirects=True, headers=UA)
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


# HTML analysis (1)
# -------------------------
def analyze_html_snippet(html):
    notes = []
    if not html:
        return notes
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ").lower()

    # generator meta
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        notes.append(f"Generator: {gen['content']}")

    # CMS/frameworks
    if "wp-content" in html.lower() or "wordpress" in html.lower():
        notes.append("WordPress detected")
    if "joomla" in html.lower():
        notes.append("Joomla detected")
    if "drupal" in html.lower():
        notes.append("Drupal detected")
    if "laravel" in text:
        notes.append("Laravel detected")
    if "symfony" in text:
        notes.append("Symfony detected")

    # emails
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html)
    if emails:
        notes.append(f"Emails found: {len(set(emails))}")

    # tokens / keys (shallow)
    if re.search(r"(api[_-]?key|token|secret|aws_access_key_id|aws_secret_access_key)", html, re.I):
        notes.append("Possible API keys/tokens exposed (shallow check)")

    # JS libs
    if soup.find("script", src=re.compile("jquery", re.I)):
        notes.append("jQuery present")

    # login forms
    forms = soup.find_all("form")
    if forms:
        login_forms = sum(1 for f in forms if "password" in str(f).lower())
        if login_forms:
            notes.append(f"Login-like form(s): {login_forms}")
        # CSRF like fields
        csrf = sum(1 for f in forms for i in f.find_all("input") if "csrf" in (i.get("name") or "").lower() or "token" in (i.get("name") or "").lower())
        if csrf:
            notes.append(f"CSRF-like fields: {csrf}")

    return notes


def check_common_paths(base):
    found = []
    for p in COMMON_PATHS:
        try:
            url = urljoin(base.rstrip("/") + "/", p)
            r = requests.head(url, timeout=4, allow_redirects=True, headers=UA)
            if r is not None and r.status_code < 400:
                found.append((p, r.status_code))
        except:
            pass
    return found

# robots / sitemap
def check_robots_sitemap(base):
    results = []
    try:
        r = requests.get(urljoin(base, "/robots.txt"), timeout=5, headers=UA)
        if r.status_code == 200 and r.text.strip():
            results.append("robots.txt")
    except:
        pass
    try:
        r = requests.get(urljoin(base, "/sitemap.xml"), timeout=5, headers=UA)
        if r.status_code == 200:
            results.append("sitemap.xml")
    except:
        pass
    return results

# port reachability
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


def assess_risks(result):
    findings = []
    headers = result.get("headers", {})
    missing = []
    present = []
    # check security headers
    for h in ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]:
        if h in headers:
            present.append(h)
        else:
            missing.append(h)
    if missing:
        findings.append(("HIGH", f"Missing security headers: {', '.join(missing)}"))

    # login forms and no HSTS
    if any("Login-like" in n or "Login-like form" in n for n in result.get("html_notes", [])):
        if not result.get("base","").startswith("https://"):
            findings.append(("CRITICAL", "Login form present but site not using HTTPS"))
    # exposed sensitive paths
    for p, code in result.get("common_paths", []):
        if p in (".env", "config.php", "wp-config.php", ".git/", "backup.zip"):
            findings.append(("CRITICAL", f"Exposed sensitive path: /{p} returned {code}"))
        else:
            findings.append(("MEDIUM", f"Public path accessible: /{p} returned {code}"))

    # open DB ports
    if 3306 in result.get("ports", []):
        findings.append(("HIGH", "MySQL port (3306) reachable - database may be publicly accessible"))

    # cookies
    sc = headers.get("Set-Cookie","")
    if sc:
        if "httponly" not in sc.lower():
            findings.append(("MEDIUM", "Session cookies missing HttpOnly flag"))
        if result.get("base","").startswith("https://") and "secure" not in sc.lower():
            findings.append(("MEDIUM", "Session cookies missing Secure flag"))

    
    ipinfo = result.get("api_ipinfo") or {}
    if ipinfo.get("proxy") or ipinfo.get("hosting") or ipinfo.get("org") and "amazon" in str(ipinfo.get("org")).lower():
        findings.append(("LOW", "Hosting appears to be cloud provider/host"))

    # if nothing found
    if not findings:
        findings.append(("LOW", "No obvious passive issues found - consider deeper authorized testing"))

    # dedupe by message
    dedup = []
    seen = set()
    for sev, msg in findings:
        if msg not in seen:
            seen.add(msg)
            dedup.append((sev, msg))
    return dedup


def all_in_one_passive(raw_target):
    base = normalize_url(raw_target)
    if not base:
        return {"error":"Invalid target"}
    host = get_host(base)
    ip = dns_lookup(host) or "no-dns"
    result = {"target": host, "base": base, "ip": ip, "timestamp": datetime.datetime.utcnow().isoformat()+"Z"}

    # local fetch
    r = fetch_get(base)
    if r:
        result["http_status"] = r.status_code
        result["headers"] = dict(r.headers)
        result["content_type"] = r.headers.get("Content-Type","")
        result["html_snippet"] = r.text[:200000] if result["content_type"].lower().startswith("text/html") else ""
        # redirect chain
        try:
            redirs = [h.url for h in r.history] + [r.url]
            result["redirect_chain"] = redirs
        except:
            result["redirect_chain"] = []
    else:
        result["http_status"] = "no-response"
        result["headers"] = {}
        result["content_type"] = ""
        result["html_snippet"] = ""
        result["redirect_chain"] = []

    # local passive
    result["ssl"] = ssl_summary(host) if base.lower().startswith("https://") else {}
    result["html_notes"] = analyze_html_snippet(result["html_snippet"])
    result["common_paths"] = check_common_paths(base)
    result["robots_sitemap"] = check_robots_sitemap(base)
    result["ports"] = port_reachability(host)

    # API
    result["api_http_headers"] = hackertarget_http_headers(host)
    result["api_whatweb"] = hackertarget_whatweb(host)
    result["api_dnslookup"] = hackertarget_dnslookup(host)
    result["api_hostsearch"] = hackertarget_hostsearch(host)
    result["api_whois"] = hackertarget_whois(host)
    result["api_securityheaders_html"] = securityheaders_dot_com(host)
    result["api_ipinfo"] = ip_api_info(host) or ip_api_info(ip) or {}
    result["api_threatminer"] = threatminer_domain_report(host)
    result["api_wayback"] = wayback_snapshot(host)
    result["api_urlscan"] = urlscan_search(host)

    # risk findings
    result["risk_findings"] = assess_risks(result)

    # summary
    result["summary"] = f"{host} | HTTP:{result.get('http_status')} | IP:{ip} | Ports:{len(result.get('ports',[]))} | Paths:{len(result.get('common_paths',[]))}"

    return result
