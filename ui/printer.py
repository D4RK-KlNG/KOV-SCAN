import shutil, textwrap, os
from colorama import Fore, Style, init
init(autoreset=True)

# Colors
RED = Fore.RED
WHITE = Fore.WHITE
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

# --------------------------
# BASIC SETTINGS
# --------------------------

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def term_width():
    return shutil.get_terminal_size((100, 28)).columns

def center_text(s):
    w = term_width()
    if len(s) >= w:
        return s
    pad = (w - len(s)) // 2
    return " " * pad + s

# --------------------------
# REQUIRED LEGAL BLOCK (FIXES ERROR)
# --------------------------

LEGAL = [
    "This tool performs ONLY passive OSINT.",
    "No exploitation. No unauthorized attacks.",
    "Use responsibly. Educational purpose only."
]

# --------------------------
# BANNER
# --------------------------

BANNER = [
    "",
    BOLD + center_text(" ██ ▄█▀ ▒█████   ██▒   █▓") + RED,
    BOLD + center_text(" ██▄█▒ ▒██▒  ██▒▓██░   █▒") + RED,
    BOLD + center_text("▓███▄░ ▒██░  ██▒ ▓██  █▒░") + RED,
    BOLD + center_text("▓██ █▄ ▒██   ██░  ▒██ █░░") + RED,
    BOLD + center_text("▒██▒ █▄░ ████▓▒░   ▒▀█░  ") + RED,
    BOLD + center_text("▒ ▒▒ ▓▒░ ▒░▒░▒░    ░ ▐░  ") + RED,
    BOLD + center_text("░ ░▒ ▒░  ░ ▒ ▒░    ░ ░░  ") + RED,
    BOLD + center_text("░ ░░ ░ ░ ░ ░ ▒       ░░  ") + RED,
    BOLD + center_text("░  ░       ░ ░        ░  ") + RED,
    BOLD + center_text("                     ░   ") + RED,
    "",
    center_text(BOLD + "KOV EXTREME - PASSIVE INTELLIGENCE" + RESET),
    center_text(BOLD + "DEVELOPED BY - D4RK-K1NG" + YELLOW),
    ""
]

def show_title():
    clear()  # 🔥 FIXED — clears screen before banner
    print("\n")
    for l in BANNER:
        print(l)
    print("\n")
    for l in LEGAL:
        print(center_text(l))
    print("\n")

def input_prompt(prompt):
    return input(Fore.LIGHTGREEN_EX + prompt + Fore.WHITE)

# --------------------------
# CHAIN REPORT PRINTER
# --------------------------

def print_chain_report(res):
    host = res.get("target","-")
    ip = res.get("ip","-")

    lines = []
    lines.append(f"[1] TARGET      : {host}")

    # IP info
    ipinfo = res.get("api_ipinfo") or {}
    ip_line = ip
    if isinstance(ipinfo, dict) and ipinfo.get("country"):
        ip_line += f" • {ipinfo.get('country','-')}"
        if ipinfo.get("isp"):
            ip_line += f" • {ipinfo.get('isp')}"
    lines.append(f"[2] IP INFO     : {ip_line}")

    # DNS
    dns_api = res.get("api_dnslookup")
    dnsline = "available" if dns_api else "none"
    lines.append(f"[3] DNS LOOKUP  : {dnsline}")

    # Tech Stack
    tw = res.get("api_whatweb")
    techline = tw.strip().splitlines()[0] if tw else "none"
    lines.append(f"[4] TECH STACK  : {techline}")

    # Subdomains
    subs = res.get("api_hostsearch")
    subsline = subs.strip().splitlines()[0] if subs else "none"
    lines.append(f"[5] SUBDOMAINS  : {subsline}")

    # Security headers
    pres = res.get("security_headers_present",[])
    miss = res.get("security_headers_missing",[])
    lines.append(f"[6] SEC-HEADERS : Present: {', '.join(pres) if pres else 'none'}")
    lines.append(f"     Missing: {', '.join(miss) if miss else 'none'}")

    # HTML notes
    htmln = res.get("html_notes",[])
    lines.append(f"[7] HTML CHECK  : {', '.join(htmln) if htmln else 'none'}")

    # Common paths
    cp = res.get("common_paths",[])
    lines.append(f"[8] COMMON PATHS: {len(cp)} found")

    # robots/sitemap
    rs = res.get("robots_sitemap",[])
    lines.append(f"[9] ROBOTS/SITE : {', '.join(rs) if rs else 'none'}")

    # Ports
    ports = res.get("ports",[])
    lines.append(f"[10] PORTS       : {', '.join(str(p) for p in ports) if ports else 'none'}")

    # WHOIS
    whois = res.get("api_whois")
    wl = "present" if whois else "none"
    lines.append(f"[11] WHOIS       : {wl}")

    # Summary
    lines.append(f"[12] SUMMARY     : {res.get('summary','-')}")

    # risk findings
    rlist = res.get("risk_findings", [])
    if rlist:
        lines.append(f"[13] RISK        : {len(rlist)} findings")
    else:
        lines.append(f"[13] RISK        : none")

    print_chain_box(lines, rlist)

def print_chain_box(lines, risk_list):
    tw = term_width()
    inner_w = min(max(len(l) for l in lines) + 6, tw - 6)

    top = RED + "+" + "-" * inner_w + "+" + RESET
    print("\n" + top)

    for l in lines:
        wrapped = textwrap.wrap(l, width=inner_w - 4) or [""]
        for wline in wrapped:
            content = "  " + wline.ljust(inner_w - 4) + "  "
            print(RED + "|" + RESET + WHITE + content + RESET + RED + "|" + RESET)

    print(RED + "|" + RESET + WHITE + "  " + ("-"*(inner_w-4)) + "  " + RESET + RED + "|" + RESET)

    if risk_list:
        print(RED + "|" + RESET + WHITE + "  " + "RISK DETAILS:".ljust(inner_w-4) + "  " + RESET + RED + "|" + RESET)
        for sev,msg in risk_list:
            line = f"{sev}: {msg}"
            wrapped = textwrap.wrap(line, width=inner_w - 4)
            for wline in wrapped:
                print(RED + "|" + RESET + WHITE + "  " + wline.ljust(inner_w - 4) + "  " + RESET + RED + "|" + RESET)
    else:
        print(RED + "|" + RESET + WHITE + "  " + "No passive risk findings.".ljust(inner_w-4) + "  " + RESET + RED + "|" + RESET)

    print(top + "\n")


def chain_report_interactive(res):
    print_chain_report(res)
