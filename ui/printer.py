import shutil, textwrap, os, json
from colorama import Fore, Style, init
init(autoreset=True)

# Colors
RED = Fore.RED
WHITE = Fore.WHITE
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

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

LEGAL = [
    "This tool performs ONLY passive OSINT.",
    "No exploitation. No unauthorized attacks.",
    "Use responsibly. Educational purpose only."
]

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
    clear()
    print("\n")
    for l in BANNER:
        print(l)
    print("\n")
    for l in LEGAL:
        print(center_text(l))
    print("\n")

def input_prompt(prompt):
    return input(Fore.LIGHTGREEN_EX + prompt + Fore.WHITE)


def print_chain_report(res):
    if not isinstance(res, dict):
        print("No result to print.")
        return

    host = res.get("target","-")
    ip = res.get("ip","-")
    
    lines = []
    lines.append(f"[1] TARGET      : {host}")
    lines.append(f"[2] IP INFO     : {ip} • {res.get('api_ipinfo',{}).get('country','-') if isinstance(res.get('api_ipinfo',{}),dict) else '-'}")
    lines.append(f"[3] DNS LOOKUP  : {'available' if res.get('api_dnslookup') else 'none'}")

    tw = res.get("api_whatweb")
    techline = (tw.strip().splitlines()[0] if isinstance(tw,str) and tw.strip() else ("; ".join(res.get('api_threatminer',{}).keys()) if res.get('api_threatminer') else "none"))
    lines.append(f"[4] TECH STACK  : {techline}")

    lines.append(f"[5] SUBDOMAINS  : {res.get('api_hostsearch','none')}")

    pres = res.get("security_headers_present",[]) if res.get("security_headers_present") else []
    miss = res.get("security_headers_missing",[]) if res.get("security_headers_missing") else []
    headers = res.get("headers",{}) or {}

    if not pres and headers:
        for h in ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]:
            if h in headers:
                pres.append(h)
            else:
                miss.append(h)

    lines.append(f"[6] SEC-HEADERS : Present: {', '.join(pres) if pres else 'none'}")
    lines.append(f"     Missing: {', '.join(miss) if miss else 'none'}")

    lines.append(f"[7] HTML CHECK  : {', '.join(res.get('html_notes',[])) if res.get('html_notes') else 'none'}")

    # -------------------------
    #jji
    cp = res.get("common_paths", [])
    lines.append(f"[8] COMMON PATHS: {len(cp)} found")

    if cp:
        for p, code in cp:
            lines.append(f"    {p} → {code}")
            lines.append("")  # blank line
    else:
        lines.append("    none")
    # -------------------------

    lines.append(f"[9] ROBOTS/SITE : {', '.join(res.get('robots_sitemap',[])) if res.get('robots_sitemap') else 'none'}")
    lines.append(f"[10] PORTS       : {', '.join(str(p) for p in res.get('ports',[])) if res.get('ports') else 'none'}")
    lines.append(f"[11] WHOIS       : {'present' if res.get('api_whois') else 'none'}")
    lines.append(f"[12] SUMMARY     : {res.get('summary','-')}")
    
    rlist = res.get("risk_findings",[])
    lines.append(f"[13] RISK        : {len(rlist)} findings" if rlist else "[13] RISK        : none")

    print_chain_box(lines, rlist, res)


def print_chain_box(lines, risk_list, res):
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
            if sev in ["CRITICAL","HIGH"]: 
                color = YELLOW
            elif sev == "MEDIUM":
                color = CYAN
            else:
                color = GREEN
            
            line = f"{sev}: {msg}"
            wrapped = textwrap.wrap(line, width=inner_w - 4) or [""]
            for wline in wrapped:
                print(RED + "|" + RESET + color + "  " + wline.ljust(inner_w - 4) + "  " + RESET + RED + "|" + RESET)
    else:
        print(RED + "|" + RESET + WHITE + "  " + "No passive risk findings.".ljust(inner_w-4) + "  " + RESET + RED + "|" + RESET)

    print(RED + "|" + RESET + WHITE + "  " + ("-"*(inner_w-4)) + "  " + RESET + RED + "|" + RESET)

    # EXTRA
    try:
        apitxt = ""
        if res.get("api_whatweb"):
            apitxt = str(res.get("api_whatweb")).splitlines()[:3]
        elif res.get("api_threatminer"):
            apitxt = [str(res.get("api_threatminer"))[:200]]
        else:
            apitxt = []
        if apitxt:
            for line in apitxt:
                wrapped = textwrap.wrap(str(line), width=inner_w-4) or [""]
                for wline in wrapped:
                    print(RED + "|" + RESET + WHITE + "  " + wline.ljust(inner_w-4) + "  " + RESET + RED + "|" + RESET)
    except:
        pass

    print(top + "\n")


def chain_report_interactive(res):
    print_chain_report(res)
