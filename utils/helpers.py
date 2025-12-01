
import sys, subprocess, pkgutil, importlib
import datetime

def ensure_requirements():
    
    reqs = ["requests","bs4","colorama"]
    missing = []
    for r in reqs:
        if not pkgutil.find_loader(r):
            missing.append(r)
    if missing:
        print("Missing Python packages detected. Installing:", ", ".join(missing))
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)

def save_scan_to_file(scan_obj, filename):
    try:
        # basic text
        with open(filename, "w", encoding="utf-8") as f:
            f.write("Kraken Extreme - Passive Scan Report\n")
            f.write(f"Generated: {datetime.datetime.utcnow().isoformat()}Z\n\n")
            for k in ("target","ip","summary"):
                if k in scan_obj:
                    f.write(f"{k.upper()}: {scan_obj.get(k)}\n")
            f.write("\n--- HTTP HEADERS ---\n")
            for hk,hv in scan_obj.get("headers", {}).items():
                f.write(f"{hk}: {hv}\n")
            f.write("\n--- HTML NOTES ---\n")
            for n in scan_obj.get("html_notes", []):
                f.write(f"{n}\n")
            f.write("\n--- RISK FINDINGS ---\n")
            for sev,msg in scan_obj.get("risk_findings", []):
                f.write(f"{sev}: {msg}\n")
            f.write("\n--- RAW API SNIPPETS (truncated) ---\n")
            for k in ("api_http_headers","api_whatweb","api_dnslookup","api_hostsearch","api_whois"):
                if scan_obj.get(k):
                    f.write(f"\n--- {k} ---\n")
                    val = scan_obj.get(k)
                    if isinstance(val, str):
                        f.write(val[:5000] + "\n")
                    else:
                        f.write(str(val)[:5000] + "\n")
        return True
    except Exception as e:
        return False

def save_scan_prompt(scan_obj):
    ans = input("Save scan result? (y/n): ").strip().lower()
    if ans != "y":
        return
    fname = input("Filename (e.g. report.txt): ").strip()
    if not fname:
        fname = f"kraken_{scan_obj.get('target','scan')}.txt"
    ok = save_scan_to_file(scan_obj, fname)
    if ok:
        print(f"Saved to {fname}")
    else:
        print("Failed to save file (permission?).")
