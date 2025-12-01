import sys, subprocess, pkgutil, importlib
import datetime, os

def ensure_requirements():
    reqs = ["requests","bs4","colorama"]
    missing = []
    for r in reqs:
        if not pkgutil.find_loader(r):
            missing.append(r)
    if missing:
        print("Missing Python packages detected. Installing:", ", ".join(missing))
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        except Exception as e:
            print("Auto-install failed. Please run: pip install -r requirements.txt")
            return False
    return True

def save_scan_to_file(scan_obj, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("KOV-SCAN - Passive Scan Report\n")
            f.write(f"Generated: {datetime.datetime.utcnow().isoformat()}Z\n\n")
            f.write(f"Target: {scan_obj.get('target')}\n")
            f.write(f"IP: {scan_obj.get('ip')}\n")
            f.write(f"Summary: {scan_obj.get('summary')}\n\n")
            f.write("--- HTTP HEADERS ---\n")
            for hk,hv in (scan_obj.get("headers") or {}).items():
                f.write(f"{hk}: {hv}\n")
            f.write("\n--- HTML NOTES ---\n")
            for n in scan_obj.get("html_notes", []):
                f.write(f"{n}\n")
            f.write("\n--- COMMON PATHS ---\n")
            for p,c in scan_obj.get("common_paths", []):
                f.write(f"/{p} -> {c}\n")
            f.write("\n--- API SNIPPETS (truncated) ---\n")
            for k in ("api_http_headers","api_whatweb","api_dnslookup","api_hostsearch","api_whois"):
                if scan_obj.get(k):
                    f.write(f"\n--- {k} ---\n")
                    val = scan_obj.get(k)
                    if isinstance(val, str):
                        f.write(val[:5000] + "\n")
                    else:
                        try:
                            f.write(str(val)[:5000] + "\n")
                        except:
                            pass
        return True
    except Exception as e:
        return False

def save_scan_prompt(scan_obj):
    ans = input("Save scan result? (y/n): ").strip().lower()
    if ans != "y":
        return
    fname = input("Filename (e.g. report.txt): ").strip()
    if not fname:
        fname = f"kov_{scan_obj.get('target','scan')}.txt"
    ok = save_scan_to_file(scan_obj, fname)
    if ok:
        print(f"Saved to {fname}")
    else:
        print("Failed to save file (permission?).")
