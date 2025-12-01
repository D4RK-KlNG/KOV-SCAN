#python3
"""
×××××××××××××××××××××××××××××××××××××××××××××
KOV-SCAN - Entry point
Developed by D4RK-K1NG (educational only)
×××××××××××××××××××××××××××××××××××××××××××××
"""

import sys
from ui.printer import show_title, chain_report_interactive, input_prompt
from scanners.passive_checks import all_in_one_passive
from utils.helpers import ensure_requirements, save_scan_prompt


ensure_requirements()

def main_loop():
    show_title()
    last_scan = None
    while True:
        print()
        cmd = input_prompt("Command (type 'help' for options): ").strip().lower()
        if cmd in ("exit","quit","q"):
            print("\nExiting Kov Extreme. Stay legal.")
            break
        if cmd in ("help","?"):
            print("""
Commands:
  allinone   - run full passive All-in-One scan (APIs + local)
  save       - save last scan to file
  help       - this help
  exit       - quit
""")
            continue
        if cmd == "allinone":
            target = input_prompt("Target (example.com or https://example.in): ").strip()
            if not target:
                print("No target provided.")
                continue
            print()
            try:
                res = all_in_one_passive(target)
            except Exception as e:
                print("Scan failed:", e)
                continue
            last_scan = res
            chain_report_interactive(res)
            save_scan_prompt(res)
            cont = input_prompt("Scan another? (y/n): ").strip().lower()
            if cont == "y":
                show_title()
                continue
            else:
                show_title()
                continue
        elif cmd == "save":
            if not last_scan:
                print("No prior scan available. Run allinone first.")
                continue
            save_scan_prompt(last_scan)
            continue
        elif cmd == "":
            continue
        else:
            print("Unknown command. Type 'help'.")

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)
