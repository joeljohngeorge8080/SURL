#!/usr/bin/env python3
"""
SURL — Sentinel URL Command Line Tool (CMD Interface)
Access the SURL threat scanner directly from Command Prompt (CMD).

Dual Backend Support:
    1. Localhost  (http://localhost:8000)
    2. Cloud      (https://sentinelurl.site)

Usage:
    surl <URL>
    surl https://example.com
    surl https://example.com --local      (force localhost:8000)
    surl https://example.com --cloud      (force sentinelurl.site)
    surl https://example.com --both       (redirect to both local and cloud)
    surl https://example.com --site       (also directly open destination if safe)
    surl                                  (interactive prompt)
"""

import sys
import os
import json
import time
import urllib.parse
import urllib.request
import urllib.error
import webbrowser
import subprocess
import argparse
import asyncio

# Ensure standard output handles Unicode or fallbacks cleanly
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Enable Windows ANSI escape sequence support
if os.name == "nt":
    os.system("")

# ─────────────────────────────────────────────────────────────
# ANSI Color Codes
# ─────────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

LOCAL_BACKEND = "http://localhost:8000"
CLOUD_BACKEND = "https://sentinelurl.site"


def print_banner(active_backend: str = None):
    backend_line = f"|     Active Backend: {active_backend:<56} |" if active_backend else "|     Dual Backend Engine: [1] Localhost:8000  [2] sentinelurl.site            |"
    banner = f"""
{MAGENTA}{BOLD}+==============================================================================+
|     SURL - Sentinel URL Threat Intelligence & Security Scanner               |
{backend_line}
+==============================================================================+{RESET}
"""
    print(banner)


def normalize_url(url: str) -> str:
    """Ensure the URL has a valid http/https scheme."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_project_root() -> str:
    """Find the root directory of the SURL repository."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    if os.path.exists(os.path.join(parent_dir, "app", "main.py")):
        return parent_dir
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "app", "main.py")):
        return cwd
    return parent_dir


def is_server_running(server_url: str) -> bool:
    """Check if the given server is responsive."""
    url = server_url.rstrip("/")
    # For localhost, hit /health
    if "localhost" in url or "127.0.0.1" in url:
        check_url = f"{url}/health"
    else:
        check_url = url

    try:
        req = urllib.request.Request(
            check_url,
            headers={"User-Agent": "SURL-CMD/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return resp.status in (200, 301, 302)
    except Exception:
        return False


def get_uvicorn_python(project_root: str) -> str:
    """Find a Python binary that has uvicorn installed."""
    for candidate in [sys.executable, "python", os.path.join(project_root, "venv", "Scripts", "python.exe")]:
        try:
            res = subprocess.run([candidate, "-m", "uvicorn", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return candidate
        except Exception:
            continue
    return sys.executable


def start_local_server_background(project_root: str, port: int = 8000) -> bool:
    """Automatically start the local SURL server in the background if offline."""
    print(f"{YELLOW}[*] Local SURL server is not running. Starting it now...{RESET}")

    python_exe = get_uvicorn_python(project_root)

    cmd = [
        python_exe,
        "-m",
        "uvicorn",
        "app.main:app",
        "--port",
        str(port),
    ]

    try:
        if os.name == "nt":
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            subprocess.Popen(
                cmd,
                cwd=project_root,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        else:
            subprocess.Popen(
                cmd,
                cwd=project_root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )

        for _ in range(20):
            time.sleep(0.5)
            if is_server_running(f"http://localhost:{port}"):
                print(f"{GREEN}[OK] Localhost server started successfully on http://localhost:{port}{RESET}\n")
                return True

        print(f"{RED}[!] Timed out waiting for local server to spin up.{RESET}")
        return False

    except Exception as e:
        print(f"{RED}[!] Failed to launch local server: {e}{RESET}")
        return False


def resolve_backend(preference: str = "auto", custom_server: str = None) -> tuple[str, str]:
    """
    Determine the active backend URL and label based on user preference and availability.
    Returns (backend_url, backend_mode).
    """
    if custom_server:
        return custom_server.rstrip("/"), "custom"

    pref = preference.lower()

    if pref in ("both", "all"):
        return "both", "both"

    if pref in ("cloud", "sentinelurl", "sentinelurl.site"):
        return CLOUD_BACKEND, "sentinelurl.site"

    if pref in ("local", "localhost"):
        return LOCAL_BACKEND, "localhost"

    # Auto Mode:
    # 1. Check if localhost is alive
    if is_server_running(LOCAL_BACKEND):
        return LOCAL_BACKEND, "localhost"

    # 2. Check if cloud sentinelurl.site is reachable
    if is_server_running(CLOUD_BACKEND):
        return CLOUD_BACKEND, "sentinelurl.site"

    # 3. If neither responds, default to localhost (will attempt auto-start)
    return LOCAL_BACKEND, "localhost"


def run_internal_scan(url: str, project_root: str) -> dict:
    """Run scan directly via internal Python modules if HTTP API is unavailable."""
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    try:
        from app.services.scan_orchestrator import scan_url as orchestrator_scan
        res = asyncio.run(orchestrator_scan(url))
        return res if isinstance(res, dict) else res.dict()
    except Exception as e:
        return {"error": f"Internal scan engine error: {e}"}


def perform_scan(url: str, backend_url: str, project_root: str) -> dict:
    """Perform threat scan using the target backend API with intelligent fallback."""
    # If mode is 'both', use localhost for the API call if available, else cloud
    primary_backend = LOCAL_BACKEND if backend_url in ("both", LOCAL_BACKEND) else backend_url

    endpoint = f"{primary_backend.rstrip('/')}/scan"
    payload = json.dumps({"url": url}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SURL-CMD/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, Exception) as api_err:
        # If API HTTP request failed (e.g. CloudFront blocked POST or local server error),
        # run the internal scan engine directly!
        print(f"{DIM}[*] API call to {primary_backend} encountered {api_err.__class__.__name__}. Using internal analysis engine...{RESET}")
        return run_internal_scan(url, project_root)


def display_results(result: dict, target_url: str, backend_label: str):
    """Format and print threat intelligence analysis to CMD."""
    if "error" in result:
        print(f"{RED}[!] Scan Error: {result['error']}{RESET}\n")
        return

    severity = (result.get("severity") or "Unknown").upper()
    risk_score = result.get("risk_score", 0)
    safety_score = result.get("safety_score", max(0, 100 - risk_score))
    transport_risk = result.get("transport_risk", 0)
    phishing_risk = result.get("phishing_risk", 0)
    confidence = result.get("confidence_score", 0)
    pbh = result.get("pbh_fingerprint", "N/A")

    if severity == "LOW":
        sev_color = GREEN
        badge = f"{GREEN}[ VERIFIED SAFE / LOW RISK ]{RESET}"
    elif severity in ("MEDIUM", "MEDIUM-HIGH"):
        sev_color = YELLOW
        badge = f"{YELLOW}[ CAUTION / MODERATE RISK ]{RESET}"
    else:
        sev_color = RED
        badge = f"{RED}[ ALERT / HIGH RISK - SUSPICIOUS ]{RESET}"

    if safety_score >= 80:
        score_color = GREEN
    elif safety_score >= 50:
        score_color = YELLOW
    else:
        score_color = RED

    sep = "-" * 70
    print(f"\n{CYAN}{BOLD}--- SCAN RESULTS FOR:{RESET} {WHITE}{BOLD}{target_url}{RESET}")
    print(f"{DIM}    Evaluated via Backend: {backend_label}{RESET}")
    print(f"{CYAN}{sep}{RESET}")
    print(f" {BOLD}Overall Verdict:{RESET}       {badge}")
    print(f" {BOLD}Safety Score:{RESET}          {score_color}{BOLD}{safety_score}/100{RESET}  {DIM}(Risk: {risk_score}/100){RESET}")
    print(f" {BOLD}Phishing Risk:{RESET}         {YELLOW if phishing_risk > 20 else GREEN}{phishing_risk}/100{RESET}")
    print(f" {BOLD}Transport/SSL Risk:{RESET}    {YELLOW if transport_risk > 20 else GREEN}{transport_risk}/100{RESET}")
    print(f" {BOLD}Confidence Score:{RESET}      {CYAN}{confidence}%{RESET}")
    print(f" {BOLD}PBH Fingerprint:{RESET}       {DIM}{pbh[:32]}...{RESET}")
    print(f"{CYAN}{sep}{RESET}")

    summary = result.get("executive_summary")
    if summary:
        print(f"\n{BOLD}Executive Summary:{RESET}")
        print(f" {WHITE}{summary}{RESET}")

    indicators = result.get("detailed_analysis", [])
    if indicators:
        print(f"\n{BOLD}Detected Indicators ({len(indicators)}):{RESET}")
        for idx, item in enumerate(indicators[:4], 1):
            ind_sev = item.get("severity", "Low")
            ind_name = item.get("indicator", "Indicator")
            remed = item.get("remediation_strategy", "")
            icon = f"{RED}[!] {RESET}" if ind_sev == "High" else f"{YELLOW}[^] {RESET}" if ind_sev == "Medium" else f"{GREEN}[+] {RESET}"
            print(f"  {icon}{BOLD}{ind_name}{RESET} {DIM}[{ind_sev}]{RESET}")
            if remed:
                print(f"      Action: {remed}")

    print(f"\n{CYAN}{sep}{RESET}")


def redirect_to_sites(target_url: str, backend_mode: str, backend_url: str, direct_site: bool = False, is_safe: bool = True):
    """Directly open browser to SURL results site (Localhost, sentinelurl.site, or Both)."""
    encoded_url = urllib.parse.quote(target_url, safe="")

    target_redirects = []

    if backend_mode == "both":
        target_redirects.append(("Localhost Dashboard", f"{LOCAL_BACKEND}/results?url={encoded_url}"))
        target_redirects.append(("Cloud Portal (sentinelurl.site)", f"{CLOUD_BACKEND}/?url={encoded_url}"))
    elif backend_mode == "sentinelurl.site" or "sentinelurl" in backend_url:
        target_redirects.append(("Cloud Portal (sentinelurl.site)", f"{CLOUD_BACKEND}/?url={encoded_url}"))
    else:
        target_redirects.append(("Localhost Dashboard", f"{LOCAL_BACKEND}/results?url={encoded_url}"))

    print(f"\n{CYAN}[>>> REDIRECTING TO SURL SITE]{RESET}")
    for name, dest in target_redirects:
        print(f"  {WHITE}Opening {name}:{RESET} {CYAN}{dest}{RESET}")
        try:
            webbrowser.open(dest)
        except Exception as e:
            print(f"  {YELLOW}[!] Could not launch browser for {name}: {e}{RESET}")

    print(f"  {GREEN}[OK] Site opened in your default browser!{RESET}")

    if direct_site:
        if is_safe:
            print(f"\n{GREEN}[>>> DIRECT REDIRECT TO DESTINATION]{RESET}")
            print(f"  Opening destination site: {target_url}")
            time.sleep(0.5)
            webbrowser.open(target_url)
        else:
            print(f"\n{RED}[!] SAFETY WARNING:{RESET} Direct destination redirect blocked because security risks were detected.")
            print(f"  Review details on the SURL dashboard before proceeding.")


def main():
    parser = argparse.ArgumentParser(
        description="SURL — Sentinel URL: Threat Intelligence & Scanner via CMD"
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="The URL to scan (e.g. https://example.com or example.com)",
    )
    parser.add_argument(
        "-b",
        "--backend",
        choices=["auto", "local", "cloud", "both"],
        default="auto",
        help="Backend environment: 'auto' (default), 'local' (http://localhost:8000), 'cloud' (https://sentinelurl.site), or 'both'",
    )
    parser.add_argument(
        "-l",
        "--local",
        action="store_true",
        help="Force Localhost backend (http://localhost:8000)",
    )
    parser.add_argument(
        "-c",
        "--cloud",
        action="store_true",
        help="Force Cloud backend (https://sentinelurl.site)",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Redirect to BOTH Localhost and sentinelurl.site in browser",
    )
    parser.add_argument(
        "-s",
        "--site",
        action="store_true",
        help="Also directly open the destination website if verified safe",
    )
    parser.add_argument(
        "-n",
        "--no-browser",
        action="store_true",
        help="Do not open the browser, show terminal report only",
    )
    parser.add_argument(
        "--server",
        default=None,
        help="Custom server URL override",
    )

    args = parser.parse_args()

    # Determine backend preference
    backend_pref = args.backend
    if args.local:
        backend_pref = "local"
    elif args.cloud:
        backend_pref = "cloud"
    elif args.both:
        backend_pref = "both"

    project_root = get_project_root()
    backend_url, backend_label = resolve_backend(backend_pref, custom_server=args.server)

    print_banner(f"{backend_label.upper()} ({backend_url})")

    target_url = args.url

    # Interactive prompt if no URL argument provided
    if not target_url:
        print(f"{WHITE}Give any URL to analyze and directly redirect to the SURL report:{RESET}")
        try:
            target_url = input(f"{CYAN}{BOLD}Enter URL > {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

        if not target_url or target_url.lower() in ("q", "quit", "exit"):
            print("Exiting.")
            sys.exit(0)

    target_url = normalize_url(target_url)
    print(f"\n{CYAN}[*] Target URL:{RESET} {BOLD}{target_url}{RESET}")

    # Ensure local server is started if local backend is selected/needed
    if backend_label in ("localhost", "both") or (backend_label == "custom" and "localhost" in backend_url):
        if not is_server_running(LOCAL_BACKEND):
            started = start_local_server_background(project_root)
            if not started and backend_pref == "auto":
                print(f"{YELLOW}[*] Falling back to Cloud Backend ({CLOUD_BACKEND})...{RESET}")
                backend_url, backend_label = CLOUD_BACKEND, "sentinelurl.site"

    print(f"{GREEN}[OK] Connected with backend: {BOLD}{backend_label}{RESET} ({backend_url})")

    # Run Threat Scan
    print(f"{CYAN}[*] Running multi-stage threat intelligence scan...{RESET}")
    scan_start = time.time()
    result = perform_scan(target_url, backend_url=backend_url, project_root=project_root)
    elapsed = round(time.time() - scan_start, 2)
    print(f"{GREEN}[OK] Scan completed in {elapsed}s{RESET}")

    # Display results
    display_results(result, target_url, backend_label)

    # Determine safety
    severity = (result.get("severity") or "Low").upper()
    risk_score = result.get("risk_score", 0)
    is_safe = severity == "LOW" and risk_score < 50

    # Redirection
    if not args.no_browser:
        redirect_to_sites(
            target_url=target_url,
            backend_mode=backend_label,
            backend_url=backend_url,
            direct_site=args.site,
            is_safe=is_safe,
        )

        if not args.site and is_safe and not args.url:
            try:
                choice = input(f"\n{CYAN}[?] Destination verified safe. Open {target_url} directly too? [y/N]: {RESET}").strip().lower()
                if choice in ("y", "yes"):
                    webbrowser.open(target_url)
            except (KeyboardInterrupt, EOFError):
                pass

    print(f"\n{GREEN}{BOLD}[OK] Done.{RESET}\n")


if __name__ == "__main__":
    main()
