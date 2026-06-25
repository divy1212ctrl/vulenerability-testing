"""
VulnScan Pro — Main CLI Entry Point
=====================================
Orchestrates all scanner modules and produces the final report.

Usage:
    python main.py --target http://localhost:5000
    python main.py --target http://localhost:5000 --format html
    python main.py --target http://localhost:5000 --format pdf
    python main.py --target http://localhost:5000 --format both --out ./my-reports
    python main.py --target http://localhost:5000 --serve   # Also start Flask API
"""

import argparse
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from sqli_scanner     import scan          as sqli_scan
from xss_scanner      import test_reflected, test_stored
from header_analyzer  import analyze       as header_analyze
from report_generator import generate_report


def build_scan_plan(target: str) -> list[dict]:
    t = target.rstrip("/")
    return [
        {
            "label":   "SQLi: Login endpoint (username param)",
            "fn":      sqli_scan,
            "kwargs":  {"url": f"{t}/api/login",  "param": "username",
                        "method": "POST", "json_mode": True},
        },
        {
            "label":   "SQLi: Login endpoint (password param)",
            "fn":      sqli_scan,
            "kwargs":  {"url": f"{t}/api/login",  "param": "password",
                        "method": "POST", "json_mode": True},
        },
        {
            "label":   "SQLi: Product search (q param)",
            "fn":      sqli_scan,
            "kwargs":  {"url": f"{t}/api/products/search", "param": "q"},
        },
        {
            "label":   "SQLi: User exists (username param)",
            "fn":      sqli_scan,
            "kwargs":  {"url": f"{t}/api/user/exists", "param": "username"},
        },
        {
            "label":   "XSS Reflected: /api/xss/reflect (name param)",
            "fn":      test_reflected,
            "kwargs":  {"url": f"{t}/api/xss/reflect", "param": "name"},
        },
        {
            "label":   "XSS Stored: /api/xss/comment → /api/xss/comments",
            "fn":      test_stored,
            "kwargs":  {
                "submit_url":    f"{t}/api/xss/comment",
                "view_url":      f"{t}/api/xss/comments",
                "content_param": "content",
                "extra_fields":  {"user": "scanner"},
                "json_mode":     True,
            },
        },
        {
            "label":   "Security Headers: /",
            "fn":      header_analyze,
            "kwargs":  {"url": f"{t}/"},
        },
        {
            "label":   "Security Headers: /api/login",
            "fn":      header_analyze,
            "kwargs":  {"url": f"{t}/api/login"},
        },
    ]


def check_idor(target: str) -> list[dict]:
    import requests
    findings = []
    t = target.rstrip("/")

    for order_id in [1, 2]:
        url = f"{t}/api/orders/{order_id}"
        try:
            r = requests.get(url, timeout=8)
        except requests.RequestException:
            continue

        if r.status_code == 200:
            data = {}
            try:
                data = r.json()
            except Exception:
                pass

            evidence = "Order data returned without authentication"
            if "credit_card" in data:
                evidence = f"credit_card exposed: {data['credit_card']}"

            findings.append({
                "type":     "IDOR - Broken Access Control",
                "param":    f"order_id={order_id}",
                "payload":  f"GET /api/orders/{order_id} (no auth)",
                "evidence": evidence,
                "severity": "Critical",
                "cvss":     9.1,
                "url":      url,
            })

    return findings


def check_jwt_tampering(target: str) -> list[dict]:
    import requests
    findings = []
    t = target.rstrip("/")

    try:
        r_forge = requests.get(f"{t}/api/jwt/forge", params={"role": "admin"}, timeout=8)
        if r_forge.status_code != 200:
            return findings

        token = r_forge.json().get("forged_token", "")
        if not token:
            return findings

        r_admin = requests.get(
            f"{t}/api/jwt/admin",
            headers={"Authorization": f"Bearer {token}"},
            timeout=8
        )

        if r_admin.status_code == 200:
            findings.append({
                "type":     "JWT Role Tampering",
                "param":    "Authorization header",
                "payload":  f"Bearer {token[:60]}...",
                "evidence": "Forged admin JWT accepted — weak/exposed secret used",
                "severity": "Critical",
                "cvss":     9.8,
                "url":      f"{t}/api/jwt/admin",
            })
    except requests.RequestException:
        pass

    return findings


def check_csrf(target: str) -> list[dict]:
    import requests
    findings = []
    t = target.rstrip("/")
    url = f"{t}/api/csrf/transfer"

    try:
        r = requests.post(url, json={"to": "attacker", "amount": "1000"}, timeout=8)
        if r.status_code == 200:
            findings.append({
                "type":     "CSRF - Missing Token Validation",
                "param":    "POST body",
                "payload":  '{"to": "attacker", "amount": "1000"}',
                "evidence": "State-changing request accepted without CSRF token",
                "severity": "High",
                "cvss":     7.5,
                "url":      url,
            })
    except requests.RequestException:
        pass

    return findings


# ──────────────────────────────────────────────────────────
# TERMINAL OUTPUT HELPERS
# ──────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": "\033[91m",
    "High":     "\033[93m",
    "Medium":   "\033[94m",
    "Low":      "\033[96m",
    "Info":     "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_banner():
    print(f"""{BOLD}\033[91m
 __   __       _       ____                  ____
 \\ \\ / /  _  | |_ __ / ___|  ___ __ _ _ __ |  _ \\ _ __ ___
  \\ V / || | | | '_ \\\\___ \\ / __/ _` | '_ \\| |_) | '__/ _ \\
   | || |_| | | | | | |___) | (_| (_| | | | |  __/| | | (_) |
   |_| \\__,_|_|_|_| |_|____/ \\___\\__,_|_| |_|_|   |_|  \\___/
{RESET}
  {BOLD}VulnScan Pro{RESET} — Automated Web Vulnerability Scanner
  For authorized security testing and education only.
""")


def print_finding(f: dict):
    sev    = f.get("severity", "Info")
    color  = SEVERITY_COLORS.get(sev, "")
    print(f"  {color}[{sev}]{RESET} {f['type']}")
    print(f"         Param   : {f.get('param','-')}")
    print(f"         Payload : {str(f.get('payload','-'))[:80]}")
    print(f"         Evidence: {f.get('evidence','-')}")
    print(f"         URL     : {f.get('url','-')}")
    print()


def print_summary(findings: list[dict]):
    counts = {}
    for f in findings:
        s = f.get("severity", "Info")
        counts[s] = counts.get(s, 0) + 1

    print(f"\n{BOLD}── SCAN SUMMARY ──────────────────────────────{RESET}")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        c = counts.get(sev, 0)
        if c:
            print(f"  {_color(sev, sev):20s}  {c}")
    print(f"  {'Total':20s}  {len(findings)}")
    print()


def save_json_results(findings: list[dict], target: str, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "target":     target,
        "timestamp":  datetime.datetime.now().isoformat(),
        "total":      len(findings),
        "findings":   findings,
    }
    path = os.path.join(out_dir, "results.json")
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
    print(f"[*] JSON results saved → {path}")
    return path


def run_scan(target: str, out_dir: str = "reports", fmt: str = "html") -> list[dict]:
    print_banner()
    print(f"[*] Target  : {target}")
    print(f"[*] Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Output  : {out_dir}/\n")

    all_findings: list[dict] = []
    plan = build_scan_plan(target)

    for i, task in enumerate(plan, 1):
        label = task["label"]
        print(f"[{i}/{len(plan) + 3}] {label} ...", end=" ", flush=True)
        t0 = time.time()
        try:
            results = task["fn"](**task["kwargs"])
            elapsed = time.time() - t0
            count   = len(results)
            all_findings.extend(results)
            status = _color("Critical", f"{count} finding(s)") if count else "\033[32mclean\033[0m"
            print(f"{status}  ({elapsed:.1f}s)")
            for f in results:
                print_finding(f)
        except Exception as exc:
            print(f"\033[91mERROR: {exc}\033[0m")

    extra_tasks = [
        (f"[{len(plan)+1}/{len(plan)+3}] IDOR: /api/orders/<id>",          check_idor,          target),
        (f"[{len(plan)+2}/{len(plan)+3}] JWT: Role tampering via /api/jwt", check_jwt_tampering, target),
        (f"[{len(plan)+3}/{len(plan)+3}] CSRF: /api/csrf/transfer",         check_csrf,          target),
    ]
    for label, fn, arg in extra_tasks:
        print(f"{label} ...", end=" ", flush=True)
        t0 = time.time()
        try:
            results = fn(arg)
            elapsed = time.time() - t0
            count   = len(results)
            all_findings.extend(results)
            status = _color("Critical", f"{count} finding(s)") if count else "\033[32mclean\033[0m"
            print(f"{status}  ({elapsed:.1f}s)")
            for f in results:
                print_finding(f)
        except Exception as exc:
            print(f"\033[91mERROR: {exc}\033[0m")

    print_summary(all_findings)
    save_json_results(all_findings, target, out_dir)

    formats = ("html", "pdf") if fmt == "both" else (fmt,)
    paths   = generate_report(all_findings, target=target, out_dir=out_dir, formats=formats)
    for fmt_key, path in paths.items():
        print(f"[✓] {fmt_key.upper()} report → {path}")

    return all_findings


def parse_args():
    p = argparse.ArgumentParser(
        description="VulnScan Pro — Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target http://localhost:5000
  python main.py --target http://localhost:5000 --format both
  python main.py --target http://localhost:5000 --out ./my-reports --format pdf
        """,
    )
    p.add_argument("--target", "-t", required=True,
                   help="Base URL of target (e.g. http://localhost:5000)")
    p.add_argument("--format", "-f", choices=["html", "pdf", "both"], default="html",
                   help="Report format (default: html)")
    p.add_argument("--out", "-o", default="reports",
                   help="Output directory for reports (default: reports/)")
    p.add_argument("--serve", "-s", action="store_true",
                   help="Start the Flask API server after scan")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    findings = run_scan(args.target, out_dir=args.out, fmt=args.format)

    if args.serve:
        try:
            from api_server import create_app
            flask_app = create_app(results_dir=args.out)
            print(f"\n[*] API server starting on http://localhost:8000")
            print("[*] Dashboard can now connect at http://localhost:3000\n")
            flask_app.run(host="0.0.0.0", port=8000, debug=False)
        except ImportError as e:
            print(f"\n[!] Could not start API server: {e}")
            print("    Run: pip install flask flask-cors")
