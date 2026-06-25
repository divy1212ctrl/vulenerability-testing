#!/usr/bin/env python3
"""
VulnScan Pro - Scanner CLI
============================
Automated vulnerability scanner for the VulnApp target (or any similar app).

Usage:
    python scanner.py --target http://localhost:5000

    python scanner.py --target http://localhost:5000 --html-only
    python scanner.py --target http://localhost:5000 --pdf
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from modules import sqli_scanner, xss_scanner, header_analyzer, report_generator


def banner():
    print(r"""
 __      __       _       __ _              ___
 \ \    / /     | |     / _| |            |  __ \
  \ \  / /_   __| | __ | |_| | __ ___ ___ | |__) |_ __ ___
   \ \/ /| | / |  |/ / |  _| |/ // _` / _ \|  ___/| '__/ _ \
    \  / | |_| | |   <  | | |   <| (_| | | | | __| | | (_) |
     \/   \__,_|_|_|\_\ |_|_|_|\_\\__,_|_|_|_|_|   |_|  \___/

         VulnScan Pro — Automated Web Vulnerability Scanner
    """)


def run_scan(target):
    """Run the full scan suite against the target base URL. Returns findings list."""
    findings = []
    target = target.rstrip("/")

    print(f"[*] Target: {target}")
    print("[*] Starting scan...\n")

    # ── 1. Header Analysis ──
    print("[1/4] Analyzing security headers...")
    findings += header_analyzer.analyze(target + "/")
    print(f"      -> {len(findings)} finding(s) so far")

    # ── 2. SQLi — UNION/Boolean on product search ──
    print("[2/4] Testing SQL Injection (UNION/Boolean/Error)...")
    sqli_results = sqli_scanner.scan(target + "/api/products/search", "q", method="GET")
    findings += sqli_results
    print(f"      -> {len(sqli_results)} SQLi finding(s)")

    # Also test boolean-blind on the user/exists endpoint
    sqli_results2 = sqli_scanner.scan(target + "/api/user/exists", "username", method="GET")
    findings += sqli_results2
    print(f"      -> {len(sqli_results2)} more SQLi finding(s) on /api/user/exists")

    # ── 3. XSS — Reflected on /api/xss/reflect ──
    print("[3/4] Fuzzing for Reflected XSS...")
    xss_results = xss_scanner.test_reflected(target + "/api/xss/reflect", "name", method="GET")
    findings += xss_results
    print(f"      -> {len(xss_results)} reflected XSS finding(s)")

    # ── 4. XSS — Stored on /api/xss/comment + /api/xss/comments ──
    print("[4/4] Fuzzing for Stored XSS...")
    stored_results = xss_scanner.test_stored(
        submit_url=target + "/api/xss/comment",
        view_url=target + "/api/xss/comments",
        content_param="content",
        method="POST",
        extra_fields={"user": "vulnscan-bot"},
    )
    findings += stored_results
    print(f"      -> {len(stored_results)} stored XSS finding(s)")

    print(f"\n[*] Scan complete. Total findings: {len(findings)}")
    return findings


def print_summary(findings):
    severity_count = {}
    for f in findings:
        s = f.get("severity", "Info")
        severity_count[s] = severity_count.get(s, 0) + 1

    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in severity_count:
            print(f"  {sev:10s}: {severity_count[sev]}")
    print("=" * 50)

    for f in findings:
        print(f"\n[{f.get('severity')}] {f.get('type')}")
        print(f"   URL:      {f.get('url')}")
        print(f"   Param:    {f.get('param')}")
        print(f"   Evidence: {f.get('evidence')}")
        print(f"   CVSS:     {f.get('cvss')}")


def main():
    parser = argparse.ArgumentParser(description="VulnScan Pro - Automated Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Base URL of target, e.g. http://localhost:5000")
    parser.add_argument("--html-only", action="store_true", help="Generate only HTML report (skip PDF)")
    parser.add_argument("--pdf", action="store_true", help="Also generate a PDF report")
    parser.add_argument("--output-dir", default="reports", help="Directory to save reports")
    args = parser.parse_args()

    banner()
    start = time.time()
    findings = run_scan(args.target)
    print_summary(findings)

    html_path = report_generator.generate_html(
        findings, args.target, os.path.join(args.output_dir, "scan_report.html")
    )
    print(f"\n[*] HTML report saved -> {html_path}")

    if args.pdf and not args.html_only:
        pdf_path = report_generator.generate_pdf(
            findings, args.target, os.path.join(args.output_dir, "scan_report.pdf")
        )
        if pdf_path:
            print(f"[*] PDF report saved  -> {pdf_path}")

    elapsed = time.time() - start
    print(f"\n[*] Done in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
