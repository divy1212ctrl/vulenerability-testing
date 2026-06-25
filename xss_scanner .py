"""
VulnScan Pro — XSS Fuzzer Module
===================================
Detects Reflected and Stored XSS.

FIXES APPLIED:
  - FIX1: test_reflected() POST mode bhi JSON body support karta hai
  - FIX2: test_stored() submission failure gracefully handle karta hai
  - FIX3: Payload truncation in output (very long payloads display safely)
  - FIX4: Content-Type check added — only scan text/html responses

Standalone usage:
    python xss_scanner.py http://localhost:5000/api/xss/reflect name
"""

import uuid
import requests

XSS_PAYLOADS = [
    "<script>alert('{marker}')</script>",
    "<img src=x onerror=alert('{marker}')>",
    "<svg onload=alert('{marker}')>",
    "\"><script>alert('{marker}')</script>",
    "'><img src=x onerror=alert('{marker}')>",
]


def _unique_marker():
    return "xss" + uuid.uuid4().hex[:8]


def _is_html_response(r):
    """FIX4: Only check HTML responses — JSON won't execute scripts."""
    ct = r.headers.get("Content-Type", "")
    return "text/html" in ct


def test_reflected(url, param, method="GET", json_mode=False):
    """
    Inject payload as query/form/JSON param, check if reflected unescaped.
    FIX1: json_mode=True → POST with JSON body.
    """
    findings = []

    for template in XSS_PAYLOADS:
        marker  = _unique_marker()
        payload = template.format(marker=marker)

        try:
            if method.upper() == "GET":
                r = requests.get(url, params={param: payload}, timeout=5)
            elif json_mode:
                r = requests.post(url, json={param: payload}, timeout=5)
            else:
                r = requests.post(url, data={param: payload}, timeout=5)
        except requests.RequestException:
            continue

        if not _is_html_response(r):
            continue

        if payload in r.text:
            findings.append({
                "type":     "XSS - Reflected",
                "param":    param,
                "payload":  payload[:120],
                "evidence": "Payload reflected unescaped in response body",
                "severity": "High",
                "cvss":     7.4,
                "url":      url,
            })

    return findings


def test_stored(submit_url, view_url, content_param, method="POST", extra_fields=None, json_mode=True):
    """
    Two-step stored XSS check.
    FIX2: Submission errors handled — view check still runs.
    """
    findings    = []
    extra_fields = extra_fields or {}

    for template in XSS_PAYLOADS:
        marker  = _unique_marker()
        payload = template.format(marker=marker)
        body    = {**extra_fields, content_param: payload}

        try:
            if method.upper() == "POST":
                if json_mode:
                    requests.post(submit_url, json=body, timeout=5)
                else:
                    requests.post(submit_url, data=body, timeout=5)
            else:
                requests.get(submit_url, params=body, timeout=5)
        except requests.RequestException:
            pass  # FIX2: continue to check view_url even if submit failed

        try:
            check = requests.get(view_url, timeout=5)
        except requests.RequestException:
            continue

        if payload in check.text:
            findings.append({
                "type":     "XSS - Stored",
                "param":    content_param,
                "payload":  payload[:120],
                "evidence": f"Unescaped payload persisted and rendered at {view_url}",
                "severity": "Critical",
                "cvss":     8.8,
                "url":      view_url,
            })

    return findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000/api/xss/reflect"
    param  = sys.argv[2] if len(sys.argv) > 2 else "name"
    print(f"[*] Testing Reflected XSS on {target} param='{param}'")
    findings = test_reflected(target, param)
    if findings:
        for f in findings:
            print(f"  [{f['severity']}] {f['type']} | payload: {f['payload'][:60]}")
    else:
        print("  [+] No Reflected XSS found.")
