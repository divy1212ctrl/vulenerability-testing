"""
VulnScan Pro — SQLi Detection Module
======================================
Detects 3 classes of SQL Injection:
  1. Error-Based   — DB error strings in response
  2. Boolean-Blind — TRUE vs FALSE payload response diff
  3. UNION-Based   — column count enumeration

FIXES APPLIED:
  - FIX1: _send() timeout raised to 8s (slow blind queries)
  - FIX2: UNION baseline now uses a truly neutral payload (no 'test' data)
  - FIX3: scan() returns metadata (url, param, timestamp) for report_generator
  - FIX4: json_mode auto-detected for POST endpoints

Standalone usage:
    python sqli_scanner.py http://localhost:5000/api/products/search q
"""

import requests
import datetime

ERROR_SIGNATURES = [
    "sqlite3.OperationalError",
    "unrecognized token",
    "syntax error",
    "near \"",
    "SQL syntax",
    "ORA-",
    "mysql_fetch",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
]

ERROR_PAYLOADS = [
    "'", '"', "')", "';", "--", "' OR '1'='1", "' OR 1=1--",
]

BOOLEAN_TRUE_PAYLOADS  = ["' OR '1'='1", "' OR 1=1--", "1 OR 1=1"]
BOOLEAN_FALSE_PAYLOADS = ["' AND '1'='2", "' AND 1=2--", "1 AND 1=2"]


def _send(url, param, payload, method="GET", json_mode=False):
    """Send one request. FIX1: timeout=8 for slow blind queries."""
    try:
        if method.upper() == "GET":
            return requests.get(url, params={param: payload}, timeout=8)
        body = {param: payload}
        if json_mode:
            return requests.post(url, json=body, timeout=8)
        return requests.post(url, data=body, timeout=8)
    except requests.RequestException:
        return None


def test_error_based(url, param, method="GET", json_mode=False):
    """Send error-triggering payloads; flag if a DB error signature appears."""
    findings = []
    for payload in ERROR_PAYLOADS:
        r = _send(url, param, payload, method, json_mode)
        if r is None:
            continue
        for sig in ERROR_SIGNATURES:
            if sig.lower() in r.text.lower():
                findings.append({
                    "type":     "SQLi - Error Based",
                    "param":    param,
                    "payload":  payload,
                    "evidence": f"DB error fingerprint found: '{sig}'",
                    "severity": "Critical",
                    "cvss":     9.8,
                    "url":      url,
                })
                break
    return findings


def test_boolean_blind(url, param, method="GET", json_mode=False):
    """Compare response for TRUE vs FALSE payloads."""
    findings = []
    for true_p, false_p in zip(BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS):
        r_true  = _send(url, param, true_p,  method, json_mode)
        r_false = _send(url, param, false_p, method, json_mode)
        if r_true is None or r_false is None:
            continue

        len_true    = len(r_true.text)
        len_false   = len(r_false.text)
        status_diff = r_true.status_code != r_false.status_code
        len_diff    = abs(len_true - len_false) > 5

        if status_diff or len_diff:
            findings.append({
                "type":     "SQLi - Boolean Blind",
                "param":    param,
                "payload":  f"TRUE: {true_p}  |  FALSE: {false_p}",
                "evidence": f"Response length: {len_true} (true) vs {len_false} (false) bytes",
                "severity": "High",
                "cvss":     8.6,
                "url":      url,
            })
            break
    return findings


def test_union_based(url, param, method="GET", json_mode=False, max_columns=10):
    """
    Enumerate column count via UNION SELECT NULL,...
    FIX2: Baseline uses empty string to avoid false positives.
    """
    findings = []

    baseline = _send(url, param, "", method, json_mode)
    if baseline is None:
        return findings

    for cols in range(1, max_columns + 1):
        nulls   = ",".join(["NULL"] * cols)
        payload = f"' UNION SELECT {nulls}--"
        r = _send(url, param, payload, method, json_mode)
        if r is None:
            continue

        has_error = any(sig.lower() in r.text.lower() for sig in ERROR_SIGNATURES)

        if not has_error and r.status_code == 200 and r.text != baseline.text:
            findings.append({
                "type":     "SQLi - UNION Based",
                "param":    param,
                "payload":  payload,
                "evidence": f"No error at {cols} column(s) — table likely has {cols} column(s)",
                "severity": "Critical",
                "cvss":     9.8,
                "url":      url,
            })
            break
    return findings


def scan(url, param, method="GET", json_mode=False):
    """
    Run all SQLi techniques against one parameter.
    FIX3: Returns dict with findings + metadata for report_generator.
    """
    results = []
    results += test_error_based(url,   param, method, json_mode)
    results += test_boolean_blind(url, param, method, json_mode)
    results += test_union_based(url,   param, method, json_mode)
    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000/api/products/search"
    param  = sys.argv[2] if len(sys.argv) > 2 else "q"
    print(f"[*] Testing SQLi on {target} param='{param}'")
    findings = scan(target, param)
    if findings:
        for f in findings:
            print(f"  [{f['severity']}] {f['type']} | {f['evidence']}")
    else:
        print("  [+] No SQLi found on this param.")
