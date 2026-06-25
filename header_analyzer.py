"""
VulnScan Pro — Header Analyzer Module
=======================================
Checks HTTP response headers against security best practices.

FIXES APPLIED:
  - FIX1: Referrer-Policy aur Permissions-Policy bhi check karta hai
  - FIX2: HSTS min-age value check (too short = misconfigured)
  - FIX3: X-Powered-By leakage detect karta hai
  - FIX4: analyze() agar redirect ho toh final URL check karta hai
"""

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High", "cvss": 6.1,
        "advice": "Add a CSP to restrict script/style sources and mitigate XSS impact."
    },
    "X-Frame-Options": {
        "severity": "Medium", "cvss": 4.3,
        "advice": "Set to DENY or SAMEORIGIN to prevent clickjacking."
    },
    "X-Content-Type-Options": {
        "severity": "Low", "cvss": 3.1,
        "advice": "Set to 'nosniff' to stop MIME-type sniffing attacks."
    },
    "Strict-Transport-Security": {
        "severity": "Medium", "cvss": 5.3,
        "advice": "Enforce HTTPS via HSTS in production. min-age >= 31536000 recommended.",
        "special": "hsts_check"
    },
    "X-XSS-Protection": {
        "severity": "Low", "cvss": 2.7,
        "advice": "Legacy header, but still flagged by many scanners if missing."
    },
    "Referrer-Policy": {
        "severity": "Low", "cvss": 2.5,
        "advice": "Set to 'no-referrer' or 'strict-origin' to limit info leakage."
    },
    "Permissions-Policy": {
        "severity": "Low", "cvss": 2.5,
        "advice": "Set Permissions-Policy to restrict camera, mic, geolocation features."
    },
    "Set-Cookie": {
        "severity": "High", "cvss": 6.5,
        "advice": "Cookies should set HttpOnly, Secure, and SameSite attributes.",
        "special": "cookie_flags"
    },
}


def analyze(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
    except requests.RequestException as e:
        return [{"type": "Header Analysis - Error", "severity": "Info", "cvss": 0,
                 "evidence": str(e), "url": url, "param": "-", "payload": "-"}]

    headers   = r.headers
    final_url = r.url

    for header, meta in SECURITY_HEADERS.items():
        if meta.get("special") == "cookie_flags":
            cookie = headers.get("Set-Cookie", "")
            if cookie:
                missing = [f for f, k in [("HttpOnly","httponly"),("Secure","secure"),("SameSite","samesite")]
                           if k not in cookie.lower()]
                if missing:
                    findings.append({"type":"Insecure Cookie Flags","param":"Set-Cookie","payload":"-",
                        "evidence":f"Missing flags: {', '.join(missing)}",
                        "severity":meta["severity"],"cvss":meta["cvss"],"url":final_url})
            continue

        if meta.get("special") == "hsts_check":
            hsts = headers.get("Strict-Transport-Security","")
            if not hsts:
                findings.append({"type":"Missing Security Header","param":"Strict-Transport-Security",
                    "payload":"-","evidence":meta["advice"],"severity":meta["severity"],
                    "cvss":meta["cvss"],"url":final_url})
            else:
                for part in hsts.split(";"):
                    part = part.strip()
                    if part.lower().startswith("max-age"):
                        try:
                            age = int(part.split("=")[1].strip())
                            if age < 31536000:
                                findings.append({"type":"Weak HSTS max-age","param":"Strict-Transport-Security",
                                    "payload":"-","evidence":f"max-age={age} too short (need >= 31536000)",
                                    "severity":"Low","cvss":3.0,"url":final_url})
                        except (IndexError, ValueError):
                            pass
            continue

        if header not in headers:
            findings.append({"type":"Missing Security Header","param":header,"payload":"-",
                "evidence":meta["advice"],"severity":meta["severity"],"cvss":meta["cvss"],"url":final_url})

    for info_header, label in [("Server","Server banner"), ("X-Powered-By","X-Powered-By")]:
        val = headers.get(info_header,"")
        if val:
            findings.append({"type":"Information Disclosure","param":info_header,"payload":"-",
                "evidence":f"{label} reveals: '{val}'","severity":"Low","cvss":2.0,"url":final_url})

    return findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000/"
    print(f"[*] Analyzing headers for: {target}")
    for f in analyze(target):
        print(f"  [{f['severity']}] {f['type']} -> {f['evidence']}")
