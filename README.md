# 🛡️ VulnScan Pro

> **An intentionally vulnerable web application + automated security scanner + visual dashboard.**  
> Built for learning, demos, and portfolio showcasing. Do NOT deploy on a public server.

---

## 📁 Project Structure

```
VulnScan-Pro/
├── vulnapp/              # 🎯 Deliberately Vulnerable Flask Target App
│   ├── app.py
│   ├── database.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── scanner/              # 🔍 Python CLI Vulnerability Scanner + REST API
│   ├── main.py
│   ├── modules/
│   │   ├── sqli.py
│   │   ├── xss.py
│   │   ├── idor.py
│   │   ├── headers.py
│   │   ├── jwt_check.py
│   │   └── csrf.py
│   ├── report_gen.py
│   ├── api_server.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── dashboard/            # 📊 React Frontend Dashboard
│   ├── src/
│   │   └── App.jsx
│   ├── public/
│   ├── package.json
│   └── Dockerfile
│
├── crypto-demo/          # 🔐 Crypto Module (Hashing, JWT, Ciphers)
│   ├── crypto_demo.py
│   ├── server.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── reports/              # 📄 Generated HTML/JSON Scan Reports
├── docker-compose.yml    # 🐳 Spin up entire stack
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) + Docker Compose v2
- Git

### 1. Clone the repo
```bash
git clone https://github.com/<your-username>/VulnScan-Pro.git
cd VulnScan-Pro
```

### 2. Start everything with Docker Compose
```bash
docker compose up --build
```

### 3. Open in browser

| Service          | URL                        |
|------------------|----------------------------|
| 🎯 VulnApp       | http://localhost:5000      |
| 📊 Dashboard     | http://localhost:3000      |
| 🔍 Scanner API   | http://localhost:8000      |
| 🔐 Crypto Demo   | http://localhost:8080      |

### 4. Run a scan (CLI)
```bash
# Inside the scanner container
docker exec -it vulnscan_api python main.py --target http://vulnapp:5000 --format html

# Or directly on your machine (with Python 3.10+)
cd scanner
pip install -r requirements.txt
python main.py --target http://localhost:5000 --format html
```

---

## 🎯 VulnApp — Vulnerability List

| #  | Vulnerability              | Endpoint                        | Severity   |
|----|----------------------------|---------------------------------|------------|
| 1  | SQL Injection (Error)      | `POST /api/login`               | 🔴 Critical |
| 2  | SQL Injection (UNION)      | `GET  /api/products/search`     | 🔴 Critical |
| 3  | SQL Injection (Boolean)    | `GET  /api/user/exists`         | 🟠 High     |
| 4  | XSS — Reflected            | `GET  /api/xss/reflect`         | 🟠 High     |
| 5  | XSS — Stored               | `POST /api/xss/comments`        | 🔴 Critical |
| 6  | IDOR                       | `GET  /api/orders/<id>`         | 🔴 Critical |
| 7  | Broken Auth / JWT Tamper   | `GET  /api/jwt/admin`           | 🔴 Critical |
| 8  | CSRF                       | `POST /api/csrf/transfer`       | 🟠 High     |
| 9  | Missing Security Headers   | All routes                      | 🟠 High     |
| 10 | Insecure Cookie Flags      | Session cookie                  | 🟠 High     |
| 11 | Information Disclosure     | `Server` header                 | 🔵 Low      |

---

## 🔍 Scanner — How It Works

```
python main.py --target http://localhost:5000 --format html
```

**Modules:**

| Module         | Technique                                      |
|----------------|------------------------------------------------|
| `sqli.py`      | Error-based, UNION-based, Boolean blind        |
| `xss.py`       | Reflected + Stored payload fuzzing             |
| `idor.py`      | Sequential ID enumeration, auth bypass check   |
| `headers.py`   | Missing CSP, HSTS, X-Frame-Options, etc.       |
| `jwt_check.py` | Weak secret brute-force, alg:none, role tamper |
| `csrf.py`      | State-change request without token check       |

**Output:** HTML report saved to `reports/report_<timestamp>.html`

---

## 📊 Dashboard — Features

- 🗺️ **Vulnerability Radar** — Category-wise finding distribution
- 🥧 **Severity Pie** — Critical / High / Medium / Low breakdown
- 📊 **CVSS Bar Chart** — Top vulnerabilities by score
- 🎯 **Risk Meter** — Composite risk score (0–100)
- 📋 **Findings Table** — Filter, sort, expand payload + evidence
- 💻 **Scan Terminal** — Live log output during scan
- ⬇️ **Export JSON** — Download raw results

---

## 🔐 Crypto Demo — Modules

| Demo              | What it shows                                      |
|-------------------|----------------------------------------------------|
| MD5 vs bcrypt     | Why MD5 is broken for password storage             |
| Caesar cipher     | Classic cipher + brute-force break                 |
| JWT tampering     | Forging admin token with weak secret               |
| Hash cracker      | Dictionary attack on MD5 hashes                    |
| Weak cipher detect| Identify rot13/caesar/base64 obfuscation           |

---

## 🐳 Docker Services

```
vulnapp          → Flask vulnerable app     → :5000
vulnscan_api     → Python scanner + API     → :8000
vulnscan_dashboard → React (Nginx)          → :3000
vulnscan_crypto  → Crypto demo server       → :8080
```

All services share `vulnscan_net` bridge network so they can talk to each other by container name (e.g., `http://vulnapp:5000`).

---

## ⚠️ Disclaimer

> This project contains **intentional security vulnerabilities** for educational purposes.  
> **Never deploy this on a public server or production environment.**  
> Use only in isolated local/Docker environments.

---

## 🛠️ Tech Stack

| Layer      | Tech                                     |
|------------|------------------------------------------|
| Target App | Python 3.11, Flask, SQLite               |
| Scanner    | Python 3.11, requests, BeautifulSoup4, reportlab |
| Dashboard  | React 18, Recharts, TailwindCSS          |
| Crypto     | Python 3.11, hashlib, PyJWT, Flask       |
| DevOps     | Docker, Docker Compose v2, Nginx         |

---



```
reports/
├── report_sample.html     ← Open this in browser
└── results_sample.json    ← Raw findings JSON
```

---

## 👤 Author



---

*Made with 🔴 intentional vulnerabilities and ☕ coffee.*
