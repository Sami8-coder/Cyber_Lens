# CyberLens – Explainable Web Security Posture Assessment and Reporting Platform

> **Academic Project:** CSE Web Engineering Capstone & Security Demonstration  
> **Status:** Production Ready & Verified  
> **Test Suite:** 18 Tests Passing (100% Pass Rate)

---

## 1. Project Overview

**CyberLens** is a full-stack, enterprise-grade web application engineered to perform **explainable, passive web security posture assessments**. Unlike traditional intrusive scanners that risk service disruptions or provide opaque numbers, CyberLens emphasizes **transparency, defense-in-depth, and actionable remediation**.

### Core Capabilities
1. **Explainable Vulnerability Findings:** Every identified defect clearly states *What was detected*, *Why it matters (Threat Context & Exploitation Risk)*, mapped to **OWASP Top 10 (2021)** and **MITRE CWE**, accompanied by copy-paste configuration snippets (Nginx, Apache, Django, Cloudflare).
2. **Defensive Passive Scanning Engine:** Multi-vector inspection of HTTP/HTTPS redirection, Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cookie flags (Secure, HttpOnly, SameSite), TLS/SSL X.509 certificates, and DNS email defenses (SPF, DMARC, CAA, DNSSEC).
3. **Transparent 0–100 Scoring & Grading:** Weighted composite scoring algorithm providing normalized ratings: **A+ (90–100)**, **A (80–89)**, **B (70–79)**, **C (50–69)**, **D (30–49)**, and **F (0–29)**.
4. **Audit-Ready ReportLab PDF Generation:** Multi-page executive and technical PDF reports with dynamic page counts, scorecards, domain ratings, findings tables, and formal disclaimers.
5. **Interactive Operations Dashboard:** Real-time metrics, grade distribution donut charts, category average benchmarks, top detected deficiencies, and quick-scan triggers.
6. **Side-by-Side Posture Comparison:** Differential analysis between two assessments to track security enhancements over time or compare staging vs production environments.
7. **Strict SSRF & Private Network Protection:** Multi-layered URL validation blocking RFC 1918 private subnets, loopbacks, cloud metadata (`169.254.169.254`), and DNS rebinding attacks.

---

## 2. Technology Stack

- **Backend Framework:** Python 3.13, Django 6.1 (Modular Architecture)
- **Database Engine:** PostgreSQL (Primary production engine via `psycopg2-binary`) with zero-config SQLite local development fallback
- **Frontend / UI:** HTML5, CSS3, JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons 1.11, Chart.js 4.4
- **Cryptography & TLS:** Python native `ssl`, `socket`, and `cryptography` (X.509 certificate decoding, SHA-256 signatures, SAN extraction)
- **DNS Analysis:** `dnspython` (A, AAAA, MX, TXT/SPF, _dmarc, CAA, DNSSEC inspection)
- **PDF Generation Engine:** ReportLab 5.x (`SimpleDocTemplate`, `TableStyle`, `NumberedCanvas`)
- **HTTP Client:** `requests` (with custom User-Agent, timeouts, and redirect hop validation)

---

## 3. Modular Architecture

The application is structured into specialized, decoupled Django apps:

```
Cyber_Lens/
├── accounts/          # User authentication, profile management, and API tokens
├── dashboard/         # Aggregated metrics, Chart.js analytics, and activity feeds
├── scans/             # Assessment model, submission forms, detail views, and comparison
├── scanner/           # Passive inspection engine (SSRF validation, TLS, DNS, HTTP)
├── analysis/          # Scoring algorithm, OWASP/CWE catalog, and explainability engine
├── reports/           # ReportLab PDF report generation and JSON exports
├── core/              # Global layout, landing page, documentation, and error handlers
├── templates/         # Centralized Bootstrap 5 Django templates
├── static/            # Centralized CSS design system, JavaScript, and SVG assets
├── cyberlens/         # Project settings, routing, and WSGI/ASGI configuration
├── manage.py          # Django management script
├── requirements.txt   # Locked Python package dependencies
├── .env.example       # Template environment variables
└── README.md          # Comprehensive documentation
```

### Module Responsibilities

| App | Key Classes / Functions | Responsibility |
| :--- | :--- | :--- |
| `scanner` | `SSRFValidator`, `HTTPScanner`, `TLSScanner`, `DNSScanner`, `ScanningEngine` | Safe, passive inspection across network protocols; enforces SSRF boundary. |
| `analysis` | `ScoringEngine`, `KNOWLEDGE_BASE` | Calculates weighted scores, letter grades, and generates explainable remediation text. |
| `reports` | `PDFReportGenerator`, `NumberedCanvas` | Compiles publication-grade PDF reports with running headers and scorecards. |
| `scans` | `Scan`, `ScanFinding`, `ScanRawData` | Stores audit records, findings, raw HTTP headers, certificates, and DNS data. |
| `dashboard`| `index_view` | Computes live stats, grade distributions, and category averages. |
| `accounts` | `UserProfile`, `UserRegistrationForm` | Handles RBAC, user profile initials, and automation API tokens. |

---

## 4. Security Scoring & Weighting Formula

The overall score is a composite index computed out of 100 points:

$$\text{Overall Score} = (\text{Headers} \times 0.35) + (\text{TLS} \times 0.25) + (\text{Cookies} \times 0.15) + (\text{DNS/Email} \times 0.15) + (\text{Infrastructure} \times 0.10)$$

### Category Weights

| Category | Weight | Evaluated Controls |
| :--- | :---: | :--- |
| **HTTP Security Headers** | **35%** | HSTS (`max-age >= 31536000`, `includeSubDomains`, `preload`), CSP (unsafe directives), X-Frame-Options (`DENY`/`SAMEORIGIN`), X-Content-Type-Options (`nosniff`), Referrer-Policy, Permissions-Policy, COOP/CORP. |
| **TLS / SSL Cryptography** | **25%** | Certificate validity, expiration horizon (>30 days), trusted CA chain, self-signed detection, signature algorithm (SHA-256+), modern protocol negotiation (TLS 1.2 / TLS 1.3). |
| **Cookie Protection** | **15%** | `Secure` attribute (HTTP transmission prevention), `HttpOnly` attribute (XSS theft mitigation), and `SameSite` attribute (CSRF defense). |
| **DNS & Email Defense** | **15%** | SPF record verification in TXT, DMARC policy at `_dmarc` (`p=reject`/`p=quarantine`), CAA authorization records, and DNSSEC keys. |
| **Infrastructure Exposure**| **10%** | Port 80 to 443 automatic redirection (301/302) and masking of Server / X-Powered-By software version banners. |

---

## 5. Defensive Scanning Policy & SSRF Protection

CyberLens strictly adheres to **safe, passive security assessment principles**:
1. **Zero Offensive Payloads:** Does not perform SQL injection, Cross-Site Scripting fuzzing, or port scanning.
2. **SSRF Mitigation:**
   - Hostnames are resolved to IP addresses before any connection is initiated.
   - Blocks private IPv4 address blocks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
   - Blocks loopback addresses: `127.0.0.0/8`, `::1`.
   - Blocks cloud metadata endpoints: `169.254.169.254`, `100.100.100.200`.
   - Disallows non-HTTP protocols (e.g., `file://`, `gopher://`, `ftp://`).
3. **Redirect Hop Verification:** Limits HTTP redirects to 5 hops, re-validating the resolved destination IP at every hop to prevent DNS rebinding or redirect-based SSRF.
4. **Timeouts:** Enforces strict socket timeouts (4 to 8 seconds) to prevent resource starvation.

---

## 6. Installation & Setup Guide

### Prerequisites
- Python 3.10+ (Tested on Python 3.13.5)
- PostgreSQL (Optional: SQLite fallback is active by default for immediate out-of-the-box execution)

### Step 1: Clone or Navigate to Project
```powershell
cd "c:\Users\THINKPAD -RYZEN 5PRO\Documents\Cyber_Lens"
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy the template configuration file:
```powershell
Copy-Item .env.example .env
```

If connecting to PostgreSQL, update `.env`:
```ini
USE_SQLITE=False
DB_ENGINE=postgresql
DB_NAME=cyberlens_db
DB_USER=cyberlens_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432
```
*(Leave `USE_SQLITE=True` for zero-configuration testing with SQLite).*

### Step 4: Apply Database Migrations
```powershell
python manage.py migrate
```

### Step 5: Seed Demonstration Data
Populate the database with pre-configured sample users, posture assessments, and findings:
```powershell
python manage.py seed_demo_data
```

### Step 6: Run the Development Server
```powershell
python manage.py runserver
```
Navigate to: `http://127.0.0.1:8000/`

---

## 7. Default Demo Accounts

| Role | Username | Password | Access Privileges |
| :--- | :--- | :--- | :--- |
| **System Administrator** | `admin` | `AdminPass123!` | Full Access, Admin Panel, Delete Records |
| **Security Analyst** | `analyst` | `AnalystPass123!` | Dashboard, Assessments, Compare, PDF Reports |

---

## 8. Verification & Automated Test Suite

CyberLens includes an automated test suite verifying all critical security layers:
- User registration, login, profile signal, and API key generation (`accounts/tests.py`).
- Strict SSRF blocking of private IPs, loopback, cloud metadata, and malicious schemes (`scanner/tests.py`).
- 0–100 scoring algorithm, grade assignment, and explainability catalog (`analysis/tests.py`).
- Assessment persistence, history filtering, and posture comparison (`scans/tests.py`).
- ReportLab PDF generation binary validity and JSON API exports (`reports/tests.py`).

To run the test suite:
```powershell
python manage.py test
```

**Test Execution Output:**
```text
Creating test database for alias 'default'...
..................
----------------------------------------------------------------------
Ran 18 tests in 29.590s

OK
Destroying test database for alias 'default'...
```

---

## 9. API Automation Example

CyberLens supports automated triggering of passive assessments via HTTP API:

```bash
curl -X POST http://127.0.0.1:8000/scans/api/quick-scan/ \
  -H "Authorization: Bearer cl_your_api_token" \
  -d "url=https://cloudflare.com"
```

**JSON Response:**
```json
{
  "status": "success",
  "scan_uuid": "48fc9dda-7389-4097-b2da-53c6e00d0a16",
  "target_hostname": "cloudflare.com",
  "overall_score": 95,
  "grade": "A+",
  "risk_level": "Secure",
  "detail_url": "/scans/48fc9dda-7389-4097-b2da-53c6e00d0a16/"
}
```

---

## 10. Academic Demonstration Checklist

- [x] Complete modular Django structure (`accounts`, `dashboard`, `scans`, `scanner`, `analysis`, `reports`, `core`).
- [x] Responsive Deep Navy SaaS UI with consistent Bootstrap 5 design system.
- [x] Real passive scanner covering HTTPS, Headers, Cookies, TLS, and DNS.
- [x] Real SSRF & private IP protection.
- [x] Transparent 0–100 weighted scoring with letter grades (A+ to F).
- [x] Explainable findings with threat impact and copyable remediation snippets.
- [x] Interactive Chart.js analytics dashboard.
- [x] Downloadable ReportLab PDF reports.
- [x] Search, multi-criteria filtering, and pagination.
- [x] Side-by-side posture comparison tool.
- [x] Comprehensive test suite (18/18 passing).
- [x] Seed data command for immediate university evaluation.
