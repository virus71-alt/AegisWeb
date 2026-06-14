# 🛡️ AegisWeb: Website Health & Security Analyzer

AegisWeb is a high-performance, asynchronous Python CLI tool designed to perform comprehensive health, performance, and security audits of web domains. Built using `asyncio` and `httpx`, it scans pages concurrently, verifies infrastructure configs, audits SSL certificates, evaluates response security headers, queries performance diagnostics, and tracks audit histories locally.

---

## ✨ Features

* 🕷️ **Asynchronous BFS Web Crawler**  
  Crawls pages concurrently up to a user-defined depth or maximum count limits. Respects `robots.txt` and normalizes relative links, separating internal links from external records.
* 🔗 **Broken Link & Redirect Tracker**  
  Verifies internal links asynchronously to identify `404` or `500` HTTP failures. Captures redirect chains, tracks loops, and logs redirect hops.
* 🔍 **Structural SEO Auditor**  
  Analyzes page titles, meta descriptions (flagging missing or duplicate instances across paths), `<h1>` counts, missing image `alt` attributes, and canonical tags.
* 🌐 **Infrastructure & DNS Profiler**  
  Measures Time to First Byte (TTFB) and total Round-Trip Time (RTT). Resolves and profiles DNS records (`A`, `AAAA`, `MX`, `NS`, `TXT`) asynchronously using `dnspython`.
* 🔒 **SSL Certificate Auditor**  
  Queries TLS ports to pull peer certificates. Extracts expiration remaining days, issuer authority, and signature algorithms using Python's native `ssl` and `cryptography` libraries.
* 🛡️ **HTTP Security Header Evaluator**  
  Scans homepage headers for recommended security settings, including `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
* 🕵️ **Vulnerability & Exposure Scanner**  
  Performs safe, non-intrusive (read-only `GET`) reconnaissance to surface real loopholes attackers exploit: publicly exposed sensitive files (`/.git/config`, `/.env`, database dumps, backup archives, `phpinfo.php`, `server-status`), enabled directory listing, insecure cookie flags (missing `Secure`/`HttpOnly`/`SameSite`), software/version disclosure headers, CORS misconfigurations (reflected `Origin`, wildcard + credentials), weak Content-Security-Policy directives (`unsafe-inline`/`unsafe-eval`/wildcards), missing extended hardening headers (`Permissions-Policy`, COOP, CORP), HTTP→HTTPS redirect enforcement, HSTS quality, missing Subresource Integrity (SRI) on third-party scripts, and mixed (insecure) content. Findings feed directly into the report, Markdown export, and AI remediation prompt.
* ⚡ **Core Web Vitals Integration**  
  Wraps the Google PageSpeed Insights API to query lab data diagnostics: First Contentful Paint (FCP), Largest Contentful Paint (LCP), and Cumulative Layout Shift (CLS).
* 📈 **Weighted Scoring Engine**  
  Translates audit findings into a color-coded overall health score (0.0% to 100.0%) based on severity deductions. Active vulnerability findings now feed directly into the score (`-10%` High / `-5%` Medium / `-1%` Low each, capped at `-40%`).
* 🗄️ **Persistent SQLite3 History**  
  Logs every run, crawl detail, network metric, header state, and vulnerability finding into a local database. The `history` view surfaces a per-audit High/Medium vulnerability count so you can track your security posture over time. Offloads database queries to background thread pools to keep the async event loop active.
* 📝 **Automatic Markdown Report Exporter**  
  Saves audit details inside the `result/<website_name>` directory in a markdown format named with the execution date and time.
* 💡 **Actionable Fix Suggestor**  
  Analyzes all anomalies (security, SEO, network latencies, performance data) and yields prioritized step-by-step fix guides complete with HTML tags and Nginx config blocks.
* 🤖 **AI Agent Remediation Prompt Exporter**  
  Automatically generates a highly descriptive Markdown prompt specifications file saved inside `fixprompt/<website_name>/<timestamp>_prompt.md`. This prompt can be directly copy-pasted into any AI coding assistant to automatically implement the requested security and SEO fixes.

---

## 🚀 Installation

### 1. Prerequisites
Ensure you have **Python 3.10+** installed on your system.

### 2. Install Dependencies
Clone the repository and install the required library packages using `pip`:

```bash
pip install httpx beautifulsoup4 dnspython cryptography rich
```

---

## 💻 Usage

AegisWeb supports two primary subcommands: `run` and `history`.

### 1. Initiate a Live Audit (`run`)
Initiate a comprehensive scan against a target website:

```bash
python analyzer.py run --url https://example.com --depth 3 --max-pages 100
```

#### Options:
* `--url`: **(Required)** Target website URL (e.g., `https://example.com`).
* `--depth`: Maximum BFS link crawl depth (Default: `3`).
* `--max-pages`: Maximum page crawl threshold limit (Default: `100`).
* `--api-key`: Optional Google PageSpeed Insights API Key (if omitted, queries are made using Google's public rate-limited limits).
* `--db`: SQLite3 database path (Default: `analyzer.db`).

### 2. Query History (`history`)
Retrieve historical audit records for previously scanned domains:

```bash
python analyzer.py history
```

To filter historical scores by a specific website URL:

```bash
python analyzer.py history --url https://example.com
```

---

## 📊 Scoring Deductions Model

Calculations begin at **100.0%** and apply the following deductions based on findings:

| Anomaly Class | Severity | Deduction Weight | Capping / Rules |
| :--- | :--- | :--- | :--- |
| **Broken Internal Links** | 🔴 Critical | `-5.0%` per link | Capped at maximum `-30.0%` |
| **SSL Certificate Expiry** | 🔴 Critical | `-25.0%` overall | Triggers if certificate expires in `< 30` days |
| **Missing Security Headers** | 🟡 Medium | `-3.0%` per header | Audited: HSTS, CSP, X-Frame, X-Content, Referrer |
| **Vulnerability & Exposure Findings** | 🔴 Critical | `-10.0%` High / `-5.0%` Medium / `-1.0%` Low (each) | Capped at maximum `-40.0%` (exposed files, CORS, cookies, weak CSP, mixed content, etc.) |
| **SEO structural Issues** | 🟢 Light | `-0.5%` per issue | Missing titles, descriptions, canonicals, alts, duplicates |

---

## 📂 Project Structure

```text
├── analyzer.py        # CLI Entrypoint & Runner
├── crawler.py         # Asynchronous Web Crawler
├── db.py              # SQLite3 Async Connection Manager
├── network.py         # Network RTT, TTFB & DNS Query Profiler
├── performance.py     # PageSpeed Insights API Wrapper
├── scoring.py         # Deductions Scoring Engine
├── security.py        # SSL Handshake Auditor & Header Scanner
├── vulnscan.py        # Vulnerability & Exposure Scanner (files, CORS, cookies, CSP, TLS)
├── suggestor.py       # Actionable Remediation Suggestor
├── test_analyzer.py   # Unit Test Suite
└── README.md          # Project Documentation
```

---

## 🛡️ License

This project is open-source and available under the [MIT License](LICENSE).
