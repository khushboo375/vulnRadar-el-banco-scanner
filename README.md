# VulnRadar - El Banco Penetration Testing & Security Assessment Platform

> **Authorized academic use only.** Run VulnRadar only against localhost,
> Docker lab targets, intentionally vulnerable applications, or systems where
> you have explicit written permission.

VulnRadar extends the original smart web vulnerability scanner into an El Banco
Bank gray-box penetration testing platform. It combines:

- Network reconnaissance with Nmap
- Web application security scanning
- HTTP access log attack analysis
- Unified findings, evidence, severity, mitigations, and HTML reporting

## Features

| Area | Capability |
|---|---|
| Network Reconnaissance | Half-Open TCP SYN scan and aggressive Nmap scan |
| Aggressive Scan | OS detection, service/version detection, NSE/script scanning, traceroute |
| Web Scanner | Form crawling, SQL Injection, reflected XSS, authentication checks, directory traversal |
| HTTP Log Analyzer | Detects suspicious XSS, directory traversal/LFI-style probing, and SQL Injection requests |
| Reporting | El Banco penetration test report with evidence, severity summary, and mitigations |

## Project Structure

```text
security_scanner/
├── app.py
├── requirements.txt
├── README.md
├── logs/
├── reports/
├── modules/
│   ├── auth_scanner.py
│   ├── crawler.py
│   ├── log_analyzer.py
│   ├── network_scanner.py
│   ├── report_generator.py
│   ├── sql_scanner.py
│   ├── traversal_scanner.py
│   └── xss_scanner.py
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/scanner.js
```

## Requirements

- Python 3.10+
- Nmap installed on the operating system for network scans
- Python packages from `requirements.txt`
- Docker Desktop, if you want to run DVWA locally

Install Nmap:

- Windows: download and install from `https://nmap.org/download.html`, then ensure `nmap.exe` is in PATH.
- Linux: `sudo apt install nmap`
- macOS: `brew install nmap`

Half-open SYN scans may require administrator/root privileges depending on your OS.

## Python Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## DVWA Docker Lab

DVWA is the recommended El Banco demonstration target because the provided log
examples use DVWA-style paths.

```bash
docker pull vulnerables/web-dvwa
docker run -d -p 4280:80 --name dvwa vulnerables/web-dvwa
```

Open DVWA at:

```text
http://localhost:4280
```

Complete DVWA setup in the browser if prompted. Then use `http://localhost:4280`
as the VulnRadar web scanner target.

Other safe lab targets:

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
docker run -d -p 80:80 raesene/bwapp
```

## How To Use

### Task 1 - Half-Open Scan

1. In **Network Reconnaissance**, enter an authorized IP or hostname.
2. Click **Half-Open Scan**.
3. Results show discovered ports, state, and service names returned by Nmap.

If Nmap is missing, VulnRadar shows a clear setup error instead of generating fake data.

### Task 2 - Aggressive Scan

1. Enter an authorized IP or hostname.
2. Click **Aggressive Scan**.
3. The report includes OS detection, service/version details, NSE/script output, and traceroute when Nmap returns them.

### Web Application Scan

1. In **Web Application Scanner**, enter a target URL such as `http://localhost:4280`.
2. Select modules: SQL Injection, XSS, Directory Traversal, Authentication.
3. Click **Launch Scan**.
4. Findings include evidence and remediation guidance.

### Task 3 - HTTP Log Analysis

1. Paste HTTP access logs or upload a `.log` / `.txt` file.
2. Click **Analyze Logs**.
3. VulnRadar classifies suspicious requests as:
   - DOM-Based XSS / XSS-related suspicious request
   - Directory Traversal / Local File Inclusion-style probing
   - SQL Injection

The log analyzer reports suspicious requests / attack attempts. It does not claim
successful exploitation unless the evidence proves it.

## Provided Log Examples

Use the assignment logs in the paste box. Expected classifications:

| Log | Expected Result |
|---|---|
| Log #1 | DOM-Based XSS / XSS-related suspicious request |
| Log #2 | Directory Traversal / Local File Inclusion-style probing |
| Log #3 | SQL Injection |

Each result includes attack type, evidence, severity, description, impact, and mitigation.

## Reports

After any successful workflow, click **Download HTML Report**.

The report contains:

1. Executive Summary
2. Target Information
3. Network Reconnaissance
4. Web Application Findings
5. HTTP Log Analysis
6. Evidence
7. Severity Summary
8. Recommended Mitigations

Reports are saved in `reports/`. Activity is logged to `logs/scanner.log`.

## Safety Scope

VulnRadar is for reconnaissance, vulnerability identification, evidence
collection, risk explanation, mitigation, and academic reporting. It does not add
stealth, persistence, credential theft, destructive exploitation, or evasion
features.
