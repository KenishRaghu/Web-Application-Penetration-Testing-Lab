# Web Application Penetration Testing Lab

Structured, **hands-on** web security lab built around **DVWA** (Damn Vulnerable Web Application). This repo is a portfolio piece: it shows how I **run a target**, **map attack surface**, **find and document vulnerabilities**, and **translate findings into fixes and developer guidance** — not how I build a custom scanner product.

**Primary toolkit:** **Burp Suite** (Proxy, Repeater, Intruder, session handling). **OWASP ZAP** is noted as a useful secondary proxy for passive analysis; Burp is the main narrative in the findings. **Python 3** + `requests` for small automation that mirrors manual steps. Host OS was **Kali Linux**-style tooling is optional; no Metasploit chain is part of this project.

---

## What’s inside

| Section | Purpose |
|---------|---------|
| [lab-setup/](lab-setup/) | Docker Compose: **one** DVWA container + setup notes (port, creds, security levels). |
| [findings/](findings/) | **Core work** — one markdown report per vulnerability with repro steps, Burp evidence, impact, remediation. |
| [threat-model/](threat-model/) | Practical threat model + Mermaid/text attack-surface diagram. |
| [scripts/](scripts/) | Supplementary **Python** probes (`sqli_scanner.py`, `brute_force.py`, `wordlist.txt`). |
| [docs/](docs/) | Secure coding mitigations + a short **developer onboarding** guide tied to what we found. |

---

## Methodology (how I approached the lab)

1. **Recon / environment** — Bring up DVWA locally; confirm default creds, PHP session, security level behavior.  
2. **Mapping** — Browse all modules through **Burp Proxy**; build a mental (and sitemap) model of parameters, forms, and static paths.  
3. **Discovery** — Classify inputs (SQL vs HTML echo vs file operations) using minimal probes; escalate only where impact is clear.  
4. **Exploitation (controlled)** — Prove impact (e.g., UNION shape for SQLi, executed XSS, successful login guess) **without** exfiltrating real third-party data — lab scope only.  
5. **Reporting** — Capture **requests/responses**, explain payloads, CVSS/severity, and fixes developers can ship.

---

## Quick start

```bash
cd lab-setup
docker compose up -d
# Application: http://localhost:4280
```

Details: [lab-setup/README.md](lab-setup/README.md).

**Python helpers**

```bash
pip install requests
cd scripts
python sqli_scanner.py --help
python brute_force.py --help
```

---

## Findings index

- [SQL injection](findings/sql_injection.md)  
- [Reflected XSS](findings/xss_reflected.md)  
- [Stored XSS](findings/xss_stored.md)  
- [Broken authentication / brute force](findings/broken_authentication.md)  
- [IDOR-style file access](findings/idor.md)  

---
