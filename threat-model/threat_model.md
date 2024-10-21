# Threat model — DVWA lab target

Practical threat model for the **Damn Vulnerable Web Application** instance in this repo (`lab-setup/docker-compose.yml`). Scope is the **training app as deployed locally**, not a production system.

## 1. Asset identification

| Asset | Why it matters |
|-------|----------------|
| **Application database** | Holds users, guestbook entries, session backing store (depending on config), and other module state. |
| **User accounts & sessions** | `admin` and low-priv users; session cookies gate module access. |
| **Administrative / security controls** | DVWA “Security” level switches — if an attacker could change them, difficulty of exploitation shifts. |
| **Uploaded files** | Objects under predictable URLs; may contain sensitive user-chosen content. |
| **Server filesystem (via modules)** | File inclusion / command execution style modules increase integrity/availability risk in a real app (here, intentionally weak). |

## 2. Attack surface mapping

| Entry point | Type | Notes |
|-------------|------|--------|
| `/login.php` | Authentication | Username/password POST; CSRF token field. |
| Module query/body params | Input fields | SQLi, XSS, etc. (`id`, `name`, guestbook `mtxMessage`, …). |
| File upload | File upload | Extension/type checks vary by security level. |
| Local/Remote file inclusion | Path / URL input | User-influenced path to interpreted or returned files. |
| Command injection sinks | Shell-invoking inputs | Where the app passes input to OS commands (training modules). |
| Static paths | Direct HTTP GET | `/hackable/uploads/...` and similar direct object URLs. |

**Trust boundaries:** Browser ↔ PHP app ↔ MySQL; browser ↔ filesystem (indirect via PHP); tester ↔ Burp ↔ app.

## 3. Threat actors

| Actor | Objective | Typical access |
|-------|-----------|----------------|
| **Unauthenticated attacker** | Credential guessing, scrape public paths, probe default installs. | No valid session initially. |
| **Authenticated low-priv user** | Horizontal moves (other users’ data), escalate via bugs, poison stored content. | Valid session as non-admin. |
| **Authenticated privileged user** | Abuse admin features; in real apps, supply-chain / insider misuse — out of scope for DVWA except as comparison. | Admin session. |

## 4. Threats ↔ OWASP Top 10 (2021) mapping

Priority reflects **lab realism** for DVWA at Low/Medium — not a formal risk register for your employer.

| Threat (lab wording) | OWASP Top 10 category | Priority |
|----------------------|------------------------|----------|
| SQL injection via string-concatenated queries | A03:2021 – Injection | Critical |
| Stored XSS in guestbook-style sinks | A03:2021 – Injection | Critical |
| Reflected XSS via echoed parameters | A03:2021 – Injection | High |
| Login brute force / missing throttling | A07:2021 – Identification and Authentication Failures | High |
| Predictable upload URLs / missing object ACL | A01:2021 – Broken Access Control | High |
| Weak session handling demos (where enabled) | A07:2021 – Identification and Authentication Failures | Medium |
| Sensitive data in error messages (SQL errors) | A04:2021 – Insecure Design / A09:2021 – Security Logging Failures* | Medium |
| File inclusion / path abuse | A01:2021 – Broken Access Control / A03:2021 – Injection | High |

\*Logging failures apply when errors leak to users but are not centrally monitored — common in training stacks.

## 5. What I actually tested (traceability)

Mapped surface in browser + Burp, then filed findings under `findings/` for SQLi, XSS (reflected/stored), broken authentication, and IDOR-style file access. Python helpers in `scripts/` duplicate small slices of that work for repeatability.
