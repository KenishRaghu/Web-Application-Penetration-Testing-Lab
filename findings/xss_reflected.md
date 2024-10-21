# Cross-Site Scripting (Reflected) — DVWA XSS (Reflected)

## Summary

On the **XSS (Reflected)** page (`vulnerabilities/xss_r/`), user input supplied in the `name` GET parameter was echoed into the HTML response without contextual encoding. At **Low** security, I injected a JavaScript payload that executed in my browser when I loaded the crafted URL — classic reflected XSS.

## Severity

**Medium** (typical for reflected XSS requiring user interaction / link delivery; raise to **High** if the app sits behind auth that an attacker can leverage for session theft against privileged users). CVSS-style shorthand: **AV:N / AC:L / PR:N / UI:R** for “victim clicks link.”

## Steps to reproduce

1. Log in to DVWA; set security to **Low**.
2. Open **XSS (Reflected)**.
3. Turn on Burp Proxy and submit a normal name; observe `name` echoed in the response.
4. In Repeater, replace the value with a harmless proof payload first, e.g. `"><svg/onload=alert(1)>` or `<script>alert(document.domain)</script>` depending on filter level.
5. For **Low**, the raw script path worked in my run; for **Medium**, I adjusted to bypass simple string replacement (e.g. nested tags / case variation) until execution returned.

## Evidence

**Request (Burp Repeater)**

```http
GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1
Host: localhost:4280
Cookie: PHPSESSID=...; security=low
```

**Response (snippet)**

The HTML contained my `<script>...</script>` unescaped in the greeting line, and the browser executed it — DevTools Console showed no CSP blocking the inline script at Low.

**Screenshot description (for your portfolio)**

Capture the DVWA page with the browser alert box reading `XSS` (or `document.domain`) over the “Hello {payload}” banner. Crop to show the address bar with the encoded query string so reviewers see it is **URL-delivered** reflection, not stored content.

## Reflected vs stored (how I explain it in an interview)

| Type        | Where payload lives        | Victim trigger                          |
|------------|----------------------------|-----------------------------------------|
| Reflected  | Only in immediate response | Must request a malicious URL (or form)  |
| Stored     | Persisted server-side      | Victim loads normal page; payload fires |

This finding is **reflected**: clearing the parameter or loading the page without the query string removes the behavior.

## Impact

- **Session theft** if cookies lack `HttpOnly` or via phishing of credentials.
- **Defacement** of page content in the victim’s browser, **keylogging** via DOM hooks, or **drive-by** actions as the victim if the app performs sensitive actions without re-auth.
- **Chaining**: XSS often pairs with CSRF or open redirects for higher impact.

## Remediation

- **Contextual output encoding** (HTML, attribute, JS, URL) on every sink.
- **Content-Security-Policy** with nonces/hashes for any required scripts.
- Prefer **allow-lists** for formats that do not need HTML at all.

Details: `docs/secure_coding_mitigations.md`.
