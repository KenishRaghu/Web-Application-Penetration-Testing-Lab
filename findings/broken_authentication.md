# Broken Authentication — DVWA login brute force (no throttling)

## Summary

The DVWA **login** endpoint (`login.php`) accepts unlimited password guesses when security controls are relaxed. At **Low** / default training config, there is **no account lockout**, **no progressive delay**, and **no CAPTCHA**. I validated the weakness with **Burp Intruder** (cluster/sniper on `password`) and independently with `scripts/brute_force.py`, which mirrors the same HTTP sequence including per-request CSRF token handling.

## Severity

**Medium** (network-exposed login without rate limiting; rises to **High** if weak passwords or no MFA are policy). CVSS depends on lockout/MFA — for the lab target, credential guessing against `admin` is the story.

## Steps to reproduce

### A. Burp Suite

1. Configure browser → Burp Proxy; disable TLS issues for localhost if needed.
2. Browse to `http://localhost:4280/login.php`, enter dummy credentials, intercept POST.
3. Send to **Intruder**. Mark `password` as the only payload position (Sniper).
4. **Payloads** tab: load `scripts/wordlist.txt` (or a small professional list you own).
5. **Options → Grep - Match**: add `Welcome to Damn Vulnerable Web Application` or a unique string from the authenticated home page **or** grep **absence** of `Login failed`.
6. Because DVWA rotates `user_token`, configure **Intruder → Options → Grep - Extract** for `user_token` value from the GET response body, then **Payload Processing → Invoke Burp Extension / Recursive grep** — in Community Edition, the practical approach is:
   - Either use **Pitchfork** with two payload lists (not ideal), or
   - Refresh token per attempt: I used **Macros** (Project options → Sessions → Session handling rules) to **run a macro** before each Intruder request: `GET /login.php` → extract `user_token` → substitute into the POST template.

**What I actually did in the lab:** For speed on CE, I sent the first request to Repeater, confirmed token flow, then used a **macro** so Intruder always pulled a fresh `user_token` before posting the next password. That is the same logic encoded in `brute_force.py` (GET login page → regex token → POST).

### B. Python (sanity check)

```bash
cd scripts
pip install requests
python brute_force.py --base-url http://localhost:4280 --user admin --wordlist wordlist.txt
```

With `password` present in the wordlist, the script reported a successful redirect to `index.php`.

## Evidence

**Captured Intruder request template**

```http
POST /login.php HTTP/1.1
Host: localhost:4280
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=...; security=low

username=admin&password=§password§&Login=Login&user_token=§token§
```

**Observed behavior**

- Responses for wrong passwords: HTTP 200, body contains `Login failed`.
- Correct password: redirect to authenticated area; grep rule highlighted the hit in Intruder results after ~N attempts (where N = position of `password` in the wordlist).

## Impact

- **Account takeover** for users with guessable passwords.
- **Credential stuffing** at scale if the same passwords are reused from breaches.

## Remediation

- **Rate limiting** per IP + per username with exponential backoff.
- **Account lockout** or **soft lock** with notification (balance UX vs abuse).
- **MFA** for sensitive accounts.
- **Strong password policy** + breach password denylist.
- Monitor for **distributed** guessing (per-IP limits alone are insufficient).

Code-level patterns: `docs/secure_coding_mitigations.md`.
