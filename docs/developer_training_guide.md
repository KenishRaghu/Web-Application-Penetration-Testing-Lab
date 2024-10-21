# Developer onboarding — what we found in the lab and how you avoid it

This guide is written as if I’m briefing a product team after a **focused web assessment** of our DVWA training stack. The bugs are intentional there; in **your** production code, the same patterns cause **real** incidents.

## What we exercised

1. **SQL injection** — dynamic SQL built from request parameters.  
2. **Reflected and stored XSS** — untrusted data rendered as HTML/JS.  
3. **Broken authentication** — login endpoints that allow unlimited guesses.  
4. **IDOR-style issues** — predictable URLs to user-owned files without a server-side check.

Primary tool: **Burp Suite** (Proxy, Repeater, Intruder with session handling). **OWASP ZAP** is a solid alternative for the same workflow; I used ZAP occasionally for passive checks, but Burp was the main workbench.

## How to not repeat it

| Mistake | Instead |
|---------|---------|
| String-building SQL | Bound parameters / ORM query APIs |
| “We sanitize input” only | Encode on **output** per context; CSP for depth |
| Security through obscurity URLs | Authorization + opaque IDs |
| Login without backoff | Rate limits, alerts, MFA for risky accounts |

## How you can self-test (safe, internal)

1. **Run the lab** from `lab-setup/` on your laptop only.  
2. **Map** the app: click every module with Burp logging; build a **site map**.  
3. **Pick one parameter** per module; in Repeater, send `'` , `"><test>`, and a long string to classify sinks (error / reflection / length change).  
4. **File hypotheses**: “This looks like SQL” → try minimal boolean payloads; “This echoes” → try HTML-encoded vs raw payloads.  
5. **Stop at proof** — screenshot + request/response; don’t exfiltrate real user data.  
6. **Fix + retest** — rerun the same Repeater tab; add regression tests (static analysis + integration tests for parameterized queries).

## If you only remember three rules

1. **Database:** parameters bound, always.  
2. **HTML:** treat user content as data, not code.  
3. **Objects:** check **can this principal access this id?** on every handler.

Deeper references: `docs/secure_coding_mitigations.md` and the per-finding write-ups in `findings/`.
