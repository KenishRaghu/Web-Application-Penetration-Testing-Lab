# Cross-Site Scripting (Stored) — DVWA XSS (Stored) / guestbook-style sink

## Summary

The **XSS (Stored)** module (`vulnerabilities/xss_s/`) persists guestbook-style messages in a database and renders them to every visitor without sanitization. At **Low** security, posting a `<script>` payload caused persistent execution: any user opening the page triggered the script without needing a crafted URL.

## Severity

**High** — stored XSS affects **all** viewers of the page (including admins), does not require tricking the victim into clicking a unique link, and is straightforward to weaponize for session abuse.

## Steps to reproduce

1. Log in; set DVWA security to **Low**.
2. Navigate to **XSS (Stored)**.
3. Intercept POST to `vulnerabilities/xss_s/` in Burp.
4. Inject a proof payload into the **Message** field (the name field may be length-limited depending on version — I used Message for reliability):

   ```text
   <script>alert('stored-xss')</script>
   ```

5. Forward the request, then reload the page in a fresh browser context (or incognito) — the alert fires on normal navigation.

## Evidence

**Request (Burp — illustrative)**

```http
POST /vulnerabilities/xss_s/ HTTP/1.1
Host: localhost:4280
Cookie: PHPSESSID=...; security=low
Content-Type: application/x-www-form-urlencoded

txtName=researcher&mtxMessage=%3Cscript%3Ealert%28%27stored-xss%27%29%3C%2Fscript%3E&btnSign=Sign+Guestbook
```

**Response**

302/200 sequence returned to the guestbook view; subsequent GET showed the script tag rendered inline in the guestbook list (not encoded).

**Screenshot description**

Show the guestbook listing with multiple entries; the malicious row should appear as normal text in “view source” as a raw `<script>` node. Capture the alert on reload to prove **persistence** vs one-shot reflection.

## Impact

- **Mass compromise** of sessions for users who browse the page.
- **Worm-like** behavior if the app allows reposting (self-propagating payloads in social features).
- **Administrative takeover** if staff moderate entries in an unsafe viewer.

## Remediation

- Store **plain text** only; encode on output; never treat user content as HTML unless using a strict sanitizer.
- CSP + **HttpOnly** cookies reduce blast radius but **do not** replace encoding.
- Add **moderation** and **rate limits** for abuse, after fixing the root sink.

Cross-reference: `findings/xss_reflected.md` for reflected variant comparison.
