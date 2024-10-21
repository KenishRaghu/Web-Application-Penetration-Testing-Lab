# Insecure Direct Object Reference (IDOR) — predictable resource / horizontal access pattern

## Summary

DVWA does not ship a button labeled “IDOR,” but **direct object references** appear anywhere the app names a resource by predictable identifier without server-side authorization. In my lab pass I focused on the **File Upload** outcome page and supporting docs: uploaded files land under a **known web path** with **sequential or guessable filenames** (`hackable/uploads/file_N.*`). An attacker who learns the naming scheme can **request another user’s object** (their uploaded file) without being that user — classic IDOR-style access to **objects** (files) rather than rows in a JSON API.

I also reviewed **SQL Injection** numeric `id` as a *related* failure mode (forced browsing via parameter tampering). The write-up below centers on **unauthorized file retrieval** because it maps cleanly to IDOR interviews.

## Severity

**Medium** (confidentiality of uploaded artifacts; **High** if uploads contain PII, auth tokens, or ID scans). Adjust for your threat model.

## Steps to reproduce

1. Log in as **user A** (e.g. `gordonb` / `abc123` in default DVWA) or create content as a non-admin account.
2. Open **File Upload** (`vulnerabilities/upload/`); upload a distinctive image (note the success message and filename hint).
3. Log out; log in as **user B** (or stay unauthenticated if the uploads directory is directly readable — behavior depends on server config; in many DVWA containers the uploads path is web-accessible).
4. In Burp or the browser, request:

   `GET /hackable/uploads/file_1.jpg`

   Increment the numeric suffix (`file_2.jpg`, …) until you retrieve **user A’s** artifact without presenting A’s session.

5. Document which identities you used and which file index corresponded to which upload.

## Evidence

**Request**

```http
GET /hackable/uploads/file_2.jpg HTTP/1.1
Host: localhost:4280
Cookie: PHPSESSID=...; security=low
```

**Response**

HTTP 200, `Content-Type: image/jpeg` (or png), body is the other user’s image — **not** the uploader’s current session, proving missing object-level authorization on **static file URLs**.

**Note:** Exact enumeration steps depend on container layout and prior uploads; the finding is the **pattern** (predictable URL ↔ sensitive object), not a specific CVE number.

## Impact

- **Unauthorized disclosure** of user-supplied content (documents, screenshots, exports).
- **Compliance** issues (GDPR/HIPAA) when uploads contain personal data.
- **Chaining** with other bugs (e.g., malware delivery if uploads are executable — separate finding).

## Remediation

- Store uploads **outside the web root** or serve via **controller** that checks `user_id` on every download.
- Use **opaque, unguessable** object IDs (UUID) **plus** authorization, not instead of it.
- Log and alert on **enumeration** (many 404s / rapid sequential GETs).

See `docs/secure_coding_mitigations.md` for authorization check sketches.
