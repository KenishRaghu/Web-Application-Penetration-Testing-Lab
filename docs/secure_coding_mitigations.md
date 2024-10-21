# Secure coding mitigations

Short, practical mitigations aligned to the vulnerabilities documented in `findings/`. These are reference patterns — adapt to your framework’s ORM and templating.

## SQL injection → parameterized queries

**PHP (PDO prepared statement)**

```php
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
$stmt->execute(['id' => $userId]);
$row = $stmt->fetch();
```

**Python (sqlite3 parameterized — same idea for MySQL drivers)**

```python
cur.execute("SELECT first_name, last_name FROM users WHERE user_id = ?", (user_id,))
row = cur.fetchone()
```

Never build `"... WHERE id = '" + user + "'"` style strings from raw input.

## XSS → output encoding + CSP

**Principle:** Encode for the **sink context** (HTML body, attribute, JavaScript, URL).

**Template engines:** use framework auto-escaping; mark only vetted fragments as safe.

**HTTP header (CSP example — tune for your app)**

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'
```

Combine with **HttpOnly** session cookies where JavaScript must not read tokens.

## Broken authentication → rate limiting, lockout, password hashing

**Application layer (conceptual Python middleware)**

```python
# Pseudocode: combine IP + username key; use Redis in production
if rate_limiter.too_many_failures(client_ip, username):
    raise HTTPException(429, "Try again later")
```

**Password storage:** bcrypt/Argon2id with per-user salt and sensible cost factors; never MD5/SHA1 for passwords.

**Account lockout:** soft lock + email alert, or progressive backoff, to limit guessing without permanent DoS.

## IDOR → server-side authorization

**Pattern:** Resolve the object, then check ownership/role **every time**.

```python
def get_upload(upload_id, current_user):
    row = db.fetch("SELECT path, owner_id FROM uploads WHERE id = ?", (upload_id,))
    if not row or row.owner_id != current_user.id:
        raise Forbidden()
    return safe_storage_path(row.path)
```

Opaque IDs (UUID) help **reduce enumeration** but are **not** a substitute for checks.

## Cross-reference

| Finding | Primary control |
|---------|-----------------|
| `findings/sql_injection.md` | Parameterized queries, least-privilege DB user |
| `findings/xss_reflected.md` / `xss_stored.md` | Encoding, CSP, store plain text |
| `findings/broken_authentication.md` | Rate limit, MFA, strong passwords |
| `findings/idor.md` | Authorization on every object access |
