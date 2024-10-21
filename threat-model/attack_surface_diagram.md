# Attack surface — entry points and data flow

Text + Mermaid views of how traffic reaches vulnerable sinks in the DVWA lab.

## High-level flow

```mermaid
flowchart LR
  subgraph Client
    B[Browser]
    P[Burp Proxy]
  end
  subgraph DVWA["DVWA container :80"]
    W[Apache + PHP]
    M[(MySQL)]
    FS[(Uploads / web files)]
  end
  B <--> P
  P <-->|HTTP| W
  W --> M
  W --> FS
```

## Request paths (logical)

```mermaid
flowchart TB
  A[Attacker / Tester] -->|HTTP GET/POST| L[login.php]
  A -->|Authenticated modules| V[vulnerabilities/*]
  V --> S[SQL string concat]
  V --> X[HTML echo sinks]
  V --> U[File upload handler]
  V --> F[File inclusion / exec modules]
  S --> DB[(Database)]
  X --> R[Response HTML to victim]
  U --> UP[/hackable/uploads/]
```

## Entry → typical weakness (quick reference)

| You touch… | Data often flows to… | Classic mistake |
|------------|----------------------|-----------------|
| Query params (`id`, `name`, …) | SQL or HTML templates | Concatenation / no encoding |
| Forms (login, guestbook) | Auth logic / DB writes | No rate limit / stored HTML |
| Upload UI | Filesystem + URL | Predictable names, weak ACL |
| “View file” style params | Disk or remote fetch | Path traversal, SSRF (in other apps) |

Use this diagram in interviews to explain **where** you look first after mapping routes in Burp’s site map.
