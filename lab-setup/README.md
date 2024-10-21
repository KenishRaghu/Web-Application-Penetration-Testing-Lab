# Lab setup — DVWA target

This folder brings up **one** container: [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application) as the intentionally vulnerable target.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose v2 (`docker compose` plugin)

## Start the lab

From this directory:

```bash
cd lab-setup
docker compose up -d
```

Open the app in a browser:

- **URL:** `http://localhost:4280`

(The host port is **4280** so it does not clash with anything else bound to port 80.)

## First-time setup in the UI

1. Click **Create / Reset Database** on the setup page if prompted.
2. Log in with the default credentials (see below).
3. Set the **security level** from the left sidebar (**DVWA Security**) before each exercise if you want consistent difficulty.

## Default credentials

| User     | Password |
|----------|----------|
| `admin`  | `password` |

Other built-in users may exist depending on image/version; `admin` / `password` is the standard pair for DVWA.

## Security levels

DVWA exposes four levels (Low → Impossible). For this portfolio lab I worked mainly at **Low** and **Medium** to demonstrate classic web flaws and mitigations. **High** and **Impossible** are useful to compare defenses after remediation discussions.

| Level     | What it approximates                          |
|-----------|------------------------------------------------|
| Low       | Minimal validation; easiest to exploit        |
| Medium    | Some filtering / weak controls                |
| High      | Stronger (still bypassable in places)         |
| Impossible| Reference-safe patterns (compare fixes)       |

## Stop the lab

```bash
docker compose down
```

## Notes

- Run this **only** on an isolated machine or lab network. Do not expose the container to the internet.
- Burp Suite (or ZAP) should point its browser/proxy at the same host (`localhost:4280`).
