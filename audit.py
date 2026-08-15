#!/usr/bin/env python3
"""
Security & TLS Auditor
-----------------------
A lightweight CLI tool that audits a website's HTTP security headers
and TLS configuration, then produces a scored A-F report.

Usage:
    python audit.py example.com
    python audit.py https://example.com --html report.html
    python audit.py example.com --json
"""

import argparse
import json
import sys

from colorama import Fore, Style, init as colorama_init

from auditor.checks import run_audit
from auditor.report import render_html

colorama_init(autoreset=True)

GRADE_COLORS = {
    "A+": Fore.GREEN, "A": Fore.GREEN,
    "B": Fore.CYAN,
    "C": Fore.YELLOW,
    "D": Fore.YELLOW,
    "F": Fore.RED,
}


def print_console_report(report):
    grade_color = GRADE_COLORS.get(report.grade, Fore.WHITE)

    print()
    print(f"{Style.BRIGHT}Security & TLS Audit: {report.target}{Style.RESET_ALL}")
    print("=" * 60)

    if report.error:
        print(f"{Fore.RED}Error: {report.error}{Style.RESET_ALL}")

    print(f"\n{Style.BRIGHT}Overall Grade: {grade_color}{report.grade}  ({report.score}/100){Style.RESET_ALL}\n")

    print(f"{Style.BRIGHT}HTTP Security Headers{Style.RESET_ALL}")
    print("-" * 60)
    for h in report.headers:
        status = f"{Fore.GREEN}[PRESENT]" if h.present else f"{Fore.RED}[MISSING]"
        print(f"{status}{Style.RESET_ALL} {h.name}")
        if h.present:
            shown = h.value if len(h.value) <= 70 else h.value[:67] + "..."
            print(f"           {Fore.LIGHTBLACK_EX}{shown}{Style.RESET_ALL}")
        else:
            print(f"           {Fore.LIGHTBLACK_EX}Fix: {h.fix}{Style.RESET_ALL}")

    print(f"\n{Style.BRIGHT}TLS Configuration{Style.RESET_ALL}")
    print("-" * 60)
    t = report.tls
    if t and t.reachable:
        print(f"Protocol:        {t.protocol}")
        print(f"Cipher suite:    {t.cipher}")
        print(f"Cert issuer:     {t.issuer}")
        print(f"Cert expires:    {t.cert_expires} ({t.days_until_expiry} days remaining)")
        for note in t.notes:
            print(f"{Fore.YELLOW}Note: {note}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Could not complete TLS handshake.{Style.RESET_ALL}")
        for note in (t.notes if t else []):
            print(f"{Fore.RED}  {note}{Style.RESET_ALL}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Audit a website's HTTP security headers and TLS configuration."
    )
    parser.add_argument("target", help="Domain or URL to audit, e.g. example.com")
    parser.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE")
    parser.add_argument("--json", action="store_true", help="Print raw results as JSON")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    args = parser.parse_args()

    report = run_audit(args.target, timeout=args.timeout)

    if args.json:
        payload = {
            "target": report.target,
            "final_url": report.final_url,
            "status_code": report.status_code,
            "score": report.score,
            "grade": report.grade,
            "error": report.error,
            "headers": [
                {"name": h.name, "present": h.present, "value": h.value, "points": h.points}
                for h in report.headers
            ],
            "tls": {
                "reachable": report.tls.reachable,
                "protocol": report.tls.protocol,
                "cipher": report.tls.cipher,
                "cert_expires": report.tls.cert_expires,
                "days_until_expiry": report.tls.days_until_expiry,
                "issuer": report.tls.issuer,
                "valid": report.tls.valid,
                "notes": report.tls.notes,
            } if report.tls else None,
        }
        print(json.dumps(payload, indent=2))
    else:
        print_console_report(report)

    if args.html:
        render_html(report, args.html)
        print(f"{Fore.CYAN}HTML report written to {args.html}{Style.RESET_ALL}")

    sys.exit(0 if report.grade in ("A+", "A", "B") else 1)


if __name__ == "__main__":
    main()
