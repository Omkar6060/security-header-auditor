"""
Core check logic for the Security & TLS Auditor.

Two things get audited:
1. HTTP response security headers (presence + basic sanity of value)
2. TLS configuration (protocol version, certificate validity/expiry)

Each check contributes points toward a 0-100 score, which is then
mapped to a letter grade (A-F), loosely modeled on securityheaders.com.
"""

import ssl
import socket
import datetime
from dataclasses import dataclass, field

import requests

# ---------------------------------------------------------------------------
# Header definitions: name -> (points, description, how to fix)
# ---------------------------------------------------------------------------
HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "points": 20,
        "desc": "Forces browsers to use HTTPS for future requests (HSTS).",
        "fix": 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    },
    "Content-Security-Policy": {
        "points": 20,
        "desc": "Restricts what sources scripts/styles/frames can load from, mitigating XSS.",
        "fix": "Add: Content-Security-Policy: default-src 'self'  (then tighten per-resource)",
    },
    "X-Frame-Options": {
        "points": 15,
        "desc": "Prevents the page from being embedded in an iframe (clickjacking protection).",
        "fix": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
    },
    "X-Content-Type-Options": {
        "points": 15,
        "desc": "Stops browsers from MIME-sniffing a response away from its declared type.",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "points": 10,
        "desc": "Controls how much referrer information is leaked to other sites.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "points": 10,
        "desc": "Restricts which browser features (camera, geolocation, etc.) the page can use.",
        "fix": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
    "X-XSS-Protection": {
        "points": 5,
        "desc": "Legacy XSS filter header (deprecated, but still checked by some scanners).",
        "fix": "Add: X-XSS-Protection: 0  (modern advice: rely on CSP instead, but explicitly disabling avoids legacy quirks)",
    },
}

MAX_HEADER_POINTS = sum(h["points"] for h in HEADER_CHECKS.values())  # 95
TLS_BONUS_POINTS = 5  # rounds total to 100 when TLS is solid


@dataclass
class HeaderResult:
    name: str
    present: bool
    value: str = ""
    points: int = 0
    desc: str = ""
    fix: str = ""


@dataclass
class TLSResult:
    reachable: bool = False
    protocol: str = ""
    cipher: str = ""
    cert_expires: str = ""
    days_until_expiry: int = None
    issuer: str = ""
    valid: bool = False
    notes: list = field(default_factory=list)


@dataclass
class AuditReport:
    target: str
    final_url: str = ""
    status_code: int = None
    headers: list = field(default_factory=list)
    tls: TLSResult = None
    score: int = 0
    grade: str = "F"
    error: str = ""


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def check_headers(url: str, timeout: int = 8) -> tuple[list[HeaderResult], int, requests.Response]:
    """Fetch the URL and evaluate each header in HEADER_CHECKS."""
    resp = requests.get(url, timeout=timeout, allow_redirects=True)
    results = []
    earned = 0
    for name, meta in HEADER_CHECKS.items():
        value = resp.headers.get(name, "")
        present = bool(value)
        pts = meta["points"] if present else 0
        earned += pts
        results.append(HeaderResult(
            name=name, present=present, value=value,
            points=pts, desc=meta["desc"], fix=meta["fix"],
        ))
    return results, earned, resp


def check_tls(hostname: str, port: int = 443, timeout: int = 8) -> TLSResult:
    """Open a TLS connection and inspect protocol version + certificate."""
    result = TLSResult()
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result.reachable = True
                result.protocol = ssock.version()
                cipher = ssock.cipher()
                result.cipher = cipher[0] if cipher else "unknown"
                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert.get("issuer", []))
                result.issuer = issuer.get("organizationName", issuer.get("commonName", "unknown"))

                not_after = cert.get("notAfter")
                if not_after:
                    expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    result.cert_expires = expires.strftime("%Y-%m-%d")
                    delta = expires - datetime.datetime.utcnow()
                    result.days_until_expiry = delta.days
                    result.valid = delta.days > 0

                if result.protocol in ("TLSv1", "TLSv1.1"):
                    result.notes.append(f"Outdated protocol in use: {result.protocol} (upgrade to TLS 1.2+)")
                if result.days_until_expiry is not None and result.days_until_expiry < 30:
                    result.notes.append(f"Certificate expires soon ({result.days_until_expiry} days)")
    except ssl.SSLCertVerificationError as e:
        result.notes.append(f"Certificate verification failed: {e.verify_message}")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result.notes.append(f"Could not establish TLS connection: {e}")
    return result


def run_audit(target: str, timeout: int = 8) -> AuditReport:
    """Run the full audit (headers + TLS) against a target and return an AuditReport."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    hostname = target.split("://", 1)[1].split("/", 1)[0].split(":")[0]
    report = AuditReport(target=target)

    try:
        headers, header_points, resp = check_headers(target, timeout=timeout)
        report.headers = headers
        report.final_url = resp.url
        report.status_code = resp.status_code
    except requests.exceptions.RequestException as e:
        report.error = f"Failed to fetch headers: {e}"
        header_points = 0
        report.headers = [
            HeaderResult(name=n, present=False, points=0, desc=m["desc"], fix=m["fix"])
            for n, m in HEADER_CHECKS.items()
        ]

    tls_result = check_tls(hostname, timeout=timeout)
    report.tls = tls_result

    tls_points = 0
    if tls_result.reachable and tls_result.valid and tls_result.protocol not in ("TLSv1", "TLSv1.1"):
        tls_points = TLS_BONUS_POINTS

    total_possible = MAX_HEADER_POINTS + TLS_BONUS_POINTS
    raw_score = header_points + tls_points
    report.score = round((raw_score / total_possible) * 100)
    report.grade = _grade_from_score(report.score)

    return report
