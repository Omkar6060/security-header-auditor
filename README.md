# security-header-auditor

A lightweight CLI tool that audits any website's **HTTP security headers** and **TLS configuration**, then scores it A–F — similar in spirit to [securityheaders.com](https://securityheaders.com), but self-hosted, scriptable, and free of rate limits.

Built as a hands-on way to apply OWASP Top 10 concepts (specifically **A05:2021 – Security Misconfiguration**) beyond lab environments.

## Why this exists

Missing security headers are one of the most common — and most overlooked — findings in real web application assessments. This tool automates the first-pass check that a pentester or AppSec engineer runs manually: pull the response headers, check TLS posture, and flag what's missing with a concrete fix.

## What it checks

**HTTP Headers**
| Header | Why it matters |
|---|---|
| `Strict-Transport-Security` | Forces HTTPS, prevents SSL-stripping downgrade attacks |
| `Content-Security-Policy` | Primary defense against XSS and data injection |
| `X-Frame-Options` | Prevents clickjacking via iframe embedding |
| `X-Content-Type-Options` | Blocks MIME-sniffing attacks |
| `Referrer-Policy` | Limits information leakage to third parties |
| `Permissions-Policy` | Restricts browser feature access (camera, geolocation, etc.) |
| `X-XSS-Protection` | Legacy filter, still checked by many scanners |

**TLS**
- Protocol version (flags TLS 1.0 / 1.1 as outdated)
- Cipher suite in use
- Certificate issuer and expiry (flags certs expiring within 30 days)

## Usage

```bash
pip install -r requirements.txt

# Console report
python audit.py example.com

# Export a shareable HTML report
python audit.py example.com --html report.html

# Machine-readable output (for piping into other tools / CI)
python audit.py example.com --json
```

Exit code is `0` for grades A+/A/B, and `1` for C/D/F — so it can be dropped into a CI pipeline as a basic security gate.

## Sample output

```
Security & TLS Audit: https://example.com
============================================================

Overall Grade: B  (68/100)

HTTP Security Headers
------------------------------------------------------------
[PRESENT] Strict-Transport-Security
           max-age=31536000; includeSubDomains
[MISSING] Content-Security-Policy
           Fix: Add: Content-Security-Policy: default-src 'self'
[PRESENT] X-Frame-Options
           DENY
...

TLS Configuration
------------------------------------------------------------
Protocol:        TLSv1.3
Cipher suite:    TLS_AES_256_GCM_SHA384
Cert issuer:     Let's Encrypt
Cert expires:    2026-11-02 (79 days remaining)
```

See [`sample-report.html`](./sample-report.html) for the HTML report output.

## How it works

- `auditor/checks.py` — makes the HTTP request, evaluates each header against a weighted rubric, and opens a raw TLS socket (via Python's `ssl`/`socket` modules) to inspect the certificate and negotiated protocol directly — no third-party scanning API involved.
- `auditor/report.py` — renders the results into a styled, self-contained HTML report.
- `audit.py` — CLI entry point (argument parsing, console + JSON + HTML output modes).

## Roadmap / ideas for contributions

- [ ] Batch mode: audit a list of domains from a file
- [ ] Compare mode: diff two audits of the same domain over time
- [ ] Cookie security flag checks (`Secure`, `HttpOnly`, `SameSite`)
- [ ] Subresource Integrity (SRI) checks on loaded scripts

## Disclaimer

This tool only reads publicly-served HTTP responses and TLS handshake metadata — the same information any browser sees when it connects. It does not send exploit payloads or attempt unauthorized access. Still, only run it against domains you own or are authorized to test.

## Author

Built by [Omkar Behera](https://github.com/Omkar6060) as part of ongoing AppSec/pentesting portfolio work.
