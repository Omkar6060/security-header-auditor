"""HTML report rendering for the Security & TLS Auditor.

Design: a terminal-console theme. The report literally looks like the
output of the CLI tool that generated it, since that's the truest
signature for a tool whose whole value is "read this like a log".
"""

import html
import datetime

GRADE_COLOR = {
    "A+": "#4ADE80", "A": "#4ADE80",
    "B": "#8FD1FF",
    "C": "#FBBF24",
    "D": "#FBBF24",
    "F": "#F87171",
}


def _header_row(h) -> str:
    status_color = "#4ADE80" if h.present else "#F87171"
    status_text = "PRESENT" if h.present else "MISSING"
    detail = (
        f'<span class="value">{html.escape(h.value[:120])}</span>'
        if h.present else
        f'<span class="fix">fix &rarr; {html.escape(h.fix)}</span>'
    )
    return f"""
    <div class="row">
      <div class="row-top">
        <span class="tag" style="color:{status_color}; border-color:{status_color}33; background:{status_color}14;">[{status_text}]</span>
        <span class="header-name">{html.escape(h.name)}</span>
      </div>
      <div class="row-detail">{detail}</div>
      <div class="row-desc">{html.escape(h.desc)}</div>
    </div>"""


def render_html(report, out_path: str) -> None:
    grade_color = GRADE_COLOR.get(report.grade, "#E6E9EF")
    header_rows = "\n".join(_header_row(h) for h in report.headers)

    tls = report.tls
    if tls and tls.reachable:
        tls_block = f"""
        <div class="kv"><span>protocol</span><span>{html.escape(tls.protocol)}</span></div>
        <div class="kv"><span>cipher_suite</span><span>{html.escape(tls.cipher)}</span></div>
        <div class="kv"><span>cert_issuer</span><span>{html.escape(tls.issuer)}</span></div>
        <div class="kv"><span>cert_expires</span><span>{html.escape(tls.cert_expires)} ({tls.days_until_expiry} days)</span></div>
        {"".join(f'<div class="note">! {html.escape(n)}</div>' for n in tls.notes)}
        """
    else:
        notes = tls.notes if tls else []
        tls_block = f'<div class="note fail">TLS handshake failed.</div>' + "".join(
            f'<div class="note fail">{html.escape(n)}</div>' for n in notes
        )

    generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Audit — {html.escape(report.target)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap');

  :root {{
    --bg: #0B0E14;
    --surface: #131826;
    --surface-2: #0F1420;
    --border: #232B3D;
    --text: #E6E9EF;
    --muted: #8891A3;
    --accent: #FF8A3D;
  }}

  * {{ box-sizing: border-box; }}

  body {{
    margin: 0;
    background: var(--bg);
    background-image:
      radial-gradient(circle at 15% 0%, rgba(255,138,61,0.06), transparent 40%),
      radial-gradient(circle at 85% 100%, rgba(143,209,255,0.05), transparent 40%);
    color: var(--text);
    font-family: 'Inter', -apple-system, sans-serif;
    padding: 40px 20px;
    display: flex;
    justify-content: center;
  }}

  .window {{
    width: 100%;
    max-width: 760px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 30px 60px -20px rgba(0,0,0,0.6);
  }}

  .titlebar {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
  }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
  .dot.r {{ background: #F87171; }}
  .dot.y {{ background: #FBBF24; }}
  .dot.g {{ background: #4ADE80; }}
  .titlebar .path {{
    margin-left: 10px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--muted);
  }}

  .content {{ padding: 32px; }}

  .cmd {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: var(--muted);
    margin-bottom: 4px;
  }}
  .cmd .prompt {{ color: var(--accent); }}
  .cmd .cursor {{
    display: inline-block;
    width: 7px; height: 13px;
    background: var(--accent);
    margin-left: 4px;
    animation: blink 1.1s steps(1) infinite;
    vertical-align: -2px;
  }}
  @keyframes blink {{ 50% {{ opacity: 0; }} }}

  h1 {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 20px;
    font-weight: 700;
    margin: 6px 0 2px;
    word-break: break-all;
  }}
  .subline {{ color: var(--muted); font-size: 13px; margin-bottom: 28px; }}

  .grade-panel {{
    display: flex;
    align-items: center;
    gap: 24px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 32px;
  }}
  .grade-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 40px;
    font-weight: 700;
    line-height: 1;
    color: {grade_color};
    border: 2px solid {grade_color}55;
    background: {grade_color}14;
    border-radius: 8px;
    padding: 10px 18px;
  }}
  .grade-meta .score {{ font-family: 'JetBrains Mono', monospace; font-size: 14px; color: var(--muted); }}
  .grade-meta .score b {{ color: var(--text); }}

  h2 {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--accent);
    margin: 0 0 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  section {{ margin-bottom: 32px; }}

  .row {{
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
  }}
  .row:last-child {{ border-bottom: none; }}
  .row-top {{ display: flex; align-items: center; gap: 10px; }}
  .tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid;
  }}
  .header-name {{ font-family: 'JetBrains Mono', monospace; font-size: 13.5px; font-weight: 500; }}
  .row-detail {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; margin: 6px 0 4px 0; word-break: break-all; }}
  .row-detail .value {{ color: var(--muted); }}
  .row-detail .fix {{ color: #FBBF24; }}
  .row-desc {{ font-size: 12.5px; color: var(--muted); }}

  .kv {{
    display: flex;
    justify-content: space-between;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    padding: 7px 0;
    border-bottom: 1px solid var(--border);
  }}
  .kv span:first-child {{ color: var(--muted); }}
  .kv:last-of-type {{ border-bottom: none; }}
  .note {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #FBBF24; margin-top: 8px; }}
  .note.fail {{ color: #F87171; }}

  footer {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    text-align: center;
    padding: 16px;
    border-top: 1px solid var(--border);
    background: var(--surface-2);
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>
  <div class="window">
    <div class="titlebar">
      <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
      <span class="path">security-audit &mdash; {html.escape(report.target)}</span>
    </div>
    <div class="content">
      <div class="cmd"><span class="prompt">$</span> audit {html.escape(report.target)}<span class="cursor"></span></div>
      <h1>{html.escape(report.target)}</h1>
      <div class="subline">Generated {generated} &middot; HTTP status {report.status_code if report.status_code else "n/a"}</div>

      <div class="grade-panel">
        <div class="grade-badge">{report.grade}</div>
        <div class="grade-meta">
          <div class="score"><b>{report.score}</b> / 100</div>
          <div class="score">{len([h for h in report.headers if h.present])}/{len(report.headers)} security headers present</div>
        </div>
      </div>

      <section>
        <h2>HTTP Security Headers</h2>
        {header_rows}
      </section>

      <section>
        <h2>TLS Configuration</h2>
        {tls_block}
      </section>
    </div>
    <footer>generated by <a href="#">security-header-auditor</a> &middot; a lightweight AppSec CLI tool</footer>
  </div>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
