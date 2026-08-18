"""Turns a list of Findings into Markdown + a self-contained HTML report. No template
engine needed for this — it's just f-strings."""
from __future__ import annotations

import html as _html
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from scanner import Finding

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {"Critical": "#7f1d1d", "High": "#b91c1c", "Medium": "#b45309", "Low": "#1d4ed8", "Info": "#4b5563"}
GRADE_BY_WORST_SEVERITY = {
    "Critical": ("F", "Critical vulnerabilities present — remediate immediately before any other work."),
    "High": ("D", "High-severity issues present — prioritize remediation."),
    "Medium": ("C", "Medium-severity issues present."),
    "Low": ("B", "Only low-severity hygiene issues found — solid baseline posture."),
    "Info": ("A", "No issues found above informational severity."),
}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def compute_grade(findings: list[Finding]) -> tuple[str, str]:
    """Overall letter grade from the single worst severity present, so one Critical
    among 50 Lows still fails the audit instead of averaging away."""
    if not findings:
        return "A", "No issues found."
    worst = min(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)).severity
    return GRADE_BY_WORST_SEVERITY.get(worst, ("A", "No issues found."))


def _group(findings: list[Finding]) -> list[tuple[Finding, list[str]]]:
    """Collapse findings that are the same issue on different endpoints (e.g. one missing
    header repeated on every crawled URL) into one entry + the list of affected endpoints."""
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        key = (f.severity, f.category, f.explanation, f.remediation, f.cvss, f.confidence, f.method, f.payload)
        groups[key].append(f)
    out = [(members[0], [m.endpoint for m in members]) for members in groups.values()]
    return sorted(out, key=lambda pair: SEVERITY_ORDER.get(pair[0].severity, 9))


def build_markdown(target: str, findings: list[Finding]) -> str:
    findings = _sorted(findings)
    verified = [f for f in findings if f.severity != "Info"]
    strengths = [f for f in findings if f.severity == "Info" and not f.payload]
    grade, grade_note = compute_grade(findings)
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M (%z)")
    grouped = _group(findings)
    grouped_verified = [(f, eps) for f, eps in grouped if f.severity != "Info"]
    sev_counts = Counter(f.severity for f in findings)

    lines = [
        f"# Verix — Security Audit Report",
        f"**Target:** {target}  \n**Generated:** {now}  \n**Total findings:** {len(findings)} "
        f"({len(grouped)} distinct issue(s) across {len(findings)} endpoint hits)",
        "",
        f"## Overall Grade: {grade}",
        f"{grade_note}",
        f"Severity breakdown: " + ", ".join(f"{sev}={n}" for sev, n in sorted(sev_counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))),
        "",
        "## a) Overall Security Posture",
        f"- {len(verified)} issue instance(s) flagged above Info severity ({len(grouped_verified)} distinct).",
        f"- {len(strengths)} baseline/hygiene note(s).",
        "",
        "## b) Identified Weaknesses & Potential Attack Vectors",
    ]
    for f, endpoints in grouped:
        lines.append(f"- **[{f.severity}] {f.category}** — {len(endpoints)} endpoint(s), e.g. {endpoints[0]}")

    lines += ["", "## c) Verified Vulnerabilities"]
    if not grouped_verified:
        lines.append("_No above-Info severity findings verified in this run._")
    for f, endpoints in grouped_verified:
        shown = endpoints[:5]
        more = f"\n  - ...and {len(endpoints) - 5} more" if len(endpoints) > 5 else ""
        lines += [
            f"### [{f.severity}] {f.category} ({len(endpoints)} endpoint(s))",
            f"- **CVSS:** {f.cvss}  **Confidence:** {f.confidence}",
            f"- **Method/Payload:** `{f.method}` / `{f.payload}`",
            f"- **Explanation:** {f.explanation}",
            f"- **Affected endpoints:**\n" + "\n".join(f"  - {ep}" for ep in shown) + more,
            f"- **Evidence (PoC):**\n```\n{f.evidence}\n```",
            f"- **Remediation:** {f.remediation}",
            "",
        ]

    lines += ["## d) Actionable Remediation & Hardening Steps"]
    seen = set()
    for f in findings:
        if f.remediation and f.remediation not in seen:
            seen.add(f.remediation)
            lines.append(f"- {f.remediation}")

    return "\n".join(lines)


def build_html(target: str, findings: list[Finding]) -> str:
    findings = _sorted(findings)
    grade, grade_note = compute_grade(findings)
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M (%z)")
    grouped = _group(findings)
    grade_color = {"A": "#16a34a", "B": "#1d4ed8", "C": "#b45309", "D": "#b91c1c", "F": "#7f1d1d"}[grade]

    rows = "\n".join(
        f"""<tr>
            <td><span class="badge" style="background:{SEVERITY_COLOR.get(f.severity, '#4b5563')}">{f.severity}</span></td>
            <td>{_html.escape(f.category)}</td>
            <td><details><summary>{len(endpoints)} endpoint(s)</summary>{"<br>".join(_html.escape(e) for e in endpoints)}</details></td>
            <td>{f.method}</td>
            <td>{f.cvss}</td>
            <td>{f.confidence}</td>
            <td><code>{_html.escape(f.payload)}</code></td>
            <td>{_html.escape(f.explanation)}</td>
            <td>{_html.escape(f.remediation)}</td>
        </tr>"""
        for f, endpoints in grouped
    )
    stats = [("Grade", grade, grade_color), ("Total findings", str(len(findings)), "#1f2937"),
              ("Distinct issues", str(len(grouped)), "#1f2937")]
    stat_cards = "".join(
        f'<div class="stat"><div class="stat-value" style="color:{color if color != "#1f2937" else "#e5e7eb"}">'
        f'{value}</div><div class="stat-label">{label}</div></div>'
        for label, value, color in stats
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Verix Report — {_html.escape(target)}</title>
<style>
:root {{ --bg: #0b0f19; --card: #141a2a; --border: #2a3348; --text: #e5e7eb; --muted: #9ca3af; --accent: #22d3ee; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", Arial, sans-serif; margin: 0; padding: 2.5rem clamp(1rem, 5vw, 3rem);
        background: var(--bg); color: var(--text); line-height: 1.5; }}
h1 {{ color: #fff; font-size: 1.5rem; margin: 0 0 .25rem; }}
.subtitle {{ color: var(--muted); margin: 0 0 1.5rem; font-size: .9rem; }}
.stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
.stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.5rem; min-width: 8rem; }}
.stat-value {{ font-size: 1.8rem; font-weight: 700; }}
.stat-label {{ color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; margin-top: .25rem; }}
.grade-note {{ color: var(--muted); margin-bottom: 1.5rem; }}
.table-wrap {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }}
table {{ border-collapse: collapse; width: 100%; font-size: .85rem; }}
th, td {{ border-bottom: 1px solid var(--border); padding: 10px 12px; text-align: left; vertical-align: top; }}
th {{ background: var(--card); color: var(--muted); text-transform: uppercase; font-size: .7rem; letter-spacing: .04em;
      position: sticky; top: 0; }}
tr:last-child td {{ border-bottom: none; }}
tbody tr:hover {{ background: rgba(255,255,255,.03); }}
.badge {{ color: #fff; padding: 2px 10px; border-radius: 999px; font-size: .7rem; font-weight: 600; display: inline-block; }}
code {{ color: #93c5fd; background: rgba(255,255,255,.05); padding: 1px 5px; border-radius: 4px; }}
details summary {{ cursor: pointer; color: var(--accent); }}
footer {{ color: var(--muted); font-size: .8rem; margin-top: 2rem; text-align: center; }}
</style></head><body>
<h1>🛡️ Verix — Security Audit Report</h1>
<p class="subtitle"><b>Target:</b> {_html.escape(target)} &nbsp;·&nbsp; <b>Generated:</b> {now}</p>
<div class="stats">{stat_cards}</div>
<p class="grade-note">{_html.escape(grade_note)}</p>
<div class="table-wrap">
<table>
<tr><th>Severity</th><th>Category</th><th>Endpoints</th><th>Method</th><th>CVSS</th><th>Confidence</th><th>Payload</th><th>Explanation</th><th>Remediation</th></tr>
{rows}
</table>
</div>
<footer>Generated by Verix — for authorized security testing only.</footer>
</body></html>"""


def write_reports(target: str, findings: list[Finding], output_dir: Path) -> tuple[Path, Path]:
    md_path = output_dir / "report.md"
    html_path = output_dir / "report.html"
    md_path.write_text(build_markdown(target, findings), encoding="utf-8")
    html_path.write_text(build_html(target, findings), encoding="utf-8")
    return md_path, html_path
