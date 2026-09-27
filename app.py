"""Streamlit dashboard for Verix. Run: streamlit run app.py"""
from __future__ import annotations

import asyncio
import csv
import io
import zipfile
from datetime import datetime
from pathlib import Path

import streamlit as st

from ai_brain import BrainError
from config import Config
from history import diff_scans, list_scans, load_scan
from reporter import compute_grade
from runner import run_scan

GRADE_COLOR = {"A": "#16a34a", "B": "#1d4ed8", "C": "#b45309", "D": "#b91c1c", "F": "#7f1d1d"}
HISTORY_DIR = Path("./verix-reports") / "history"  # matches Config's default output_dir

PRESETS = {
    "⚡ Quick — header checks only, seconds": {
        "depth": 1, "ai_checks": False, "rate_limit": 5.0,
        "note": "Crawls just the target page, checks security headers. No Claude calls, no cost.",
    },
    "🔎 Standard — recommended": {
        "depth": 2, "ai_checks": True, "rate_limit": 3.0,
        "note": "A couple levels deep + Claude-driven vulnerability probing. A few minutes.",
    },
    "🛡️ Thorough — deep & slow": {
        "depth": 4, "ai_checks": True, "rate_limit": 2.0,
        "note": "Deeper crawl, more Claude hypotheses tested, gentler rate limit. Longest but most complete.",
    },
}


def _fmt_ts(ts: str) -> str:
    # Local time with UTC offset, e.g. "2026-08-19T03:52:13+0300" — stored this way since
    # v2 (scans made before that are UTC/"Z"-suffixed and fall through to the raw string below).
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d %H:%M:%S (%z)")
    except ValueError:
        return ts


def _findings_csv(findings) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Severity", "Category", "Endpoint", "Method", "CVSS", "Confidence", "Payload"])
    for f in findings:
        w.writerow([f.severity, f.category, f.endpoint, f.method, f.cvss, f.confidence, f.payload])
    return buf.getvalue()


def _export_all_zip(md_report: str, html_report: str, findings) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.md", md_report)
        zf.writestr("report.html", html_report)
        zf.writestr("findings.csv", _findings_csv(findings))
    return buf.getvalue()

st.set_page_config(page_title="Verix", page_icon="🛡️", layout="wide")

# UI is English-only by design. Without this, a browser set to auto-translate (e.g. Chrome
# on an Arabic OS/browser locale) translates the text to Arabic (RTL) while Streamlit's own
# layout/widgets stay LTR — sliders, numbers, and controls end up visually scrambled.
st.markdown(
    '<meta name="google" content="notranslate">'
    '<style>'
    'html, body, .stApp { direction: ltr !important; }'
    # Streamlit/BaseWeb applies primaryColor to float sliders but not int sliders (a known
    # theming inconsistency) — force every slider's fill/handle to match regardless of type.
    'div[data-baseweb="slider"] div[role="slider"] { background-color: #22d3ee !important; }'
    'div[data-baseweb="slider"] > div > div { background: #22d3ee !important; }'
    '</style>',
    unsafe_allow_html=True,
)

st.title("🛡️ Verix")
st.caption("Autonomous, Claude-driven web + LLM vulnerability scanner — authorized testing only.")

with st.sidebar:
    st.header("Scan configuration")
    target = st.text_input("Target URL", placeholder="https://your-authorized-target.com")
    confirm_scope = st.checkbox("I have explicit authorization to test this target")

    intensity = st.radio("Scan intensity", list(PRESETS.keys()), index=1)
    preset = PRESETS[intensity]
    st.caption(preset["note"])

    with st.expander("Advanced settings"):
        depth = st.slider("Scan depth", 1, 5, preset["depth"])
        rate_limit = st.slider("Rate limit (req/sec)", 0.5, 10.0, preset["rate_limit"], step=0.5)
        max_concurrency = st.slider("Max concurrency", 1, 20, 5)
        ai_checks = st.checkbox("Enable AI/LLM-specific checks (Claude-driven)", value=preset["ai_checks"])
        allow_unsafe_methods = st.checkbox("Allow unsafe HTTP methods (PUT/DELETE/PATCH)", value=False)

    start = st.button("🚀 Start Security Audit", type="primary", use_container_width=True)

if "findings" not in st.session_state:
    st.session_state.findings = None
    st.session_state.md_report = None
    st.session_state.html_report = None

if start:
    if not target:
        st.error("Enter a target URL first.")
    elif not confirm_scope:
        st.error("You must confirm scope authorization before scanning.")
    else:
        try:
            config = Config(
                target=target,
                depth=depth,
                ai_checks=ai_checks,
                confirm_scope=confirm_scope,
                max_concurrency=max_concurrency,
                rate_limit_rps=rate_limit,
                allow_unsafe_methods=allow_unsafe_methods,
            )
        except ValueError as exc:
            st.error(str(exc))
        else:
            progress = st.progress(0, text="Starting...")
            log_box = st.empty()
            log_lines: list[str] = []
            STAGES = 5  # crawl, ai-probe, scan-done, report, done — rough progress ticks

            def on_stage(msg: str) -> None:
                log_lines.append(f"▸ {msg}")
                log_box.code("\n".join(log_lines), language="text")
                progress.progress(min(len(log_lines) / STAGES, 1.0), text=msg)

            with st.status("Running scan...", expanded=True) as status:
                try:
                    recon, findings, md_path, html_path = asyncio.run(run_scan(config, on_stage=on_stage))
                except BrainError as exc:
                    status.update(label="Scan failed", state="error")
                    st.error(f"Claude didn't cooperate:\n\n{exc}")
                    st.stop()
                except Exception as exc:
                    status.update(label="Scan failed", state="error")
                    st.exception(exc)
                    st.stop()
                status.update(label="Scan complete", state="complete")

            st.session_state.findings = findings
            st.session_state.md_report = md_path.read_text(encoding="utf-8")
            st.session_state.html_report = html_path.read_text(encoding="utf-8")
            st.success(f"Done — {len(recon.pages)} pages crawled, {len(findings)} findings.")

if st.session_state.findings is not None:
    findings = st.session_state.findings
    grade, grade_note = compute_grade(findings)
    g_col, exp_col = st.columns([3, 1])
    with g_col:
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:1rem;">'
            f'<div style="font-size:2rem;font-weight:bold;color:#fff;background:{GRADE_COLOR[grade]};'
            f'width:3.5rem;height:3.5rem;line-height:3.5rem;text-align:center;border-radius:10px;">{grade}</div>'
            f'<div>{grade_note}</div></div>',
            unsafe_allow_html=True,
        )
    with exp_col:
        st.download_button(
            "📦 Export All (ZIP)",
            _export_all_zip(st.session_state.md_report, st.session_state.html_report, findings),
            file_name="verix-report.zip",
            mime="application/zip",
            use_container_width=True,
        )

    st.subheader(f"Findings ({len(findings)})")
    st.dataframe(
        [
            {"Severity": f.severity, "Category": f.category, "Endpoint": f.endpoint,
             "Method": f.method, "CVSS": f.cvss, "Confidence": f.confidence, "Payload": f.payload}
            for f in findings
        ],
        use_container_width=True,
    )

    st.subheader("Report")
    md_tab, html_tab = st.tabs(["📄 Markdown", "🌐 HTML"])
    with md_tab:
        st.markdown(st.session_state.md_report)
        st.download_button("Download report.md", st.session_state.md_report, file_name="report.md")
    with html_tab:
        st.components.v1.html(st.session_state.html_report, height=800, scrolling=True)
        st.download_button("Download report.html", st.session_state.html_report, file_name="report.html")
else:
    st.info("Configure the scan in the sidebar and click **Start Security Audit**.")

st.divider()
st.subheader("📊 Scan History & Before/After")
all_scans = list_scans(HISTORY_DIR)
all_targets = sorted({load_scan(p)["target"] for p in all_scans})

if not all_targets:
    st.caption("Every scan is saved automatically. Run at least two scans of the same target "
               "(e.g. one before fixing an issue, one after) to compare them here.")
else:
    # A separate picker from the sidebar's "Target URL" field — history can hold scans of
    # several different sites, and mixing them in one Before/After list would be meaningless.
    default_idx = all_targets.index(target) if target in all_targets else 0
    hist_target = st.selectbox("Target to browse history for", all_targets, index=default_idx)
    scans = list_scans(HISTORY_DIR, hist_target)

    if len(scans) < 2:
        st.caption(f"Only one saved scan for {hist_target} so far — run it again after a change to compare.")
    else:
        labels = {}
        for p in scans:
            data = load_scan(p)
            short_id = p.stem.split("_", 2)[1]  # disambiguates two scans saved in the same second
            labels[f"{_fmt_ts(data['timestamp'])} — Grade {data['grade']} ({short_id})"] = p
        options = list(labels.keys())
        c1, c2 = st.columns(2)
        before_label = c1.selectbox("Before", options, index=0)
        after_label = c2.selectbox("After", options, index=len(options) - 1)
        if st.button("Compare"):
            before = load_scan(labels[before_label])
            after = load_scan(labels[after_label])
            diff = diff_scans(before, after)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Grade", f"{diff['grade_before']} → {diff['grade_after']}")
            m2.metric("Resolved issue types", len(diff["resolved"]))
            m3.metric("New issue types", len(diff["new"]))
            m4.metric("Still present", len(diff["persisting"]))

            if diff["resolved"]:
                st.success("✅ Resolved since 'Before':")
                st.dataframe(diff["resolved"], use_container_width=True)
            if diff["new"]:
                st.error("🆕 New since 'Before':")
                st.dataframe(diff["new"], use_container_width=True)
            if diff["persisting"]:
                st.warning("⏳ Still open:")
                st.dataframe(diff["persisting"], use_container_width=True)
