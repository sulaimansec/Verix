"""Runnable self-check, no network/API calls: python test_smoke.py"""
import shutil
import tempfile
from pathlib import Path

from ai_brain import _parse_json
from history import diff_scans, list_scans, load_scan, save_scan
from recon import CrawlResult
from scanner import _header_findings
from reporter import build_markdown, build_html, compute_grade
from config import Config


def test_history_save_list_diff():
    tmp = Path(tempfile.mkdtemp())
    try:
        recon = CrawlResult(target="https://example.com")
        recon.response_headers["https://example.com/"] = {}
        recon.response_headers["https://example.com/b"] = {}
        before_findings = _header_findings(recon)  # 4 issue types x 2 endpoints = 8 findings

        recon2 = CrawlResult(target="https://example.com")
        recon2.response_headers["https://example.com/"] = {"content-security-policy": "default-src 'self'"}
        after_findings = _header_findings(recon2)  # CSP fixed, 3 issue types remain

        save_scan("https://example.com", before_findings, tmp)
        save_scan("https://example.com", after_findings, tmp)

        scans = list_scans(tmp, "https://example.com")
        assert len(scans) == 2
        diff = diff_scans(load_scan(scans[0]), load_scan(scans[1]))
        assert len(diff["resolved"]) == 1  # CSP resolved
        assert len(diff["persisting"]) == 3  # the other 3 headers still missing
        assert diff["new"] == []
    finally:
        shutil.rmtree(tmp)


def test_grade_follows_worst_severity_not_count():
    recon = CrawlResult(target="https://example.com")
    recon.response_headers["https://example.com/"] = {}
    lows = _header_findings(recon)  # 4 Low findings, no Critical/High
    grade, _ = compute_grade(lows)
    assert grade == "B"
    assert compute_grade([])[0] == "A"


def test_parse_json_extracts_from_prose():
    # model ignored "no prose" instructions and wrapped the array in an explanation
    text = 'Sure, here you go:\n[{"a": 1}]\nHope that helps!'
    assert _parse_json(text) == [{"a": 1}]


def test_parse_json_strips_markdown_fence():
    assert _parse_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_confirm_scope_required():
    try:
        Config(target="https://example.com", confirm_scope=False)
        assert False, "should have raised"
    except ValueError:
        pass


def test_ai_checks_require_key():
    try:
        Config(target="https://example.com", confirm_scope=True, ai_checks=True, anthropic_api_key="")
        assert False, "should have raised"
    except ValueError:
        pass


def test_header_findings_flags_missing_headers():
    recon = CrawlResult(target="https://example.com")
    recon.response_headers["https://example.com/"] = {"Content-Type": "text/html"}
    findings = _header_findings(recon)
    assert len(findings) == 4  # CSP, XFO, HSTS, XCTO all missing
    assert all(f.severity == "Low" for f in findings)


def test_header_findings_ignore_third_party_assets():
    # A site can't add response headers to fonts.gstatic.com or a CDN it doesn't own —
    # flagging those as "your site's weaknesses" is noise, not a real finding.
    recon = CrawlResult(target="https://example.com")
    recon.response_headers["https://example.com/"] = {}
    recon.response_headers["https://fonts.gstatic.com/font.woff2"] = {}
    findings = _header_findings(recon)
    assert all(f.endpoint.startswith("https://example.com") for f in findings)


def test_report_builders_render():
    recon = CrawlResult(target="https://example.com")
    recon.response_headers["https://example.com/"] = {}
    findings = _header_findings(recon)
    md = build_markdown("https://example.com", findings)
    htm = build_html("https://example.com", findings)
    assert "Verified Vulnerabilities" in md
    assert "<table>" in htm


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all smoke tests passed")
