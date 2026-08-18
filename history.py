"""Persist each scan run to disk and diff two runs for a before/after view."""
from __future__ import annotations

import json
import re
import uuid
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from reporter import compute_grade
from scanner import Finding


def _slug(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", target).strip("-").lower() or "target"


def save_scan(target: str, findings: list[Finding], history_dir: Path) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    grade, _ = compute_grade(findings)
    now = datetime.now().astimezone()  # local time — UTC in a report the user reads locally was just confusing
    ts = now.strftime("%Y-%m-%dT%H:%M:%S%z")
    # Sort key needs finer-than-1-second resolution: two scans saved in the same second would
    # otherwise sort by the random suffix, not save order, silently swapping "before"/"after".
    sort_key = now.strftime("%Y%m%dT%H%M%S%f")
    path = history_dir / f"{sort_key}_{uuid.uuid4().hex[:6]}_{_slug(target)}.json"
    path.write_text(
        json.dumps({"target": target, "timestamp": ts, "grade": grade, "findings": [asdict(f) for f in findings]}, indent=2),
        encoding="utf-8",
    )
    return path


def list_scans(history_dir: Path, target: str | None = None) -> list[Path]:
    if not history_dir.exists():
        return []
    paths = sorted(history_dir.glob("*.json"))
    if target:
        slug = _slug(target)
        paths = [p for p in paths if p.stem.endswith(f"_{slug}")]
    return paths


def load_scan(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _group_by_issue(findings: list[dict]) -> dict[tuple, list[dict]]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        groups[(f["category"], f["explanation"])].append(f)
    return groups


def diff_scans(before: dict, after: dict) -> dict:
    """Compare by issue type (category+explanation), not raw endpoint, since crawl noise
    (cache-busting query strings etc) makes exact endpoint URLs unstable between runs."""
    b, a = _group_by_issue(before["findings"]), _group_by_issue(after["findings"])
    resolved = sorted(b.keys() - a.keys())
    new = sorted(a.keys() - b.keys())
    persisting = sorted(b.keys() & a.keys())
    return {
        "grade_before": before["grade"],
        "grade_after": after["grade"],
        "resolved": [{"category": c, "explanation": e, "severity": b[(c, e)][0]["severity"], "endpoints_before": len(b[(c, e)])} for c, e in resolved],
        "new": [{"category": c, "explanation": e, "severity": a[(c, e)][0]["severity"], "endpoints_after": len(a[(c, e)])} for c, e in new],
        "persisting": [{"category": c, "explanation": e, "severity": a[(c, e)][0]["severity"],
                         "endpoints_before": len(b[(c, e)]), "endpoints_after": len(a[(c, e)])} for c, e in persisting],
    }
