"""Shared pipeline: recon -> scan -> report. Used by both cli.py and app.py so the
orchestration logic lives in exactly one place."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from config import Config
from history import save_scan
from recon import CrawlResult, crawl
from reporter import write_reports
from scanner import Finding, ScanEngine


async def run_scan(
    config: Config, on_stage: Callable[[str], None] | None = None
) -> tuple[CrawlResult, list[Finding], Path, Path]:
    def stage(msg: str) -> None:
        if on_stage:
            on_stage(msg)

    stage("Crawling target (recon)...")
    recon = await crawl(config.target, config.depth, config.user_agent, config.timeout)
    stage(f"Recon done: {len(recon.pages)} pages, {len(recon.endpoints)} endpoints, "
          f"{len(recon.chatbot_hits)} chatbot/AI hint(s)")
    if recon.failed_pages:
        sample = list(recon.failed_pages.items())[:3]
        stage(f"⚠ {len(recon.failed_pages)} page(s) failed to load, e.g. " +
              "; ".join(f"{u} ({e})" for u, e in sample))
    if not recon.pages:
        stage("⚠ Nothing crawled successfully — check the target URL/network before trusting a 0-finding result.")

    stage("Running AI-driven vulnerability probes...")
    findings = await ScanEngine(config=config, recon=recon).run()
    stage(f"Scan done: {len(findings)} findings")

    stage("Writing reports...")
    md_path, html_path = write_reports(config.target, findings, config.output_dir)
    save_scan(config.target, findings, config.output_dir / "history")
    stage("Reports written")

    return recon, findings, md_path, html_path
