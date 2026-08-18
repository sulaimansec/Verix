"""Orchestrates: recon -> AI hypotheses -> AI payloads -> safe HTTP probe -> AI verdict.
Plus a handful of cheap deterministic checks that don't need a model call at all.
"""
from __future__ import annotations

import asyncio
import itertools
import time
from dataclasses import dataclass, field

import httpx

from ai_brain import AIBrain, Hypothesis, Verdict
from config import Config
from recon import CrawlResult, Endpoint, _same_origin

SECURITY_HEADERS = {
    "content-security-policy": "No Content-Security-Policy header — increases XSS blast radius.",
    "x-frame-options": "No X-Frame-Options header — page may be embeddable in a clickjacking iframe.",
    "strict-transport-security": "No HSTS header — downgrade/stripping attacks against HTTPS are easier.",
    "x-content-type-options": "No X-Content-Type-Options header — MIME-sniffing risk.",
}

_id_counter = itertools.count(1)


@dataclass
class Finding:
    id: int
    category: str
    endpoint: str
    method: str
    severity: str
    confidence: str
    cvss: float
    payload: str
    explanation: str
    evidence: str
    remediation: str


def _summarize_recon(recon: CrawlResult) -> str:
    lines = [
        f"Target: {recon.target}",
        f"Pages crawled: {len(recon.pages)}",
        f"Endpoints/forms found: {len(recon.endpoints)}",
        f"Third-party/JS assets: {len(recon.scripts)}",
        f"Cookies set: {len(recon.cookies)}",
    ]
    if recon.chatbot_hits:
        lines.append("Possible AI/chat widgets detected: " + ", ".join(sorted(recon.chatbot_hits)))
    for ep in recon.endpoints[:40]:
        field_names = [f.name for f in ep.fields] or ep.params
        lines.append(f"- {ep.method} {ep.url} fields={field_names}")
    return "\n".join(lines)


def _header_findings(recon: CrawlResult) -> list[Finding]:
    findings = []
    seen_urls = set()
    for url, headers in recon.response_headers.items():
        if url in seen_urls:
            continue
        seen_urls.add(url)
        if not _same_origin(recon.target, url):
            continue  # third-party assets (fonts, analytics, CDNs) aren't the target's headers to fix
        lower = {k.lower(): v for k, v in headers.items()}
        for h, msg in SECURITY_HEADERS.items():
            if h not in lower:
                findings.append(
                    Finding(
                        id=next(_id_counter),
                        category="Missing Security Header",
                        endpoint=url,
                        method="GET",
                        severity="Low",
                        confidence="High",
                        cvss=3.1,
                        payload="",
                        explanation=msg,
                        evidence=f"Response headers: {list(headers.keys())}",
                        remediation=f"Add the `{h}` response header.",
                    )
                )
    return findings


@dataclass
class ScanEngine:
    config: Config
    recon: CrawlResult
    brain: AIBrain | None = None
    _sem: asyncio.Semaphore = field(init=False)
    _last_request: float = field(default=0.0, init=False)
    _rate_lock: asyncio.Lock = field(init=False)

    def __post_init__(self) -> None:
        self._sem = asyncio.Semaphore(self.config.max_concurrency)
        self._rate_lock = asyncio.Lock()

    async def _throttle(self) -> None:
        min_interval = 1.0 / self.config.rate_limit_rps
        async with self._rate_lock:
            wait = self._last_request + min_interval - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def _probe(self, client: httpx.AsyncClient, endpoint: Endpoint, param: str, payload: str) -> tuple[dict, dict]:
        method = endpoint.method.upper()
        if method not in self.config.allowed_methods:
            method = "GET"  # never escalate to an unsafe method the config didn't allow
        data = {param: payload}
        async with self._sem:
            await self._throttle()
            try:
                if method == "GET":
                    resp = await client.get(endpoint.url, params=data, timeout=self.config.timeout)
                else:
                    resp = await client.post(endpoint.url, data=data, timeout=self.config.timeout)
            except httpx.HTTPError as exc:
                return {"method": method, "url": endpoint.url, "param": param}, {"error": str(exc)}
        return (
            {"method": method, "url": endpoint.url, "param": param},
            {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:3000]},
        )

    async def _run_hypothesis(self, client: httpx.AsyncClient, hyp: Hypothesis, endpoint: Endpoint | None) -> list[Finding]:
        param_names = [f.name for f in endpoint.fields] if endpoint and endpoint.fields else (endpoint.params if endpoint else [])
        if not param_names:
            param_names = ["q"]
        payloads = await self.brain.generate_payloads(hyp, param_names)

        findings = []
        for payload in payloads:
            if endpoint is None:
                continue
            request_info, response_info = await self._probe(client, endpoint, param_names[0], payload)
            verdict: Verdict = await self.brain.analyze_response(hyp, payload, request_info, response_info)
            if verdict.vulnerable:
                findings.append(
                    Finding(
                        id=next(_id_counter),
                        category=hyp.category,
                        endpoint=endpoint.url,
                        method=request_info.get("method", endpoint.method),
                        severity=verdict.severity,
                        confidence=verdict.confidence,
                        cvss=verdict.cvss,
                        payload=payload,
                        explanation=verdict.explanation,
                        evidence=verdict.evidence,
                        remediation=verdict.remediation,
                    )
                )
        return findings

    async def run(self) -> list[Finding]:
        findings = _header_findings(self.recon)

        if not self.config.ai_checks:
            return findings
        if not self.recon.pages:
            # Nothing was actually crawled — sending Claude an empty recon summary just invites
            # it to guess/ramble instead of analyzing real data, and wastes a call either way.
            return findings

        self.brain = self.brain or AIBrain(api_key=self.config.anthropic_api_key, model=self.config.anthropic_model)
        hypotheses = await self.brain.hypothesize(_summarize_recon(self.recon))

        endpoint_by_url = {e.url: e for e in self.recon.endpoints}

        async with httpx.AsyncClient(headers={"User-Agent": self.config.user_agent}, follow_redirects=True) as client:
            tasks = [
                self._run_hypothesis(client, hyp, endpoint_by_url.get(hyp.endpoint) or next(iter(self.recon.endpoints), None))
                for hyp in hypotheses
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                continue
            findings.extend(r)

        return findings
