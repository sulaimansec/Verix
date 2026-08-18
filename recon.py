"""Playwright-driven crawler: maps pages, forms, params, headers, cookies, scripts, and
anything that looks like an embedded AI/chat widget. Read-only navigation only."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.async_api import async_playwright

CHATBOT_HINTS = re.compile(
    r"(intercom|drift|zendesk|crisp|tawk|chatbot|chat-widget|livechat|"
    r"gpt|assistant|copilot|ai-chat)", re.I
)


@dataclass
class FormField:
    name: str
    type: str = "text"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    fields: list[FormField] = field(default_factory=list)
    source_page: str = ""


@dataclass
class CrawlResult:
    target: str
    pages: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    scripts: set[str] = field(default_factory=set)
    cookies: list[dict] = field(default_factory=list)
    response_headers: dict[str, dict[str, str]] = field(default_factory=dict)
    chatbot_hits: set[str] = field(default_factory=set)
    failed_pages: dict[str, str] = field(default_factory=dict)  # url -> why it didn't load


def _same_origin(base: str, url: str) -> bool:
    return urlparse(base).netloc == urlparse(url).netloc


async def crawl(target: str, depth: int, user_agent: str, timeout: float) -> CrawlResult:
    result = CrawlResult(target=target)
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(target, 0)]

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        context = await browser.new_context(user_agent=user_agent)
        page = await context.new_page()

        def on_response(response):
            result.response_headers[response.url] = dict(response.headers)

        page.on("response", on_response)

        while queue:
            url, level = queue.pop(0)
            if url in seen or level > depth:
                continue
            seen.add(url)

            try:
                # "networkidle" alone is fragile: any site with polling/analytics/chat-widget
                # traffic never goes idle and the whole page load times out for no real reason.
                # domcontentloaded is what actually matters for scraping; networkidle after that
                # is just a best-effort settle window, not something a page load should fail on.
                await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass
            except Exception as exc:
                result.failed_pages[url] = str(exc).splitlines()[0]  # first line only, keep it short
                continue

            result.pages.append(url)

            # query params on this page's own URL
            parsed = urlparse(url)
            if parsed.query:
                result.endpoints.append(Endpoint(url=url, method="GET", params=list(parse_qs(parsed.query))))

            # forms -> endpoints
            forms = await page.eval_on_selector_all(
                "form",
                """els => els.map(f => ({
                    action: f.action, method: (f.method || 'get').toUpperCase(),
                    fields: Array.from(f.elements).filter(e => e.name).map(e => ({name: e.name, type: e.type || 'text'}))
                }))""",
            )
            for f in forms:
                action = urljoin(url, f["action"] or url)
                result.endpoints.append(
                    Endpoint(
                        url=action,
                        method=f["method"],
                        fields=[FormField(**ff) for ff in f["fields"]],
                        source_page=url,
                    )
                )

            # scripts
            scripts = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            result.scripts.update(scripts)

            # chatbot / AI widget fingerprinting: script srcs, iframe srcs, body text hints
            html = await page.content()
            for candidate in list(scripts) + [url]:
                if CHATBOT_HINTS.search(candidate):
                    result.chatbot_hits.add(candidate)
            if CHATBOT_HINTS.search(html):
                result.chatbot_hits.add(f"{url} (inline DOM match)")

            # links, same-origin only, for next depth level
            if level < depth:
                links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for link in links:
                    link = link.split("#")[0]
                    if link and _same_origin(target, link) and link not in seen:
                        queue.append((link, level + 1))

        result.cookies = await context.cookies()
        await browser.close()

    return result
