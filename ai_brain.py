"""Claude wrapper: turns recon data into attack hypotheses, hypotheses into payloads,
and raw responses into a verdict. Every prompt pins Claude to non-destructive,
read-only testing — it is told to refuse anything else.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from anthropic import AsyncAnthropic

SAFETY_RULES = (
    "You are the reasoning core of an authorized, non-destructive web penetration test. "
    "The operator has explicit written permission to test this target. Rules you must follow:\n"
    "1. Never propose payloads that delete/modify data, cause denial-of-service, or exfiltrate "
    "real user data. Prefer time-based, boolean-based, reflection-based, and echo-based checks.\n"
    "2. Never propose destructive HTTP methods (PUT/DELETE/PATCH) unless explicitly told they are in scope.\n"
    "3. For LLM/chatbot targets, only attempt prompt-injection / system-prompt-leak / jailbreak probes "
    "that read behavior back — never instruct a live system to take real-world destructive actions.\n"
    "4. Respond with ONLY valid JSON matching the requested schema. No prose, no markdown fences."
)


class BrainError(RuntimeError):
    """Claude didn't return usable JSON — usually a refusal or stray prose. The message
    includes the model's actual reply so you can see why instead of a bare JSONDecodeError."""


def _parse_json(text: str) -> dict | list:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Model added prose around the JSON despite instructions — grab the first [...]/{...} block.
        match = re.search(r"[\[{].*[\]}]", text, re.S)
        if match:
            return json.loads(match.group(0))
        raise


@dataclass
class Hypothesis:
    category: str
    endpoint: str
    rationale: str
    suggested_test: str


@dataclass
class Verdict:
    vulnerable: bool
    severity: str = "Info"
    confidence: str = "Low"
    cvss: float = 0.0
    explanation: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class AIBrain:
    api_key: str
    model: str = "claude-sonnet-5"
    client: AsyncAnthropic = field(init=False)

    def __post_init__(self) -> None:
        self.client = AsyncAnthropic(api_key=self.api_key)

    async def _ask(self, prompt: str, max_tokens: int = 2000) -> dict | list:
        messages = [{"role": "user", "content": prompt}]
        for attempt in range(2):  # one retry with a corrective nudge if the model adds prose/refuses
            resp = await self.client.messages.create(
                model=self.model, max_tokens=max_tokens, system=SAFETY_RULES, messages=messages
            )
            raw = "".join(block.text for block in resp.content if block.type == "text").strip()
            try:
                return _parse_json(raw)
            except json.JSONDecodeError:
                if attempt == 1:
                    snippet = raw[:500] or f"(empty reply, stop_reason={resp.stop_reason})"
                    raise BrainError(
                        f"Claude did not return valid JSON for this request (model={self.model}). "
                        f"Its actual reply was:\n\n{snippet}"
                    ) from None
                if resp.stop_reason == "max_tokens":
                    # Got cut off mid-JSON, not malformed by choice — a "be more careful" nudge
                    # won't fix that, only room to finish will. Retry fresh with a bigger budget
                    # and a request to keep it terse, instead of building on the truncated reply.
                    max_tokens = min(max_tokens * 2, 8192)
                    messages = [{"role": "user", "content": prompt + "\n\nKeep every field brief (one short sentence) — you have limited output space."}]
                else:
                    messages += [
                        {"role": "assistant", "content": raw or "(empty)"},
                        {"role": "user", "content": "That wasn't valid JSON. Reply with ONLY the JSON, no prose, no markdown fences."},
                    ]
        raise AssertionError("unreachable")  # loop always returns or raises

    async def hypothesize(self, recon_summary: str) -> list[Hypothesis]:
        prompt = f"""Given this recon summary of a web app, propose up to 12 attack hypotheses
covering OWASP Top 10, business-logic flaws (IDOR, race conditions, workflow bypass), and,
if any AI/chat widgets were found, OWASP Top 10 for LLM Applications (prompt injection,
system prompt leakage, jailbreak, excessive agency/SSRF via tool-calling, excessive disclosure).

Recon summary:
{recon_summary}

Keep "rationale" and "suggested_test" to one short sentence each — you're listing many
hypotheses, not writing an essay per one.
Return a JSON array of objects: [{{"category": str, "endpoint": str, "rationale": str, "suggested_test": str}}]"""
        data = await self._ask(prompt, max_tokens=3000)
        return [Hypothesis(**h) for h in data]

    async def generate_payloads(self, hypothesis: Hypothesis, param_names: list[str]) -> list[str]:
        prompt = f"""Attack hypothesis: {hypothesis.category} on {hypothesis.endpoint}
Rationale: {hypothesis.rationale}
Suggested test: {hypothesis.suggested_test}
Available parameters/fields: {param_names}

Generate up to 6 concrete, NON-DESTRUCTIVE payload strings to test this hypothesis
(read-only / reflection / timing / benign-marker based — no data mutation).
Return a JSON array of strings only."""
        data = await self._ask(prompt, max_tokens=800)
        return list(data)

    async def analyze_response(
        self, hypothesis: Hypothesis, payload: str, request_info: dict, response_info: dict
    ) -> Verdict:
        prompt = f"""Analyze this probe result for the hypothesis "{hypothesis.category}" on
{hypothesis.endpoint}.

Payload sent: {payload!r}
Request: {json.dumps(request_info)[:2000]}
Response: {json.dumps(response_info)[:4000]}

Decide if this is a verified vulnerability, a weakness, or benign. Return JSON:
{{"vulnerable": bool, "severity": "Critical|High|Medium|Low|Info",
  "confidence": "High|Medium|Low", "cvss": number, "explanation": str,
  "evidence": str, "remediation": str}}"""
        data = await self._ask(prompt, max_tokens=600)
        return Verdict(**data)
