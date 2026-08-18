"""Configuration: env vars in, one Config object out. No framework needed."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

SAFE_HTTP_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}  # never fire PUT/DELETE/PATCH by default


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Tiny .env loader so we don't pull in python-dotenv for 8 lines of logic."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


@dataclass
class Config:
    target: str
    anthropic_api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    # claude-sonnet-5 is current as of Aug 2026; override via ANTHROPIC_MODEL if needed.
    anthropic_model: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5"))
    depth: int = 2
    ai_checks: bool = True
    confirm_scope: bool = False
    max_concurrency: int = 5
    rate_limit_rps: float = 3.0
    timeout: float = 15.0
    user_agent: str = "Verix/1.0 (+authorized-security-testing)"
    output_dir: Path = Path("./verix-reports")
    allow_unsafe_methods: bool = False  # PUT/DELETE/PATCH stay off unless explicitly opted in

    def __post_init__(self) -> None:
        if not self.confirm_scope:
            raise ValueError(
                "Refusing to run without --confirm-scope. You must explicitly confirm "
                "you are authorized to test this target."
            )
        if self.ai_checks and not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required when --ai-checks is enabled.")
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @property
    def allowed_methods(self) -> set[str]:
        return SAFE_HTTP_METHODS | ({"PUT", "DELETE", "PATCH"} if self.allow_unsafe_methods else set())
