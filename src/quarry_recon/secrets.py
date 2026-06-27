"""Framework-managed secrets — single store at ~/.config/quarry/secrets.yaml (chmod 600).

Holds only the keys the framework passes to tools itself (github / shodan / whoxy / chaos).
Tool-native configs (subfinder provider-config.yaml, waymore config.yml) keep their own files —
this never touches them. Secret VALUES are stripped from manifests/logs via redact(). Secrets
are never written to target.yaml, run manifests, reports, or AI prompts.

Missing/unset keys are not an error: the consuming step is skipped gracefully.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import yaml

PATH = Path.home() / ".config" / "quarry" / "secrets.yaml"
_cache: dict | None = None


def load() -> dict:
    global _cache
    if _cache is None:
        try:
            _cache = (yaml.safe_load(PATH.read_text()) or {}) if PATH.exists() else {}
        except (yaml.YAMLError, OSError):
            _cache = {}
    return _cache


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v.strip()] if v.strip() else []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return []


def _scalar(v) -> str | None:
    items = _as_list(v)
    return items[0] if items else None


def github_tokens() -> list[str]:
    return _as_list(load().get("github"))


def shodan() -> str | None:
    return _scalar(load().get("shodan"))


def whoxy() -> str | None:
    return _scalar(load().get("whoxy"))


def chaos() -> str | None:
    """ProjectDiscovery / Chaos (PDCP) key — used by subfinder, asnmap, etc. via env."""
    return _scalar(load().get("projectdiscovery"))


def github_tokens_file() -> Path | None:
    """Materialize a 0600 temp file of the GitHub tokens for tools that take `-t <file>`
    (github-subdomains). Returns None if no tokens. Caller unlinks when done."""
    toks = github_tokens()
    if not toks:
        return None
    fd, name = tempfile.mkstemp(prefix="quarry-gh-", suffix=".txt")
    os.close(fd)
    p = Path(name)
    p.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    p.write_text("\n".join(toks) + "\n")
    return p


def values() -> list[str]:
    """Every secret value, for redaction. Only values long enough to be real keys."""
    vals = list(github_tokens())
    for getter in (shodan, whoxy, chaos):
        v = getter()
        if v:
            vals.append(v)
    return [v for v in vals if v and len(v) >= 6]


def redact(text: str | None) -> str | None:
    """Replace every known secret value in `text` with ***. Safe on None/empty."""
    if not text:
        return text
    for v in values():
        text = text.replace(v, "***")
    return text


def _coerce(value) -> str:
    if isinstance(value, str):
        return value
    import json as _json
    return _json.dumps(value, sort_keys=True, default=str)


def mask(value) -> str:
    """Short, non-usable preview of a DISCOVERED secret (a scanner finding, not our own
    key) — enough to recognize in a report, not enough to use. Raw evidence stays in the
    controlled raw/ files only."""
    s = _coerce(value).strip()
    if not s:
        return ""
    if len(s) <= 12:
        return f"…({len(s)} chars)"          # too short to show any char without leaking
    return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"


def fingerprint(value) -> str:
    """Stable short hash of a secret value — used as a dedup id without storing the raw."""
    import hashlib
    return hashlib.sha256(_coerce(value).encode("utf-8", "replace")).hexdigest()[:12]


def apply_env() -> None:
    """Export PDCP_API_KEY so ProjectDiscovery tools (subfinder -pc, asnmap, …) pick up the
    chaos key without it ever appearing on a command line. No-op if unset or already set."""
    k = chaos()
    if k and not os.environ.get("PDCP_API_KEY"):
        os.environ["PDCP_API_KEY"] = k


def reset_cache() -> None:
    global _cache
    _cache = None
