"""Framework-managed secrets — single store at ~/.config/quarry/secrets.yaml (chmod 600).

Holds only the keys the framework passes to tools itself (github / shodan / whoxy / chaos).
Tool-native configs (subfinder provider-config.yaml, waymore config.yml) keep their own files —
this never touches them. Secret VALUES are stripped from manifests/logs via redact(). Secrets
are never written to target.yaml, run manifests, reports, or AI prompts.

Missing/unset keys are not an error: the consuming step is skipped gracefully.
"""
from __future__ import annotations

import os
import re
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


#: LOCAL shape checks — never a network call (Lumpy, 2026-08-07: "not by pinging, and accidentally
#: create costs"). A pattern is declared ONLY where the provider's format is actually known; everywhere
#: else the answer is "set", with no claim about validity, because inventing a shape would reject a
#: perfectly good key. `doctor` reports the shape; nothing here ever gates a lane — a key we cannot
#: parse is still the operator's key, and the provider is the authority on whether it works.
_KEY_SHAPES = {
    # classic PAT `ghp_` + 36, fine-grained `github_pat_` + 82, and the pre-2021 40-hex tokens
    "github": re.compile(r"\A(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|[a-f0-9]{40})\Z"),
    "shodan": re.compile(r"\A[A-Za-z0-9]{32}\Z"),
}
#: what a key is NEVER: an unedited template placeholder, or a value with whitespace/quotes in it.
_PLACEHOLDER = re.compile(r"(?i)\A(<.*>|your[-_ ]?|changeme|xxx+|todo|none|null|example)")


def key_shape(kind: str, value: str) -> str:
    """"ok" | "malformed" | "unknown" — a LOCAL verdict on one key's shape.

    "unknown" is the honest default: it means we hold no documented format for that provider, so the
    key is reported as set and nothing is claimed about it."""
    v = (value or "").strip()
    if not v:
        return "unknown"
    if v != value or _PLACEHOLDER.match(v) or any(c.isspace() or c in "\"'" for c in v):
        return "malformed"
    rx = _KEY_SHAPES.get(kind)
    if rx is None:
        return "unknown"
    return "ok" if rx.match(v) else "malformed"


def github_tokens() -> list[str]:
    return _as_list(load().get("github"))


def shodan() -> str | None:
    return _scalar(load().get("shodan"))


def whoxy() -> str | None:
    return _scalar(load().get("whoxy"))


def chaos() -> str | None:
    """ProjectDiscovery / Chaos (PDCP) key — used by subfinder, asnmap, etc. via env."""
    return _scalar(load().get("projectdiscovery"))


def certspotter() -> str | None:
    """SSLMate certspotter API token (optional — the free tier works keyless at a low rate)."""
    return _scalar(load().get("certspotter"))


def openintel() -> dict:
    """ADVANCED optional passive source (openintel-subs binary + local subs.db). Returns {} unless
    the user set an `openintel:` block. Deliberately NOT a registered tool — install/update/doctor
    ignore it entirely, and it's SILENTLY unused unless BOTH `binary` and `db` are configured."""
    o = load().get("openintel")
    return o if isinstance(o, dict) else {}


def censys() -> dict:
    """OPTIONAL Censys Platform API creds — `{token: <PAT>, org: <organization-id>}`. Returns {} unless
    a `censys:` block is set. Silent opt-in (like openintel): install/update/doctor ignore it and the
    vertical Censys source is skipped without noise unless BOTH `token` and `org` are configured."""
    c = load().get("censys")
    return c if isinstance(c, dict) else {}


def oob() -> dict:
    """Out-of-band config (optional) for Quarry's ONE owned OOB layer. `interactsh_server`
    (+ optional `interactsh_token`) OVERRIDES the callback backend — used by Quarry's owned session
    (interactsh-client -server, normalized to a bare host) AND passed to nuclei (-iserver, full URL).
    Empty => the built-in public interactsh backend (no setup needed). `blind_xss_url` is a legacy/compat
    operator collector wired to dalfox -b (not the owned layer yet). All optional."""
    o = load().get("oob")
    return o if isinstance(o, dict) else {}


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
    for getter in (shodan, whoxy, chaos, certspotter):
        v = getter()
        if v:
            vals.append(v)
    nc = load().get("notify")                      # notify webhook URLs / telegram token are secret
    if isinstance(nc, dict):
        for k in ("slack", "discord", "webhook"):
            if isinstance(nc.get(k), str):
                vals.append(nc[k])
        tg = nc.get("telegram")
        if isinstance(tg, dict) and tg.get("token"):
            vals.append(str(tg["token"]))
    ob = load().get("oob")                          # interactsh token + blind-xss collector are secret
    if isinstance(ob, dict):
        for k in ("interactsh_token", "blind_xss_url"):
            if isinstance(ob.get(k), str):
                vals.append(ob[k])
    cy = load().get("censys")                        # censys Platform PAT is secret (org id is not)
    if isinstance(cy, dict) and isinstance(cy.get("token"), str):
        vals.append(cy["token"])
    return [v for v in vals if v and len(v) >= 6]


def redact(text: str | None) -> str | None:
    """Replace every known secret value in `text` with ***. Safe on None/empty."""
    if not text:
        return text
    for v in values():
        text = text.replace(v, "***")
    return text


def redact_deep(value):
    """`redact` over a whole STRUCTURE — every string leaf, at any depth.

    review-B1.6b24#1: structured outcome metadata was copied into the manifest verbatim while its prose
    siblings went through `redact`. Anything that carries an exception string — and machinery reasons
    now do — can carry a configured credential with it, and one unredacted sink is the whole leak.

    Containers are rebuilt rather than mutated: the caller's own object is evidence and is not ours to
    edit. Only CONFIGURED credentials are replaced; discovered secrets and verbatim provider evidence
    are untouched by this — they live in raw/ and are the point of the run."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        # keys too: a dict built from provider data can key on anything.
        return {redact_deep(k): redact_deep(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return type(value)(redact_deep(v) for v in value)
    return value


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
