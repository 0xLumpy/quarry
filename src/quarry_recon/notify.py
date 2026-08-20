"""Optional multi-channel run notifications — opt-in, off by default.

Config lives in the 0600 `secrets.yaml` under `notify:`. Nothing is sent unless both an event and a
channel are configured. Best-effort: a failed notification never breaks a run, and messages are
`secrets.redact()`'d before send.

    notify:
      events: [complete, error]          # opt in per event (default: none = off)
      slack:    https://hooks.slack.com/services/…
      discord:  https://discord.com/api/webhooks/…
      telegram: {token: "123:abc", chat_id: "456"}
      webhook:  https://my.endpoint/quarry
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlunsplit

from . import fetch, secrets

EVENTS = ("complete", "error", "lead")     # run finished · phase/tool error · promising lead

#: how a run verdict is said to a human, so no internal token ships outward.
VERDICT_WORDS = {"complete": "run completed",
                 "complete_with_limits": "run completed, with expected limits",
                 "complete_with_gaps": "run completed; coverage needs attention"}
#: at most this many bullets per section, then a pointer at the manifest.
_MAX_BULLETS = 5
CHANNELS = ("slack", "discord", "telegram", "webhook")


class NotificationTransportError(RuntimeError):
    """A notification was refused before any unbound network effect."""


def _cfg() -> dict:
    c = secrets.load().get("notify")
    return c if isinstance(c, dict) else {}


def enabled_events() -> set:
    ev = _cfg().get("events")
    if isinstance(ev, str):                    # accept scalar `events: complete` as well as a list
        ev = [ev]
    return {e for e in (ev or []) if e in EVENTS}


def channels() -> dict:
    c = _cfg()
    return {k: c[k] for k in CHANNELS if c.get(k)}


def configured() -> bool:
    """True when at least one event and one channel are set — otherwise notify is a no-op."""
    return bool(enabled_events() and channels())


def _canonical_endpoint(url: str, name: str) -> str:
    """Accept one canonical HTTPS endpoint, without ever rendering its secret path."""
    try:
        parts = fetch._validated_http_url(url)
        host = fetch._canonical_http_host(parts.hostname)
        rendered_host = f"[{host}]" if ":" in host else host
        netloc = rendered_host + (f":{parts.port}" if parts.port is not None else "")
        canonical = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
    except (TypeError, ValueError):
        raise NotificationTransportError("notification endpoint is not a canonical HTTPS URL") from None
    if parts.scheme != "https" or parts.fragment or url != canonical:
        raise NotificationTransportError("notification endpoint is not a canonical HTTPS URL")
    if name == "slack" and (host != "hooks.slack.com" or parts.port not in (None, 443)):
        raise NotificationTransportError("Slack endpoint is outside its fixed HTTPS authority")
    if name == "discord" and (host != "discord.com" or parts.port not in (None, 443)):
        raise NotificationTransportError("Discord endpoint is outside its fixed HTTPS authority")
    if name == "telegram" and (host != "api.telegram.org" or parts.port not in (None, 443)):
        raise NotificationTransportError("Telegram endpoint is outside its fixed HTTPS authority")
    return canonical


def _context(run):
    if fetch._network_scope(SimpleNamespace(run=run)) is None:
        raise NotificationTransportError("notifications require a bound run network policy")
    # Notification transport deliberately has no target scope or target pacing.
    return SimpleNamespace(run=run, profile=SimpleNamespace(block_private_targets=False),
                           scope=SimpleNamespace(active_allowed=lambda _host: False))


def _post(run, name: str, url: str, payload: dict, timeout: int = 10) -> None:
    endpoint = _canonical_endpoint(url, name)
    status = fetch.scoped_operator_post(
        _context(run), endpoint,
        json.dumps(payload, separators=(",", ":")).encode("utf-8"), timeout=timeout,
        source_id=f"notify.{name}",
    )
    if not 200 <= status < 300:
        raise NotificationTransportError("notification transport was refused")


def _send_channel(run, name: str, target, title: str, body: str) -> None:
    text = f"*{title}*\n{body}" if body else f"*{title}*"
    if name == "slack":
        _post(run, name, target, {"text": text})
    elif name == "discord":
        _post(run, name, target, {"content": text[:1900]})       # discord hard-caps message length
    elif name == "telegram":
        tok = (target or {}).get("token")
        chat = (target or {}).get("chat_id")
        if tok and chat:
            _post(run, name, f"https://api.telegram.org/bot{tok}/sendMessage",
                  {"chat_id": chat, "text": text})
    elif name == "webhook":
        _post(run, name, target, {"title": title, "body": body})


def send(event: str, title: str, body: str = "", *, run=None) -> int:
    """Send `event` to every configured channel that enabled it, redacted. Returns the count of channels
    notified. Best-effort — never raises."""
    if event not in enabled_events():
        return 0
    if run is None:
        return 0
    title = secrets.redact(title) or ""
    body = secrets.redact(body) or ""
    sent = 0
    for name, target in channels().items():
        try:
            _send_channel(run, name, target, title, body)
            sent += 1
        except Exception:
            continue
    return sent


def _bullets(summary: dict) -> tuple[list, list]:
    """(needs_attention, expected_limits), from the manifest's own structured fields.

    Two categories, never merged: a failure or coverage gap is something wrong, while a provider quota or
    our own budget is an expected boundary nothing can retry."""
    fails, gaps = summary.get("failures") or [], summary.get("gaps") or []
    pexc = summary.get("phase_exceptions") or []
    attention: list = []
    if fails:
        tools = sorted({f.get("tool", "?") for f in fails})
        attention.append(f"{len(fails)} tool run(s) failed ({', '.join(tools[:4])})")
    if gaps:
        tools = sorted({g.get("tool", "?") for g in gaps})
        attention.append(f"{len(gaps)} degraded run(s) across {len(tools)} tool(s) "
                         f"({', '.join(tools[:4])}) — coverage incomplete")
    if pexc:
        attention.append(f"{len(pexc)} phase exception(s)")
    limits: list = []
    for row in (summary.get("provider_limits") or []):
        limits.append(f"{row.get('tool', '?')} — {row.get('why') or row.get('error_class') or 'provider limit'}")
    for row in (summary.get("operator_limits") or []):
        limits.append(f"{row.get('tool', '?')} — {row.get('why') or 'withheld by our own budget'} (our bound)")
    return attention, limits


def completion_message(*, target: str, run_id: str, summary: dict, totals: str = "",
                       leads: int = 0) -> tuple[str, str]:
    """(title, body) for a finished run — the one rendering every outbound transport shares."""
    verdict = summary.get("verdict", "")
    title = f"Quarry {target}: {VERDICT_WORDS.get(verdict, 'run finished')}"
    if leads:
        title += f" — {leads} promising lead(s)"
    lines = [f"run {run_id}"]
    if totals:
        lines.append(totals)
    attention, limits = _bullets(summary)
    for label, rows in (("Needs attention", attention), ("Expected limits", limits)):
        if not rows:
            continue
        lines += ["", f"{label}:"] + [f"• {r}" for r in rows[:_MAX_BULLETS]]
        if len(rows) > _MAX_BULLETS:
            lines.append(f"  +{len(rows) - _MAX_BULLETS} more in manifest.json")
    return title, "\n".join(lines)


def send_completion(*, target: str, run_id: str, summary: dict, totals: str = "", leads: int = 0,
                    run=None) -> int:
    """Send one consolidated run-completion message, whichever of `complete`/`lead` is enabled.

    `complete` sends always and carries any lead headline; `lead` alone sends only when there are leads.
    Returns the count of channels notified."""
    events = enabled_events()
    if "complete" in events:
        event = "complete"
    elif "lead" in events and leads:
        event = "lead"
    else:
        return 0
    title, body = completion_message(target=target, run_id=run_id, summary=summary,
                                     totals=totals, leads=leads)
    # Keep the pure rendering/test seam positional; production run callers pass
    # the explicit authority-bearing repository.
    return send(event, title, body) if run is None else send(event, title, body, run=run)


def send_test() -> int:
    """Refuse tests: this command has no run-bound network authority."""
    raise NotificationTransportError(
        "notify --test is unavailable: notification sends require a bound run network policy",
    )
