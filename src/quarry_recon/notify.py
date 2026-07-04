"""Optional multi-channel run notifications — OPT-IN, OFF by default.

Config lives in the 0600 `secrets.yaml` under `notify:` — a list of enabled events + per-channel
targets. Nothing is sent unless the user configures both an event and a channel. Best-effort: a
failed notification NEVER breaks a run. Messages are `secrets.redact()`'d before send.

    notify:
      events: [complete, error]          # opt in per event (default: none = off)
      slack:    https://hooks.slack.com/services/…
      discord:  https://discord.com/api/webhooks/…
      telegram: {token: "123:abc", chat_id: "456"}
      webhook:  https://my.endpoint/quarry
"""
from __future__ import annotations

import json
import urllib.request

from . import secrets

EVENTS = ("complete", "error", "lead")     # run finished · phase/tool error · promising lead
CHANNELS = ("slack", "discord", "telegram", "webhook")


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
    """True when at least one event AND one channel are set — otherwise notify is a no-op."""
    return bool(enabled_events() and channels())


def _post(url: str, payload: dict, timeout: int = 10) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=timeout).close()


def _send_channel(name: str, target, title: str, body: str) -> None:
    text = f"*{title}*\n{body}" if body else f"*{title}*"
    if name == "slack":
        _post(target, {"text": text})
    elif name == "discord":
        _post(target, {"content": text[:1900]})       # discord hard-caps message length
    elif name == "telegram":
        tok = (target or {}).get("token")
        chat = (target or {}).get("chat_id")
        if tok and chat:
            _post(f"https://api.telegram.org/bot{tok}/sendMessage",
                  {"chat_id": chat, "text": text})
    elif name == "webhook":
        _post(target, {"title": title, "body": body})


def send(event: str, title: str, body: str = "") -> int:
    """Send `event` to every configured channel IF the user enabled that event. Returns the count of
    channels notified. Best-effort — never raises. Secrets are redacted from the message first."""
    if event not in enabled_events():
        return 0
    title = secrets.redact(title) or ""
    body = secrets.redact(body) or ""
    sent = 0
    for name, target in channels().items():
        try:
            _send_channel(name, target, title, body)
            sent += 1
        except Exception:
            continue
    return sent


def send_test() -> int:
    """Send a test message to every configured channel, bypassing event-gating (for `notify --test`
    / doctor validation). Returns channels reached."""
    sent = 0
    for name, target in channels().items():
        try:
            _send_channel(name, target, "Quarry notify test",
                          "If you see this, the channel works.")
            sent += 1
        except Exception:
            continue
    return sent
