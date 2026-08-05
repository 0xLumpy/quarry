"""Rate coordination at the PROVIDER ACCOUNT boundary, not inside one lane's object.

review (Lumpy, 2026-08-05): a per-lifecycle interval is not a rate policy. Every `_ProviderCooldown()`
started with `last = 0`, so the first request of each lane — the paid pivot coordinator, the free
`shodan_host` lookups, the `/api-info` balance read — was unpaced relative to whatever ran a moment
before it, and two Quarry processes had entirely independent clocks. "One request per second" was true
of an object, not of the account being throttled.

The rule this implements:

    Rate coordination belongs to the provider/account boundary, not to an individual lane or lifecycle.

So the pacing state is keyed by `provider:<credential fingerprint>` and shared installation-wide:

  * Shodan's paid search, its free counts, its balance reads and the free host lane all queue behind ONE
    boundary, because they are one account being rate-limited.
  * Whoxy, Censys, CertSpotter and crt.sh get their OWN boundaries — different accounts, different rate
    policies, different concurrency models. Imposing one clock across providers would be the same
    mistake in the opposite direction.
  * TARGET-facing traffic is not here at all: that is `RATELIMIT.HTTP`, pressure on someone else's site.

The credential NEVER appears in a path or in state. A truncated SHA-256 of it identifies the account,
which is enough to tell two credentials apart and not enough to reconstruct either.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import time
from pathlib import Path

from . import budget

#: installation-wide, beside the other cross-project provider state (whoxy's spend lock lives here too)
PACE_DIR = Path.home() / ".config" / "quarry" / "pace"
#: how long we are willing to queue behind other Quarry processes for one provider slot. Beyond this the
#: request proceeds UNPACED rather than stalling a run indefinitely — politeness must not become a hang.
LOCK_WAIT_S = 30.0
#: tolerance for clock skew on a shared wall-clock timestamp. A "last request" dated in the future beyond
#: this is not skew; it is unusable, and we wait the full interval rather than trusting it.
CLOCK_SKEW_S = 300.0


def account(provider: str, credential=None) -> str:
    """`provider:<fingerprint>` — the identity of ONE rate-limited account.

    Unauthenticated providers coordinate by provider alone (`crt.sh:anonymous`), which is the honest
    answer: there is no account, only an endpoint everyone shares."""
    prov = "".join(c for c in str(provider).lower() if c.isalnum() or c in "-_.") or "provider"
    if not credential:
        return f"{prov}:anonymous"
    fp = hashlib.sha256(str(credential).encode("utf-8", "replace")).hexdigest()[:16]
    return f"{prov}:{fp}"


def _state_path(key: str) -> Path:
    safe = key.replace(":", "__")
    return PACE_DIR / f"{safe}.json"


@contextlib.contextmanager
def _slot(path: Path, wait_s: float):
    """Queue BRIEFLY for this account's pacing slot, then proceed regardless.

    `budget.state_lock` is deliberately non-blocking — parking a run behind another one is the wrong
    answer for LANE STATE. A pacing slot is the opposite case: waiting a moment for your turn is the
    whole point, so the queueing lives here instead of changing that contract. If the slot never frees,
    the request proceeds unpaced rather than stalling the run: politeness must never become a hang."""
    end = time.monotonic() + max(0.0, wait_s)
    while True:
        try:
            with budget.state_lock(path) as held:
                yield held
                return
        except budget.StateBusy:
            if time.monotonic() >= end:
                yield None                       # unpaced, but never stuck
                return
            time.sleep(0.05)


def _read(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _stamp(value, *, now: float) -> float:
    """A shared wall-clock timestamp, or 0.0 when it cannot be used."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    v = float(value)
    if v != v or v in (float("inf"), float("-inf")):
        return 0.0
    if v > now + CLOCK_SKEW_S:
        return 0.0                       # dated in the future: unusable, so wait the full interval
    return v


def wait(key: str, interval_s: float, *, penalty_until: float = 0.0) -> float:
    """Wait until this ACCOUNT may be contacted again, then stamp the attempt. Returns seconds waited.

    The lock is held only across the read-wait-stamp, never across the request itself: the goal is to
    space request STARTS, not to serialize provider traffic behind one slot. The timestamp is written
    BEFORE contact, so a process that dies mid-request still leaves the account paced.

    `penalty_until` is a provider-imposed slowdown (a 429's `Retry-After`) as a wall-clock deadline; it
    is persisted with the pacing state so a penalty earned by one run is honoured by the next, and it is
    always the LONGER of the two delays.

    Best-effort by construction: a state directory we cannot read or write must not stop a run. It costs
    politeness, never money — and the caller keeps its own in-process interval as a fallback."""
    interval = max(0.0, float(interval_s or 0.0))
    path = _state_path(key)
    try:
        PACE_DIR.mkdir(parents=True, exist_ok=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return 0.0                      # unusable state directory: unpaced, never a crash
    slept = 0.0
    try:
        with _slot(path.with_suffix(".lock"), LOCK_WAIT_S):
            doc = _read(path)
            clock = float(time.time())
            last = _stamp(doc.get("last"), now=clock)
            until = max(_stamp(doc.get("until"), now=clock), float(penalty_until or 0.0))
            ready = max(last + interval, until)
            if ready > clock:
                slept = ready - clock
                time.sleep(slept)
            stamp = float(time.time())
            try:
                path.write_text(json.dumps({"last": stamp, "until": until, "interval": interval}))
            except OSError:
                pass
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return slept
    return slept


def note_penalty(key: str, until_wall: float) -> None:
    """Persist a provider-imposed slowdown for this ACCOUNT, so the next run honours what this one earned.

    A 429 is a statement about the credential, not about the process that happened to receive it."""
    if not isinstance(until_wall, (int, float)) or isinstance(until_wall, bool):
        return
    path = _state_path(key)
    try:
        PACE_DIR.mkdir(parents=True, exist_ok=True)
        with _slot(path.with_suffix(".lock"), LOCK_WAIT_S):
            doc = _read(path)
            now = float(time.time())
            keep = max(_stamp(doc.get("until"), now=now), float(until_wall))
            doc.update({"until": keep, "last": _stamp(doc.get("last"), now=now)})
            path.write_text(json.dumps(doc))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return
