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
import os
import time
from pathlib import Path

from . import budget

class PaceBusy(RuntimeError):
    """This account's rate boundary could not be HONOURED, so the provider is not contacted.

    review (Lumpy, 2026-08-05): the first version proceeded unpaced whenever the slot was held, the state
    was malformed, or a write failed — i.e. it stopped coordinating exactly when coordination mattered,
    and two processes could burst together. A fail-open pacer is advisory telemetry, not a boundary.

    Refusing is not an evidence cap and costs no coverage that a later run cannot take: replay is
    unaffected and remains immediate. It is declining to violate the account's rate policy blind."""

    error_class = "pace_busy"


#: installation-wide, beside the other cross-project provider state (whoxy's spend lock lives here too).
#: `QUARRY_PACE_DIR` redirects it for harnesses that drive the real lanes against fakes — the gate script
#: was writing pacing timestamps into the operator's actual account state, which is the same leak the
#: test suite had one layer in. Not an operator knob: pacing is not something to turn down.
PACE_DIR = Path(os.environ.get("QUARRY_PACE_DIR")
                or (Path.home() / ".config" / "quarry" / "pace"))
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
    """Queue BRIEFLY for this account's pacing slot, or REFUSE.

    `budget.state_lock` is deliberately non-blocking — parking a run behind another one is the wrong
    answer for LANE STATE. A pacing slot is the opposite case: waiting your turn is the whole point, so
    the queueing lives here rather than changing that contract.

    A bounded wait is reasonable; contacting the provider AFTER giving up on that wait is not, because
    the other holder is about to do the same. `PaceBusy` bounds the wait without abandoning the
    boundary."""
    end = time.monotonic() + max(0.0, wait_s)
    while True:
        try:
            with budget.state_lock(path) as held:
                yield held
                return
        except budget.StateBusy:
            if time.monotonic() >= end:
                raise PaceBusy(f"another process holds this account's pacing slot ({path})") from None
            time.sleep(0.05)


def _read(path: Path) -> dict:
    """The account's pacing state. MISSING is empty (a first request); UNREADABLE refuses.

    A state we cannot parse may hold a penalty we are about to ignore, so it is not the same as no
    history at all (review#2)."""
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise PaceBusy(f"pacing state unreadable: {e}") from e
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise PaceBusy(f"pacing state is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise PaceBusy(f"pacing state root is {type(doc).__name__}, not an object")
    return doc


def _publish(path: Path, doc: dict) -> None:
    """Write the state ATOMICALLY, or refuse. `write_text` can leave a half-written file behind, and the
    next process would read that as "no pacing history" — the failure mode this whole module exists to
    prevent (review#2)."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(doc))
        os.replace(tmp, path)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        with contextlib.suppress(Exception):
            tmp.unlink()
        raise PaceBusy(f"pacing state could not be durably updated: {e}") from e


def _stamp(value, *, now: float) -> float:
    """A shared wall-clock timestamp, or `now` when it cannot be used.

    review#3 (Lumpy): returning 0.0 put `last + interval` near the Unix epoch, so an unusable stamp let
    the request through IMMEDIATELY — the opposite of the documented "wait the full interval". Falling
    back to the current time is what actually produces that wait."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return now
    v = float(value)
    if v != v or v in (float("inf"), float("-inf")):
        return now
    if v > now + CLOCK_SKEW_S:
        return now                       # dated in the future: unusable, so wait a full interval
    return v


def wait(key: str, interval_s: float, *, penalty_until: float = 0.0) -> float:
    """Wait until this ACCOUNT may be contacted again, then stamp the attempt. Returns seconds waited.

    The lock is held only across the read-wait-stamp, never across the request itself: the goal is to
    space request STARTS, not to serialize provider traffic behind one slot. The timestamp is written
    BEFORE contact, so a process that dies mid-request still leaves the account paced.

    `penalty_until` is a provider-imposed slowdown (a 429's `Retry-After`) as a wall-clock deadline; it
    is persisted with the pacing state so a penalty earned by one run is honoured by the next, and it is
    always the LONGER of the two delays.

    RAISES `PaceBusy` rather than proceeding unpaced. A boundary that gives up under contention or on
    damaged state is not a boundary — and refusing costs no evidence: replay is untouched, and the pages
    we did not buy are still there to buy in the next lifecycle."""
    interval = max(0.0, float(interval_s or 0.0))
    path = _state_path(key)
    try:
        PACE_DIR.mkdir(parents=True, exist_ok=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        raise PaceBusy(f"pacing state directory unusable: {e}") from e
    slept = 0.0
    with _slot(path.with_suffix(".lock"), LOCK_WAIT_S):
        doc = _read(path)
        clock = float(time.time())
        last = _stamp(doc.get("last"), now=clock) if "last" in doc else 0.0
        until = max(_stamp(doc.get("until"), now=clock) if "until" in doc else 0.0,
                    float(penalty_until or 0.0))
        ready = max(last + interval, until)
        if ready > clock:
            slept = ready - clock
            time.sleep(slept)
        # written BEFORE contact and atomically: a process that dies mid-request still leaves the
        # account paced, and never leaves a fragment the next process reads as "no history".
        _publish(path, {"last": float(time.time()), "until": until, "interval": interval})
    return slept


def note_penalty(key: str, until_wall: float) -> bool:
    """Persist a provider-imposed slowdown for this ACCOUNT. True when it was actually SHARED.

    A 429 is a statement about the credential, not about the process that happened to receive it. But a
    penalty we could not publish is not enforced anywhere else: an older, perfectly valid state file
    stays readable, so the next process proceeds without it (review#3, Lumpy). This never raises — the
    request already happened and the caller is on a failure path — and it never CLAIMS the sharing
    worked. The caller stops contacting the provider for the rest of its lifecycle instead."""
    if not isinstance(until_wall, (int, float)) or isinstance(until_wall, bool):
        return False
    path = _state_path(key)
    try:
        PACE_DIR.mkdir(parents=True, exist_ok=True)
        with _slot(path.with_suffix(".lock"), LOCK_WAIT_S):
            doc = _read(path)
            now = float(time.time())
            keep = max(_stamp(doc.get("until"), now=now) if "until" in doc else 0.0, float(until_wall))
            doc.update({"until": keep,
                        "last": _stamp(doc.get("last"), now=now) if "last" in doc else 0.0})
            _publish(path, doc)
            return True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False
