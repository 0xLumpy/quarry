"""Rate coordination at the provider-account boundary.

Pacing state is keyed by `provider:<credential fingerprint>` and shared installation-wide, so every lane
touching one account queues behind one boundary while different providers keep separate ones.
Target-facing traffic is not here: that is `RATELIMIT.HTTP`.

The credential never appears in a path or in state — a truncated SHA-256 of it identifies the account.
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
    """This account's rate boundary could not be honoured, so the provider is not contacted.

    Not an evidence cap: replay is unaffected, and what was not bought is still there next lifecycle."""

    error_class = "pace_busy"


#: installation-wide, beside the other cross-project provider state. `QUARRY_PACE_DIR` redirects it for
#: harnesses that drive the real lanes against fakes; not an operator knob.
PACE_DIR = Path(os.environ.get("QUARRY_PACE_DIR")
                or (Path.home() / ".config" / "quarry" / "pace"))
#: how long we queue behind other Quarry processes for one provider slot before `PaceBusy`.
LOCK_WAIT_S = 30.0
#: a stamp dated further ahead than this is unusable, not skew: we wait a full interval instead.
CLOCK_SKEW_S = 300.0


def account(provider: str, credential=None) -> str:
    """`provider:<fingerprint>` — the identity of one rate-limited account. Unauthenticated providers
    coordinate by provider alone (`crt.sh:anonymous`)."""
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
    """Queue up to `wait_s` for this account's pacing slot, then raise `PaceBusy`. The queueing lives
    here because `budget.state_lock` is non-blocking by contract."""
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
    """The account's pacing state: missing is empty (a first request), unreadable or malformed raises
    `PaceBusy` — a state we cannot parse may hold a penalty."""
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
    """Write the state atomically, or raise `PaceBusy`: a half-written file would read as "no pacing
    history" to the next process."""
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
    """A shared wall-clock timestamp, or `now` when it is unusable — which costs a full interval's
    wait, where 0.0 would have let the request straight through."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return now
    v = float(value)
    if v != v or v in (float("inf"), float("-inf")):
        return now
    if v > now + CLOCK_SKEW_S:
        return now
    return v


def wait(key: str, interval_s: float, *, penalty_until: float = 0.0) -> float:
    """Wait until this account may be contacted again, then stamp the attempt. Returns seconds waited.

    The lock is held across the read-wait-stamp only, never across the request itself: this spaces
    request starts, it does not serialize provider traffic.

    `penalty_until` is a provider-imposed wall-clock deadline (a 429's `Retry-After`), persisted with the
    pacing state so the next run honours it, and always the longer of the two delays.

    Raises `PaceBusy` rather than proceeding unpaced."""
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
        # stamped before contact: a process that dies mid-request still leaves the account paced.
        _publish(path, {"last": float(time.time()), "until": until, "interval": interval})
    return slept


def note_penalty(key: str, until_wall: float) -> bool:
    """Persist a provider-imposed slowdown for this account. True when it was actually shared.

    Never raises: the caller is already on a failure path. False means the penalty is enforced nowhere
    but this process — the caller stops contacting the provider for the rest of its lifecycle."""
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
