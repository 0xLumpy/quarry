"""Machine-scoped runtime settings — the non-secret counterpart to secrets.yaml.

Store: `~/.config/quarry/config.yaml`. Non-credential, non-per-engagement knobs — local
performance / concurrency and advanced local tool paths (secrets.yaml = credentials;
target.yaml = the engagement). Every key is optional: a missing file or unset key falls back to a
safe default. Created once by bootstrap and never overwritten.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

import yaml

PATH = Path.home() / ".config" / "quarry" / "config.yaml"
_cache: dict | None = None
#: run-scoped knob overrides from an explicit operator flag; win over the file for this process only,
#: through the same strict readers (a flag can never introduce a value the file could not hold).
_overrides: dict = {}

PROFILES = ("safe", "balanced", "aggressive", "auto")


def load() -> dict:
    global _cache
    if _cache is None:
        try:
            _cache = (yaml.safe_load(PATH.read_text()) or {}) if PATH.exists() else {}
        except (yaml.YAMLError, OSError):
            _cache = {}
    return _cache


def override(key: str, value) -> None:
    _overrides[key] = value


def clear_overrides() -> None:
    _overrides.clear()


@contextlib.contextmanager
def overrides(values: dict):
    """Apply flag overrides for one run, restoring the previous set on exit."""
    before = dict(_overrides)
    _overrides.update(values)
    try:
        yield
    finally:
        _overrides.clear()
        _overrides.update(before)


def source_of(key: str) -> str:
    """Where a value for `key` came from: a run `flag`, the machine `config`, else `default`.

    Presence is not acceptance — a value the strict parser rejects still leaves the key present here;
    `strict_int_with_source()` gives the attribution of an effective value."""
    if key in _overrides:
        return "flag"
    return "config" if key in performance() else "default"


def performance() -> dict:
    p = load().get("PERFORMANCE")
    return p if isinstance(p, dict) else {}


def profile() -> str:
    """The concurrency profile: safe | balanced | aggressive | auto (default). `auto` derives worker
    counts from cpu cores at run time; the others are fixed tiers. Unknown value → `auto`."""
    prof = str(performance().get("PROFILE") or "auto").strip().lower()
    return prof if prof in PROFILES else "auto"


def web_port_prefilter() -> bool:
    """SYN web-port prefilter before the bulk httpx (naabu over host IPs × the HTTP port set → httpx
    only on open host:ports). Default on. `false` restores direct httpx over all configured ports; the
    private/reserved-only-host skip still applies. Separate from MODES.PORTSCAN (infra scan)."""
    v = performance().get("WEB_PORT_PREFILTER")
    if v is None:
        return True
    return str(v).strip().lower() not in ("false", "no", "0", "off")


def strict_int(key: str, *, default: int, maximum: int) -> int:
    """A coverage/budget knob from PERFORMANCE, parsed strictly: an exact int (never a bool) or a clean
    int-string in 0..maximum. Anything else falls back to `default` rather than inventing a policy from
    a typo.

    `0` is a meaningful value here (unbounded budget, full depth, …), which is why this is separate from
    `concurrency()` — that one clamps to >= 1 and would turn an intentional 0 into 1."""
    return strict_int_with_source(key, default=default, maximum=maximum)[0]


def _diagnostic(raw, *, maximum: int | None = None) -> str:
    """A bounded, non-disclosing description of a value the parser refused.

    The text reaches the console and `manifest.json`, so it is not an unrestricted echo: the whole
    representation is redacted first, and a number is shown only when short enough to be a bound rather
    than a secret — otherwise it is described by digit count and how it missed the range."""
    from . import secrets
    if isinstance(raw, bool):
        return repr(raw)
    numeric = None
    limit = _int_str_limit()
    if isinstance(raw, (int, float)):
        if isinstance(raw, int) and _digit_count(raw) > limit:
            # too long to render: describe it from its bit length, never build the string
            return f"int({_digit_count(raw)} digits; {_range_note(raw, maximum)})"
        text, quoted = repr(raw), False
        numeric = raw
    elif isinstance(raw, str):
        stripped = raw.strip()
        body = stripped[1:] if stripped[:1] == "-" else stripped
        if body.isdigit():
            if len(_significant(body)) > limit:
                # this many significant digits cannot be converted, and is above any maximum
                return (f"str({len(body)} digits; "
                        f"{'below zero' if stripped[:1] == '-' else _range_note(None, maximum)})")
            text, quoted = stripped, True
            numeric = int(_significant(body) or "0") * (-1 if stripped[:1] == "-" else 1)
        else:
            return f"str({len(raw)} chars)"             # never the content of an opaque value
    elif isinstance(raw, (list, tuple, set)):
        return f"{type(raw).__name__}({len(raw)} item(s))"
    elif isinstance(raw, dict):
        return f"dict({len(raw)} key(s))"
    else:
        return type(raw).__name__
    digits = sum(c.isdigit() for c in text)
    kind = "str" if quoted else type(raw).__name__
    # redact the whole representation before shortening anything
    if (secrets.redact(text) or text) != text or digits > _DIAGNOSTIC_DIGITS:
        return f"{kind}({digits} digits; {_range_note(numeric, maximum)})"
    return f"'{text}'" if quoted else text


#: how many digits a rejected number may show before it is described instead — a mistyped bound is
#: short (1440, 5000, 100000), a credential is not.
_DIAGNOSTIC_DIGITS = 6


def _int_str_limit() -> int:
    """CPython's int<->str conversion limit (4300 by default, 3.11+). Above it, `int("9" * 5000)` and even
    `repr(10 ** 5000)` raise, so a knob holding such a value could abort a run from inside the parser
    meant to refuse it."""
    import sys
    getter = getattr(sys, "get_int_max_str_digits", None)
    limit = getter() if getter else 0
    # 0 means the interpreter disabled the limit (3.11+), not "zero digits allowed" — read literally it
    # would refuse every numeric setting.
    return limit if limit > 0 else 4300


def _significant(digits: str) -> str:
    """The digits that decide the value — leading zeroes are representation, not magnitude."""
    return digits.lstrip("0")


def _digit_count(raw: int) -> int:
    """How many decimal digits an int has, without converting it to a string."""
    n = abs(raw)
    return n.bit_length() * 30103 // 100000 + 1


def _range_note(value, maximum: int | None) -> str:
    """How a refused number missed the accepted range."""
    if value is not None and value < 0:
        return "below zero"
    if maximum is not None and value is not None and value > maximum:
        return f"above maximum {maximum}"
    if maximum is not None and value is None:
        return f"above maximum {maximum}"      # too long to convert is above any maximum
    return "outside the accepted range"


def flag_int(key: str, *, default: int, maximum: int) -> tuple[int, str, str | None, str | None]:
    """Like `strict_int_with_source`, but reading only run-scoped flag overrides — never `config.yaml`.

    A module constant is not a PERFORMANCE knob: config has no say over it, so the same reader may not
    serve both."""
    if key not in _overrides:
        return default, "default", None, None
    saved = dict(_overrides)
    try:
        # the same strict parse, over the flag layer alone
        globals()["_overrides"] = {key: saved[key]}
        return strict_int_with_source(key, default=default, maximum=maximum)
    finally:
        globals()["_overrides"] = saved


def strict_int_with_source(key: str, *, default: int,
                           maximum: int) -> tuple[int, str, str | None, str | None]:
    """`(value, source, rejected, rejected_source)` — the value, where it came from, what was thrown away
    getting there, and who had written that.

    Attribution comes out of the same parse as the value: a value the parser refused is attributed to the
    default and the offending input is kept, so the report can say what was ignored."""
    written = source_of(key)
    if written == "default":
        return default, "default", None, None
    raw = _overrides[key] if key in _overrides else performance().get(key)
    value = None
    if isinstance(raw, bool):
        value = None                                  # a bool is not an int here, ever
    elif isinstance(raw, int):
        value = raw if 0 <= raw <= maximum else None  # a comparison never converts, however long it is
    elif (isinstance(raw, str) and raw.strip().isdigit()
            and len(_significant(raw.strip())) <= _int_str_limit()):
        # length gate first: `int("9" * 5000)` raises, and this parser may not abort the run with it.
        # Only the significant digits convert — `int("0" * 5000)` raises though the value is zero.
        v = int(_significant(raw.strip()) or "0")
        value = v if 0 <= v <= maximum else None
    if value is None:
        return default, "default", _diagnostic(raw, maximum=maximum), written   # refused, and says so
    return value, written, None, None


def raw(key: str, default=None):
    """The configured value exactly as written, or `default` when unset.

    For a spending control `0` means "no ceiling" and a malformed value must not become a permissive
    default — so this returns the value as the operator wrote it, for the caller's own parser to refuse.
    `concurrency()` cannot serve it (its `max(1, …)` and silent fallback are for worker counts)."""
    v = performance().get(key)
    return default if v in (None, "") else v


def policy_days(key: str, default: float) -> float:
    """A non-negative duration in days from PERFORMANCE, exactly as written: an int or a float, `0` is a
    real value. A string, bool, negative or non-finite value falls back to the default.

    `concurrency()` cannot serve this — it clamps to at least 1, and a freshness policy of zero means
    "never replay"."""
    v = performance().get(key)
    # an int or a float, never a bool (an int subclass), never a string: `float("7")` would coerce, and
    # YAML already gives a number for a number.
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return float(default)
    f = float(v)
    if f != f or f in (float("inf"), float("-inf")) or f < 0:
        return float(default)
    return f


def concurrency(key: str, default: int) -> int:
    """An explicit per-tool concurrency override from PERFORMANCE (e.g. `NUCLEI_CONCURRENCY`,
    `HTTPX_THREADS`), else `default`. The explicit-override floor; the auto/core-scaling layer sits on
    top. A blank/invalid value falls back to `default`."""
    v = performance().get(key)
    if v in (None, ""):
        return default
    try:
        return max(1, int(v))
    except (TypeError, ValueError):
        return default


# ── H2: concurrency scaled by cpu cores × profile ─────────────────────────────────────────────
# workers = cpu cores × per-tool factor × profile multiplier, clamped; local lanes only, never rate.
_OVERRIDE_KEY = {"nuclei": "NUCLEI_CONCURRENCY", "httpx": "HTTPX_THREADS",
                 "ffuf": "FFUF_THREADS", "dalfox": "DALFOX_WORKERS",
                 "katana": "KATANA_CONCURRENCY", "arjun": "ARJUN_THREADS"}
_CORE_FACTOR = {"nuclei": 10, "httpx": 12, "ffuf": 12, "katana": 6, "arjun": 6}   # workers per core
_PROFILE_MULT = {"safe": 0.5, "balanced": 1.0, "auto": 1.0, "aggressive": 1.75}
_CAP = {"nuclei": 100, "httpx": 300, "ffuf": 300, "katana": 50, "arjun": 40}
_FLOOR = 4
# network-I/O-bound tools track round-trips, not cores: give them a core-independent base
# (profile-scaled) and take the max with the core-scaled value, so a small box is not starved.
_IO_BASE = {"httpx": 150, "ffuf": 120, "katana": 25, "arjun": 20}   # katana/arjun are network-bound too


def workers(tool: str, default: int) -> int:
    """Resolve a tool's local concurrency, in priority order:
      1. explicit PERFORMANCE override (e.g. `NUCLEI_CONCURRENCY`).
      2. auto/core-scaled: `cpu_cores × per-tool factor × profile multiplier`, clamped [floor, cap].
      3. the tool's base `default`, for a tool with no scaling factor (dalfox is override-only)."""
    key = _OVERRIDE_KEY.get(tool)
    if key:
        ov = performance().get(key)
        if ov not in (None, ""):
            try:
                return max(1, int(ov))
            except (TypeError, ValueError):
                pass
    factor = _CORE_FACTOR.get(tool)
    if factor is None:
        return default
    cores = os.cpu_count() or 2
    prof = profile()
    mult = _PROFILE_MULT.get(prof, 1.0)
    scaled = round(cores * factor * mult)
    io = _IO_BASE.get(tool)
    if io is not None:                      # I/O-bound: a low core count must not cap network concurrency
        scaled = max(scaled, round(io * mult))
    scaled = min(scaled, _CAP.get(tool, 200))
    # `safe` may drop below the tool's baseline (floored at _FLOOR); the other profiles never go below
    # the tool's `default` — scaling only adds lanes on bigger boxes.
    return int(max(_FLOOR, scaled) if prof == "safe" else max(default, scaled))


def openintel() -> dict:
    """Advanced local openintel-subs paths (`{binary, db}`) — a path pair, not a credential. Back-compat:
    falls back to the legacy `openintel:` block in secrets.yaml. Returns {} unless configured."""
    o = load().get("openintel")
    if isinstance(o, dict) and (o.get("binary") or o.get("db")):
        return o
    from . import secrets                                   # legacy home (pre-config.yaml installs)
    return secrets.openintel()


def reset_cache() -> None:
    global _cache
    _cache = None
