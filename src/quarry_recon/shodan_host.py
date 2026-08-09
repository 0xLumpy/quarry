"""The free `/shodan/host/{ip}` lane: reading a record, owning it, and sweeping observed addresses.

A 404 carrying the measured wording is an answer, not a failure, and a record is Shodan's memory of a
scan it ran rather than a probe result of ours. Measurements and design: docs/design/SHODAN-HOST-DESIGN.md.
"""

from __future__ import annotations

import base64
import binascii as _binascii
import contextlib
import datetime as _dt
import errno
import fcntl
import hashlib
import math as _math
import ipaddress
import json
import os
import re
import time as _time
from dataclasses import dataclass, field
from pathlib import Path

from . import budget, normalize
from .budget import ledger_writable
from .contract import (PROVIDER_PARSE, ProviderBodyError, is_measured_empty,
                       provider_error_class)

#: a CVE id, as the numbering authority defines it. ASCII digits explicitly: `\d` matches `２０２１`.
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)

#: the transports measured in a banner. An unreadable one leaves the transport unknown; the port is
#: real either way.
_TRANSPORTS = frozenset({"tcp", "udp"})

#: the measured banner timestamp. Reconciliation compares these lexically, which is chronological only
#: for this shape.
_TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?$")

#: the collections that hold the evidence. Without them there is no record we recognise.
_EVIDENCE_KEYS = ("ports", "data")
#: ...and the softer collections: their absence is a counted loss, not a rejected envelope. Only
#: `vulns` may be absent for free.
_SOFT_KEYS = ("hostnames", "domains", "tags")

#: the status that means "no data", and the only one. It must agree with the measured wording.
_EMPTY_STATUS = 404

#: bump when the stored artifact's meaning changes; a bump re-fetches, which is free here.
SHODAN_HOST_SCHEMA = 1

#: `/shodan/host/{ip}` outcomes, as this module reports them.
HOST_RECORD = "record"          # a 200 that identifies itself as the IP we asked about
HOST_EMPTY = "empty"            # the provider's measured "no data" answer
HOST_INVALID = "invalid"        # a body we cannot trust to be about this IP


@dataclass(frozen=True)
class PortObs:
    """One banner, reduced to what Quarry can act on. Passive: Shodan saw this at `seen`, we did not."""

    port: int
    transport: str = ""          # "tcp" / "udp" — measured. "" when only the bare `ports` list knew of it
    module: str = ""             # `_shodan.module`, e.g. "dns-tcp" — the closest thing to a service name
    tls: bool = False            # an `ssl` object was present on this banner
    seen: str = ""               # the banner's own timestamp, never our clock

    @property
    def key(self) -> tuple:
        return (self.port, self.transport)


@dataclass
class HostRecord:
    """One IP's passive record. Valid parts are kept even when others are malformed; `complete` says
    whether any were dropped."""

    ip: str
    ports: list = field(default_factory=list)         # PortObs, in the provider's own order
    hostnames: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    vulns: list = field(default_factory=list)         # CVE ids, from either measured shape
    tags: list = field(default_factory=list)
    org: str = ""
    isp: str = ""
    asn: str = ""
    last_update: str = ""
    complete: bool = True                             # False when any part was malformed and dropped
    unusable: int = 0                                 # how many parts were dropped, for reporting

    def drop(self) -> None:
        self.complete = False
        self.unusable += 1


def canonical_ip(value) -> str:
    """Canonical form is a record's identity. "" for a value that is not an address."""
    if not isinstance(value, str):
        return ""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return ""
    # an IPv4-mapped v6 address names the same host as the v4 form Shodan answers on
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped or addr)


def ip_group(ip: str) -> str:
    """The fairness group for an address: its /24 (v4) or /48 (v6)."""
    # grouped on the canonical form: ownership and fairness have to see the same host family
    canon = canonical_ip(ip)
    if not canon:
        return ""
    addr = ipaddress.ip_address(canon)
    net = ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False)
    return str(net)


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _scalar(doc, key: str, rec: HostRecord) -> str:
    """A string field. `null` is this provider's "unknown"; present-but-not-a-string is a counted loss."""
    if key not in doc:
        return ""
    value = doc[key]
    if value is None:
        return ""                              # the provider's own "unknown" — measured, not a loss
    text = _text(value)
    if not text:
        rec.drop()
        return ""
    return text


def _names(raw, rec: HostRecord) -> list:
    if raw is None:
        return []
    if not isinstance(raw, list):
        rec.drop()
        return []
    out = []
    for h in raw:
        raw_name = _text(h)
        # `canon_host_strict` is Quarry's one name contract; a lane-local lower+rstrip accepts
        # `../admin.example.com`
        name = normalize.canon_host_strict(raw_name) if raw_name else None
        if not name or "." not in name:
            # a bare label names no domain, so it can be neither scoped nor attributed
            rec.drop()
            continue
        if name not in out:
            out.append(name)
    return out


def _vulns(raw, rec: HostRecord) -> list:
    if raw is None:
        return []
    if isinstance(raw, dict):
        ids = list(raw.keys())
    elif isinstance(raw, list):
        ids = raw
    else:
        rec.drop()
        return []
    out = []
    for cve in ids:
        name = _text(cve).upper()
        if not _CVE_RE.match(name):
            rec.drop()                         # not an identifier we can look anything up by
            continue
        if name not in out:
            out.append(name)
    return out


def _banner_text(src, key: str, rec: HostRecord) -> str:
    if not isinstance(src, dict) or key not in src or src[key] is None:
        return ""
    text = _text(src[key])
    if not text:
        rec.drop()
        return ""
    return text


def _banner_transport(b, rec: HostRecord) -> str:
    """The banner's transport, checked against the measured vocabulary — it is half of `PortObs.key`, so
    anything accepted here becomes a service identity."""
    raw = _banner_text(b, "transport", rec)
    if not raw:
        return ""
    transport = raw.lower()
    if transport not in _TRANSPORTS:
        rec.drop()
        return ""                              # the port survives; its transport is unknown
    return transport


def _banner_time(b, rec: HostRecord) -> str:
    """The banner's own sighting time, only when it has the measured shape and names a real instant.
    Reconciliation orders by this value."""
    raw = _banner_text(b, "timestamp", rec)
    if not raw:
        return ""
    if not _TS_RE.match(raw):
        rec.drop()
        return ""
    # the shape alone accepts `2026-99-99T99:99:99`, which would win every comparison. The calendar part
    # is checked separately because `fromisoformat` disagrees about fraction lengths across interpreters.
    try:
        _dt.datetime.strptime(raw.split(".", 1)[0], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        rec.drop()
        return ""
    return raw


def _banner_tls(b, rec: HostRecord) -> bool:
    if "ssl" not in b or b["ssl"] is None:
        return False
    if not isinstance(b["ssl"], dict):
        rec.drop()
        return False
    return True


def _merge_obs(prev: PortObs, new: PortObs, rec: HostRecord) -> PortObs:
    module, seen_at = prev.module, prev.seen
    if new.module and new.module != prev.module:
        if prev.module:
            rec.drop()                         # two modules for one service: we model a single name
        else:
            module = new.module
    if new.seen and new.seen > seen_at:
        seen_at = new.seen                     # ISO-8601 from one provider: lexical order is chronological
    return PortObs(port=prev.port, transport=prev.transport, module=module,
                   tls=prev.tls or new.tls, seen=seen_at)


def _ports(doc, rec: HostRecord) -> list:
    seen: dict = {}
    banners = doc.get("data")
    if banners is not None and not isinstance(banners, list):
        rec.drop()
        banners = None
    for b in banners or ():
        if not isinstance(b, dict):
            rec.drop()
            continue
        port = b.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            rec.drop()
            continue
        meta = b.get("_shodan")
        if meta is None:
            meta = {}
        elif not isinstance(meta, dict):
            rec.drop()                         # banner metadata we cannot read is a lost part, not a blank
            meta = {}
        # every field counts its own loss: a `transport` of `1` is a part we could not read, not a blank
        obs = PortObs(port=port, transport=_banner_transport(b, rec),
                      module=_banner_text(meta, "module", rec),
                      tls=_banner_tls(b, rec),
                      seen=_banner_time(b, rec))
        # keyed by (port, transport): 53/tcp and 53/udp are two services and the record carries both
        prev = seen.get(obs.key)
        seen[obs.key] = obs if prev is None else _merge_obs(prev, obs, rec)
    listed = doc.get("ports")
    if listed is not None and not isinstance(listed, list):
        rec.drop()
        listed = None
    known = {p for p, _t in seen}
    for port in listed or ():
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            rec.drop()
            continue
        if port in known:
            continue                           # a banner already said more about it than the bare list can
        seen.setdefault((port, ""), PortObs(port=port))
    return list(seen.values())


def _exact_status(value) -> "int | None":
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def read_host(raw, *, ip: str, http_code: int = 200):
    """`(kind, record_or_reason)` for one `/shodan/host/{ip}` response — `HOST_RECORD`, `HOST_EMPTY` or
    `HOST_INVALID`. Never raises. A 200 whose `ip_str` is not the address we asked about is not evidence
    about that address."""
    want = canonical_ip(ip)
    if not want:
        return HOST_INVALID, f"not an IP address: {ip!r}"
    code = _exact_status(http_code)
    if code is None:
        return HOST_INVALID, f"http status is not an integer ({http_code!r})"
    http_code = code
    # strict: "replace" would turn malformed UTF-8 into plausible JSON
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return HOST_INVALID, "response was not valid UTF-8"
    elif isinstance(raw, str):
        text = raw
    else:
        return HOST_INVALID, f"response was not text ({type(raw).__name__})"
    try:
        doc = json.loads(text)
    except ValueError:
        return HOST_INVALID, "response was not JSON"
    if not isinstance(doc, dict):
        return HOST_INVALID, f"response was not an object ({type(doc).__name__})"

    if doc.get("error") is not None:
        if not isinstance(doc["error"], str):
            return HOST_INVALID, f"unreadable error field ({type(doc['error']).__name__})"
        if not _text(doc["error"]):
            return HOST_INVALID, "empty error field"
    said = _text(doc.get("error"))
    if said:
        # a 500 carrying the same sentence is an outage, not an absence we established
        if http_code == _EMPTY_STATUS and is_measured_empty("shodan", said):
            return HOST_EMPTY, said
        return HOST_INVALID, f"HTTP {http_code}: {said}"
    if http_code != 200:
        return HOST_INVALID, f"HTTP {http_code} with no error message"

    got = canonical_ip(doc.get("ip_str"))
    if not got:
        return HOST_INVALID, "record has no usable ip_str"
    if got != want:
        return HOST_INVALID, f"record is about {got}, not {want}"

    # without evidence keys of the measured type, a 200 would assert this host has no open ports
    bad = [f"{k} is {'absent' if k not in doc else 'null' if doc[k] is None else type(doc[k]).__name__}"
           for k in _EVIDENCE_KEYS if not isinstance(doc.get(k), list)]
    if bad:
        return HOST_INVALID, f"success envelope: {', '.join(bad)}"

    rec = HostRecord(ip=want)
    for key in _SOFT_KEYS:
        if key not in doc or doc[key] is None:
            rec.drop()                         # usable evidence, one collection short of the measured shape
    if "vulns" in doc and doc["vulns"] is None:
        rec.drop()                             # absence is the measured "none"; a null is not
    rec.ports = _ports(doc, rec)
    rec.hostnames = _names(doc.get("hostnames"), rec)
    rec.domains = _names(doc.get("domains"), rec)
    rec.vulns = _vulns(doc.get("vulns"), rec)
    tags = doc.get("tags")
    if tags is not None and not isinstance(tags, list):
        rec.drop()
    else:
        for x in tags or ():
            tag = _text(x)
            if not tag:
                rec.drop()                     # a tag member we cannot read is a lost part
            elif tag not in rec.tags:
                rec.tags.append(tag)
    # `_scalar`, not `_text`: an `asn` of `13335` is a part we could not read, not a blank
    rec.org = _scalar(doc, "org", rec)
    rec.isp = _scalar(doc, "isp", rec)
    rec.asn = _scalar(doc, "asn", rec)
    rec.last_update = _scalar(doc, "last_update", rec)
    return HOST_RECORD, rec


def empty_or_raise(err, *, ip: str):
    """The measured no-data wording out of a failed request's body, or None when the failure is a real one.
    The transport layer raises on the 404 that carries it."""
    body = getattr(err, "body_bytes", None)
    if not body:
        return None
    kind, detail = read_host(body, ip=ip, http_code=getattr(err, "code", 0) or 0)
    return detail if kind == HOST_EMPTY else None


def host_body_error(reason: str) -> ProviderBodyError:
    return ProviderBodyError(PROVIDER_PARSE, reason, "shodan")


# ── the eligible set ──────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IpTarget:
    """One address to look up. `hosts` is why we believe it belongs to the target, and it travels with every
    entity the lane writes."""

    ip: str
    hosts: tuple = ()
    sources: tuple = ()

    @property
    def group(self) -> str:
        return ip_group(self.ip)


def _add_target(acc: dict, ip: str, host: str, source: str) -> None:
    canon = canonical_ip(ip)
    if not canon:
        return
    cur = acc.get(canon)
    hosts = tuple(cur.hosts) if cur else ()
    sources = tuple(cur.sources) if cur else ()
    if host and host not in hosts:
        hosts = hosts + (host,)
    if source and source not in sources:
        sources = sources + (source,)
    acc[canon] = IpTarget(ip=canon, hosts=hosts, sources=sources)


def _valid_port(value) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 1 <= value <= 65535


def _ip_from_id(value) -> str:
    """The address out of an `"ip:port"` composite id — the fallback when a row carries no `ip` field."""
    if not isinstance(value, str) or ":" not in value:
        return ""
    ip, _sep, port = value.rpartition(":")
    try:
        number = int(port)
    except ValueError:
        return ""
    if not _valid_port(number) or port != str(number):     # "080" and " 80" are not this id's shape
        return ""
    return canonical_ip(ip)


def eligible_ips(ctx) -> list:
    """Every address Quarry has observed for this target, from `resolved` and from `port` / `web_port`,
    deduplicated by canonical form. A CIDR filters and never generates; an OOS host's address is not
    eligible."""
    scope = ctx.scope
    acc: dict = {}

    def usable_host(h) -> bool:
        return bool(h) and scope.in_scope(h) and not scope.is_oos(h)

    for rec in ctx.run.read("resolved"):
        host = (rec.get("host") or "").lower().rstrip(".")
        if not usable_host(host):
            continue
        for field in ("a", "aaaa"):
            for ip in (rec.get(field) or ()):
                _add_target(acc, ip, host, "resolved")
    for entity in ("web_port", "port"):
        for rec in ctx.run.read(entity):
            # a port row earns its address only by naming a port; either shape must prove one
            ip = (rec.get("ip") or "") if _valid_port(rec.get("port")) else ""
            ip = ip or _ip_from_id(rec.get("id"))
            host = (rec.get("host") or "").lower().rstrip(".")
            if host and not usable_host(host):
                continue                       # attributed to a host we may not expand against
            canon = canonical_ip(ip)
            if not canon:
                continue
            if not host and not scope.ip_in_scope(canon):
                # unattributed: only a declared range makes it ours
                continue
            _add_target(acc, canon, host, entity)
    return list(acc.values())


def _dedupe(targets) -> list:
    acc: dict = {}
    for t in targets:
        canon = canonical_ip(t.ip)
        if not canon:
            continue
        cur = acc.get(canon)
        if cur is None:
            acc[canon] = IpTarget(ip=canon, hosts=tuple(t.hosts), sources=tuple(t.sources))
            continue
        acc[canon] = IpTarget(ip=canon,
                              hosts=tuple(dict.fromkeys(cur.hosts + tuple(t.hosts))),
                              sources=tuple(dict.fromkeys(cur.sources + tuple(t.sources))))
    return list(acc.values())


class SweepProgress:
    """Project-level scheduling progress: when each address was last asked about. It only orders, and losing
    it costs ordering quality, never coverage."""

    #: bump when the record's meaning changes; a bump simply starts a fresh rotation.
    SCHEMA = 1

    def __init__(self, path, *, held: bool = False):
        self.path = Path(path) if path else None
        self.asked: dict = {}
        self.loaded = False
        # `held`: a `sweep_session` owns the lock. `flock` is per open file description, so a second
        # `open()` in this process would block on ourselves.
        self.held = held
        self._read()

    @staticmethod
    def _usable_time(when) -> "float | None":
        if isinstance(when, bool) or not isinstance(when, (int, float)):
            return None
        value = float(when)
        if not _math.isfinite(value) or value < 0.0:
            return None
        return value

    @classmethod
    def _parse(cls, text: str) -> dict:
        try:
            doc = json.loads(text)
        except ValueError:
            return {}
        if not isinstance(doc, dict):
            return {}
        schema = doc.get("schema")
        # exact int, not `== 1`: `True == 1`, and a bool schema is not a schema (the `read_stored` rule)
        if isinstance(schema, bool) or not isinstance(schema, int) or schema != cls.SCHEMA:
            return {}
        asked = doc.get("asked")
        if not isinstance(asked, dict):
            return {}
        out: dict = {}
        for ip, when in asked.items():
            canon = canonical_ip(ip)
            value = cls._usable_time(when)
            if canon and value is not None:
                out[canon] = value
        return out

    def _read(self) -> None:
        if self.path is None:
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return
        self.asked = self._parse(text)
        self.loaded = bool(self.asked)

    def note(self, ip: str, when: float) -> None:
        canon = canonical_ip(ip)
        value = self._usable_time(when)
        if canon and value is not None:
            self.asked[canon] = value

    def rank(self, ip: str):
        """`(tier, when)` — tier 0 = never asked, tier 1 = asked before, oldest first."""
        when = self.asked.get(ip)
        return (1, when) if when is not None else (0, 0.0)

    def save(self) -> bool:
        """Merge this run's asks into what is on disk, under a lock, and replace atomically. Max wins."""
        if self.path is None:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        # no lock, no write: best effort may lose rotation, it may not claim one it did not serialise
        fh = None
        if not self.held:
            try:
                fh = _open_lock(self.path, blocking=True)
            except SweepBusy:
                return False
            if fh is None:
                return False
        try:
            try:
                on_disk = self._parse(self.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                on_disk = {}
            merged = dict(on_disk)
            for ip, when in self.asked.items():
                merged[ip] = max(when, merged.get(ip, 0.0))
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
            try:
                tmp.write_text(json.dumps({"schema": self.SCHEMA, "asked": merged}), encoding="utf-8")
                os.replace(tmp, self.path)
            finally:
                try:
                    tmp.unlink(missing_ok=True)          # a failed write must not leave a temp behind
                except OSError:
                    pass
            self.asked = merged
            return True
        except OSError:
            return False
        finally:
            _release(fh)


#: how long a waiting acquire tries, and how often it retries. Giving up answers False rather than
#: writing unlocked.
_PROGRESS_LOCK_WAIT_S = 5.0
_PROGRESS_LOCK_POLL_S = 0.05


class SweepBusy(RuntimeError):
    """Another run on this project holds the sweep. A gap in this run's coverage, not a skip — the holder's
    evidence never reaches this run."""


def _open_lock(path, *, blocking: bool):
    """The lock file handle, or None when this filesystem cannot lock at all. Acquisition only."""
    lock = Path(path).with_name(Path(path).name + ".lock")
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        fh = lock.open("a+")
    except OSError:
        return None                                # no lock file at all — the caller decides what that costs
    # always non-blocking at the syscall: waiting is a bounded retry, and a stuck holder must not
    # freeze the run
    deadline = _time.monotonic() + (_PROGRESS_LOCK_WAIT_S if blocking else 0.0)
    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except OSError as e:
            if e.errno not in (errno.EACCES, errno.EAGAIN):
                fh.close()
                return None                        # no lock support is different from a lock being held
            if not blocking:
                fh.close()
                raise SweepBusy(f"another run holds {lock.name}") from e
            if _time.monotonic() >= deadline:
                fh.close()
                return None                        # still held: the caller reports a save it could not make
            _time.sleep(_PROGRESS_LOCK_POLL_S)


def _release(fh) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    fh.close()


@contextlib.contextmanager
def _progress_lock(path, *, blocking: bool = True):
    fh = _open_lock(path, blocking=blocking)
    try:
        yield
    finally:
        _release(fh)


@contextlib.contextmanager
def sweep_session(path):
    """`with sweep_session(p) as progress:` — the lock held across load, schedule, note and save. Contention
    raises `SweepBusy` rather than queueing behind a sweep that may run for hours."""
    fh = _open_lock(path, blocking=False)
    try:
        # the session owns the lock for the whole lifecycle, so `save()` must not take it again
        yield SweepProgress(path, held=fh is not None)
    finally:
        _release(fh)


def progress_path(project_dir):
    return (Path(project_dir) / "recon" / "state" / "shodan-host"
            / f"v{SweepProgress.SCHEMA}" / "sweep.json")


def schedule(targets, progress=None) -> list:
    """Host-fair order across netblocks, ranked by progress when we have it. Membership is never bounded: the
    full list comes back."""
    # uniform rank without progress: no address is worth more than another
    usable = [t for t in targets if t.group]
    if progress is None:
        return budget.order_ranked_fair(usable, rank=lambda t: 0, group=lambda t: t.group)
    # age is the rank, one tier per distinct last-asked time: a never/asked split collapses once
    # everything has been asked
    ages = sorted({progress.rank(t.ip) for t in usable})
    tier = {age: i for i, age in enumerate(ages)}
    return budget.order_ranked_fair(usable, rank=lambda t: tier[progress.rank(t.ip)],
                                    group=lambda t: t.group)


# ── the free work loop ────────────────────────────────────────────────────────────────────────────────

def store_envelope(ip: str, http_code: int, body: bytes) -> bytes:
    """What we store for one answer: the provider's body verbatim, plus the status it arrived with. Bytes
    that are not text are stored base64 rather than lost."""
    # the bytes are the evidence: text when they are text, base64 otherwise, never lost to a decode
    code = _exact_status(http_code)
    if code is None:
        # a status we cannot store faithfully is not stored at all: replay reads it back and compares it
        raise ValueError(f"http status is not an integer ({http_code!r})")
    env = {"schema": SHODAN_HOST_SCHEMA, "ip": ip, "http_code": code}
    try:
        env["body"] = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        env["body_b64"] = base64.b64encode(bytes(body)).decode("ascii")
    return json.dumps(env).encode()


def read_stored(raw, *, ip: str):
    """`(kind, payload)` for a stored answer, validated as strictly as a provider body."""
    if not isinstance(raw, (bytes, bytearray, str)):
        return HOST_INVALID, f"stored answer was not text ({type(raw).__name__})"
    try:
        text = bytes(raw).decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        env = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        return HOST_INVALID, "stored answer was not readable JSON"
    if not isinstance(env, dict):
        return HOST_INVALID, "stored answer was not an object"
    schema = env.get("schema")
    # exact int, not `== SCHEMA`: `True == 1`, and a bool schema is not a schema
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SHODAN_HOST_SCHEMA:
        return HOST_INVALID, f"stored answer is schema {schema!r}"
    if canonical_ip(env.get("ip")) != canonical_ip(ip):
        return HOST_INVALID, f"stored answer is about {env.get('ip')!r}, not {ip}"
    code = env.get("http_code")
    if isinstance(code, bool) or not isinstance(code, int):
        return HOST_INVALID, "stored answer has no usable status or body"
    # exactly one carrier key, then its type: two bodies would replay whichever was checked first
    carriers = [k for k in ("body", "body_b64") if k in env]
    if len(carriers) != 1:
        return HOST_INVALID, ("stored answer carries both a text and a base64 body" if carriers else
                              "stored answer has no usable status or body")
    which = carriers[0]
    value = env[which]
    if not isinstance(value, str):
        return HOST_INVALID, f"stored answer's {which} is not a string"
    if which == "body":
        payload = value
    else:
        try:
            payload = base64.b64decode(value, validate=True)
        except (ValueError, _binascii.Error):
            return HOST_INVALID, "stored answer has an unreadable base64 body"
    return read_host(payload, ip=ip, http_code=code)


def error_key(ip: str) -> str:
    return hashlib.sha256(f"{SHODAN_HOST_SCHEMA}|{ip}|error".encode()).hexdigest()


def item_key(ip: str) -> str:
    raw = f"{SHODAN_HOST_SCHEMA}|{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class HostOutcome:
    eligible: int = 0
    attempted: int = 0
    replayed: int = 0
    answered: int = 0                    # asked and answered; `records`/`empty` include replay
    records: int = 0
    empty: int = 0
    ports_seen: int = 0
    hostnames_seen: int = 0
    vulns_seen: int = 0
    ports: int = 0
    hostnames: int = 0
    vulns: int = 0
    incomplete: int = 0
    unusable_parts: int = 0
    evidence_invalid: int = 0
    publish_failed: int = 0
    records_journaled: bool = True
    unconsumed: int = 0
    fail_classes: dict = field(default_factory=dict)
    fail_reason: str = ""
    fail_reasons: dict = field(default_factory=dict)    # first reason per class, so both name one event
    not_attempted: list = field(default_factory=list)   # exact addresses, never a count alone
    machinery: list = field(default_factory=list)
    stop_cause: str = ""
    port_rows: int = 0                   # rows, not observations: one `ip:53` row can hold both TCP and UDP
    owned: int = 0                        # reached the store and the ledger
    error_bodies: int = 0
    persisted: bool = True
    progress_saved: bool = True          # rotation, not evidence
    requests: int = 0


def _record_machinery(o: HostOutcome, e: BaseException) -> None:
    o.machinery.append(f"{type(e).__name__}: {e}")
    o.stop_cause = o.stop_cause or f"machinery:{type(e).__name__}"
    o.fail_reason = o.fail_reason or f"host state machinery failed ({type(e).__name__}: {e})"


def _fold(o: HostOutcome, rec: HostRecord) -> None:
    o.records += 1
    o.ports_seen += len(rec.ports)
    o.hostnames_seen += len(rec.hostnames)
    o.vulns_seen += len(rec.vulns)
    if not rec.complete:
        o.incomplete += 1
        o.unusable_parts += rec.unusable


#: what a sink reports having stored. A row is a different unit from the observations inside it.
WROTE_PORT, WROTE_HOSTNAME, WROTE_VULN = "port", "hostname", "vuln"
WROTE_PORT_ROW = "port_row"


def _consume(o: HostOutcome, rec: HostRecord, target, art, ingest) -> None:
    """Hand one record to the sink. An ingest that raises leaves the record owned and counts the shortfall."""
    def wrote(kind: str, n: int = 1) -> None:
        if kind == WROTE_PORT:
            o.ports += n
        elif kind == WROTE_PORT_ROW:
            o.port_rows += n
        elif kind == WROTE_HOSTNAME:
            o.hostnames += n
        elif kind == WROTE_VULN:
            o.vulns += n

    try:
        ingest(target, rec, art, wrote)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        o.unconsumed += 1
        raise


def _count_fail(o: HostOutcome, cls: str, why: str) -> None:
    o.fail_classes[cls] = o.fail_classes.get(cls, 0) + 1
    o.fail_reasons.setdefault(cls, f"{cls}: {why}")
    o.fail_reason = o.fail_reason or f"{cls}: {why}"


def _replay_owned(targets, o: HostOutcome, done: set, *, ledger, ingest) -> None:
    for t in targets:
        art = ledger.artifact(item_key(t.ip))
        if art is None:
            # not recorded, or disowned at load: either way we do not hold it, so ask again
            continue
        try:
            raw = art.read_bytes()
        except OSError:
            o.evidence_invalid += 1
            continue
        kind, payload = read_stored(raw, ip=t.ip)
        if kind not in (HOST_RECORD, HOST_EMPTY):
            o.evidence_invalid += 1            # owned but no longer usable: ask again rather than trust it
            continue
        done.add(t.ip)
        o.replayed += 1
        if kind == HOST_EMPTY:
            o.empty += 1                       # an owned "no data" answer: still coverage, still free
            continue
        _fold(o, payload)
        _consume(o, payload, t, art, ingest)


def _keep_error(o: HostOutcome, ledger, attempt_dir, ip: str, http_code: int, body: bytes) -> str:
    """Retain a failure's body as evidence, never as a completion: `add_evidence` claims nothing about
    ownership, so the address stays retryable."""
    if not body:
        return ""
    art = attempt_dir / f"{error_key(ip)}.json"
    raw = store_envelope(ip, http_code, body)
    dig = hashlib.sha256(raw).hexdigest()
    # our evidence loss outranks their boundary, and it stops us asking for more we cannot keep
    if not budget.publish_bytes(art, raw, digest=dig):
        o.publish_failed += 1
        return "publish_failed"
    if not ledger.add_evidence(error_key(ip), art, digest=dig):
        o.records_journaled = False
        return "ledger_unwritable"
    o.error_bodies += 1
    return ""


def _keep(o: HostOutcome, ledger, attempt_dir, ip: str, http_code: int, body: bytes) -> str:
    art = attempt_dir / f"{item_key(ip)}.json"
    raw = store_envelope(ip, http_code, body)
    dig = hashlib.sha256(raw).hexdigest()
    if not budget.publish_bytes(art, raw, digest=dig):
        o.publish_failed += 1
        return "publish_failed"
    if not ledger.record(item_key(ip), art, digest=dig):
        o.records_journaled = False
        return "ledger_unwritable"
    return ""


def _ask(targets, o: HostOutcome, done: set, asked: set, *, fetch, ingest, ledger, attempt_dir,
          bound=None, should_stop=None, progress=None) -> None:
    """One free request per address not already owned, in the order given.

    `fetch(ip) -> (raw_bytes, http_code, error)` never raises; `error` carries `error_class` and, for the
    measured 404, a `body_bytes`. A deadline bounds throughput, never membership: what it does not reach
    stays in `not_attempted`, by exact address."""
    should_stop = should_stop or (lambda cls: False)
    probed: list = []

    def sinks_ready() -> str:
        if not probed:
            if not budget.store_writable(attempt_dir):
                probed.append("publish_failed")
            elif not ledger_writable(ledger) or not ledger.checkpoint():
                probed.append("ledger_unwritable")
            else:
                probed.append("")
        return probed[0]

    for t in targets:
        if t.ip in done:
            continue
        if o.stop_cause:
            continue                           # the remainder is derived once, from what we asked
        if bound is not None and bound.exhausted():
            o.stop_cause = o.stop_cause or "budget_time"
            continue
        unusable = sinks_ready()
        if unusable:
            o.stop_cause = o.stop_cause or unusable
            continue
        asked.add(t.ip)
        if progress is not None:
            progress.note(t.ip, _time.time())
        o.attempted += 1
        o.requests += 1
        raw, code, err = fetch(t.ip)
        if err is not None:
            said = empty_or_raise(err, ip=t.ip)
            if said is not None:
                o.empty += 1
                o.answered += 1
                why = _keep(o, ledger, attempt_dir, t.ip, getattr(err, "code", 0) or 0,
                            getattr(err, "body_bytes", b"") or b"")
                if why:
                    o.stop_cause = o.stop_cause or why
                    continue                   # answered, not owned: the next run asks again
                o.owned += 1
                done.add(t.ip)
                continue
            cls = provider_error_class(err)
            _count_fail(o, cls, str(err))
            # retention first: our failure to keep the explanation outranks their boundary
            lost = _keep_error(o, ledger, attempt_dir, t.ip, code,
                               getattr(err, "body_bytes", b"") or b"")
            if lost:
                o.stop_cause = o.stop_cause or lost
                continue
            if should_stop(cls):
                o.stop_cause = o.stop_cause or f"provider_stop:{cls}"
            continue
        kind, payload = read_host(raw, ip=t.ip, http_code=code)
        if kind == HOST_EMPTY:
            # an empty answer arrives two ways — here and as an error — and both are owned
            o.empty += 1
            o.answered += 1
            why = _keep(o, ledger, attempt_dir, t.ip, code, raw)
            if why:
                o.stop_cause = o.stop_cause or why
                continue                       # answered, not owned: the next run asks again
            o.owned += 1
            done.add(t.ip)
            continue
        if kind != HOST_RECORD:
            _count_fail(o, PROVIDER_PARSE, str(payload))
            lost = _keep_error(o, ledger, attempt_dir, t.ip, code, raw)
            if lost:
                o.stop_cause = o.stop_cause or lost
            continue
        o.answered += 1
        _fold(o, payload)
        why = _keep(o, ledger, attempt_dir, t.ip, code, raw)
        if why:
            # a store we cannot write to is global: stop asking rather than collect evidence we cannot keep
            o.stop_cause = o.stop_cause or why
            continue
        done.add(t.ip)
        o.owned += 1
        _consume(o, payload, t, attempt_dir / f"{item_key(t.ip)}.json", ingest)
        if not ledger_writable(ledger):
            o.stop_cause = o.stop_cause or "ledger_unwritable"


def _remainder(targets, o: HostOutcome, done: set, asked: set) -> None:
    """Addresses this lifecycle never reached, by exact identity. A snapshot, not an accumulator: this is
    reachable twice."""
    o.not_attempted = [t.ip for t in targets if t.ip not in done and t.ip not in asked]


def run_hosts(targets, *, fetch, ingest, ledger, attempt_dir, bound=None,
              should_stop=None, progress=None) -> HostOutcome:
    """Look up every eligible address, replaying anything already owned. Free: no balance, no reserve.

    `bound` is a `budget.Budget` (None or unbounded by default) and is also what the caller reports
    selection coverage from. `ingest(target, record, artifact, wrote)` calls `wrote(kind)` per entity
    stored. Machinery failures are contained here and reported in the outcome; `KeyboardInterrupt` and
    `SystemExit` still cancel the run."""
    # ordering is part of the loop, not a caller's option; deduplicated first
    targets = schedule(_dedupe(targets), progress)
    o = HostOutcome(eligible=len(targets))
    done: set = set()
    asked: set = set()
    # no unbounded special-case: `Budget.exhausted()` already answers False for `seconds == 0`
    try:
        try:
            _replay_owned(targets, o, done, ledger=ledger, ingest=ingest)
            _ask(targets, o, done, asked, fetch=fetch, ingest=ingest, ledger=ledger,
                 attempt_dir=attempt_dir, bound=bound, should_stop=should_stop, progress=progress)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _record_machinery(o, e)
    finally:
        try:
            _remainder(targets, o, done, asked)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _record_machinery(o, e)
        if progress is not None:
            # saved on every path, machinery failure included, because the requests were still spent
            try:
                o.progress_saved = bool(progress.save())
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                _record_machinery(o, e)
        try:
            saved = bool(ledger.save())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            saved = False
            _record_machinery(o, e)
        if saved:
            o.persisted = True                 # the snapshot is the durable answer; nothing else to ask
        else:
            try:
                durable = bool(getattr(ledger, "durable", False))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                durable = False
                _record_machinery(o, e)
            o.persisted = durable and o.records_journaled
    return o
