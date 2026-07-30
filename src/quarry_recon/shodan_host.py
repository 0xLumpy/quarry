"""B1.7 — the `/shodan/host/{ip}` RECORD: its measured envelope, and what Quarry is allowed to conclude.

MEASURED 2026-07-30, against a real account at a **zero** query-credit balance (delta 0 either side, so
the endpoint is free where `/shodan/host/search` is not):

    a known IP      HTTP 200, 19 top-level keys —
                    {"ip_str": "1.1.1.1", "ip": 16843009,             <- `ip` is an INT, not the address
                     "ports": [161, 2082, 80, 53, 443, ...],          <- UNSORTED
                     "hostnames": [...], "domains": [...], "tags": [],
                     "org": "...", "isp": "...", "asn": "AS13335",    <- a STRING, with the AS prefix
                     "os": null, "last_update": "2026-07-30T04:14:37.743242",
                     "data": [ ...12 banner records... ]}
    an unseen IP    HTTP 404, {"error": "No information available for that IP."}   <- EMPTY, not a failure
    a banner        {"port": 53, "transport": "tcp", "hostnames": [...], "domains": [...],
                     "_shodan": {"module": "dns-tcp", "crawler": ..., "id": ..., "ptr": ...},
                     "ssl": {...}   <- present on SOME banners only (3 of 12 here)}
    `vulns`         ABSENT ENTIRELY when the host has none. Not an empty list — `has("vulns")` is false.

Two rules follow from the measurement and are the whole reason this module exists:

  · "NOT IN SHODAN" IS AN ANSWER. A 404 carrying the measured error string is EMPTY coverage; the lane
    asked and got a definitive reply. Any other 404 body is a 404 we do not understand and stays a
    failure (`contract.is_measured_empty`).
  · PASSIVE EVIDENCE IS NOT A PROBE RESULT. Everything here is Shodan's memory of a scan IT ran, at a
    time IT chose. A port in this record is not proven open now, and a hostname in it is not proven to
    resolve — the entity choices in the lane follow from that, not from convenience.

`vulns` is deliberately half-unmeasured: the measured host has none, so its TYPE is unknown. A list of
CVE ids and a `{cve: detail}` map are both accepted (Shodan has used both), and anything else is counted
unusable rather than coerced into a shape we have never seen.
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

#: a CVE id, as the numbering authority defines it. review-B1.7#2: `not-a-cve` was accepted, and once a
#: record is ledger-owned an unvalidated member is a permanent clean completion.
#: review-B1.7r2#4: `\d` matches `２０２１`, so `CVE-２０２１-１２３４` passed as a clean identifier — an id
#: nothing can be looked up by. ASCII digits, explicitly.
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)

#: the transports MEASURED in a banner. review-B1.7r4#1: this went through generic text parsing while
#: being half of the observation IDENTITY, so `TCP` and `tcp` were two services and `banana` was a clean
#: one. An unreadable transport does not discard the port — the port is real — it makes the observation's
#: transport UNKNOWN and counts the loss.
_TRANSPORTS = frozenset({"tcp", "udp"})

#: the MEASURED banner timestamp: "2026-07-30T04:14:37.743242". review-B1.7r3#3: reconciliation compared
#: timestamps LEXICALLY without checking the shape, so a duplicate carrying "tomorrow" sorted above every
#: real ISO value and became the sighting we report. Lexical order is chronological only for this shape.
_TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?$")

#: collections the MEASURED success envelope always carries. Absence of the two that hold the evidence is
#: not a record we recognise at all (review-B1.7r2#1): `{"ip_str": "1.1.1.1"}` used to read as a clean
#: complete record with no ports and no banners — a confident empty answer about a host we never saw.
_EVIDENCE_KEYS = ("ports", "data")
#: ...and the softer collections. A record without them is still usable evidence about its ports, so their
#: absence is a COUNTED loss rather than a rejected envelope. Graded deliberately: `vulns` is the only key
#: MEASURED as absent-when-empty, so it is the only one that may be missing for free.
_SOFT_KEYS = ("hostnames", "domains", "tags")

#: the status that means "no data" — and the ONLY one. review-B1.7#1: the wording was checked before the
#: status, so the measured body laundered a 200, a 401, a 429 and a 500 into EMPTY. Two facts have to
#: agree: the provider said it has nothing, AND it said so the way we measured it saying so.
_EMPTY_STATUS = 404

#: bump when the stored record ARTIFACT's meaning changes. Part of a record's identity, so a bump
#: deliberately re-fetches — which is free for this endpoint.
SHODAN_HOST_SCHEMA = 1

#: `/shodan/host/{ip}` outcomes, as this module reports them.
HOST_RECORD = "record"          # a 200 that identifies itself as the IP we asked about
HOST_EMPTY = "empty"            # the provider's measured "no data" answer
HOST_INVALID = "invalid"        # a body we cannot trust to be about this IP


@dataclass(frozen=True)
class PortObs:
    """One banner, reduced to what Quarry can act on. PASSIVE: Shodan saw this at `seen`, we did not.

    review-B1.7#3: the OBSERVATION identity is `(port, transport)`. 53/tcp and 53/udp are different
    services on one host — the measured record carries both as separate banners — and collapsing them
    loses one while reporting `complete`.

    The STORE identity stays `ip:port`, matching the existing `port` entity that nmap and naabu write, and
    the transport travels in a LIST-valued field alongside them (agreed for B1.7: passive provenance must
    coexist with a later active observation instead of fighting it as a first-write scalar). So one entity
    row can hold `transports: ["tcp", "udp"]`; `key()` below is what the lane groups by before it writes."""

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
    """One IP's passive record. VALID parts are KEPT even when others are malformed — a strict parse must
    not suppress good findings — and `complete` says whether anything was dropped."""

    ip: str
    ports: list = field(default_factory=list)         # PortObs, in the provider's own order
    hostnames: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    vulns: list = field(default_factory=list)         # CVE ids, from either measured-plausible shape
    tags: list = field(default_factory=list)
    org: str = ""
    isp: str = ""
    asn: str = ""
    last_update: str = ""
    complete: bool = True                             # False when ANY part was malformed and dropped
    unusable: int = 0                                 # how many parts were dropped, for reporting

    def drop(self) -> None:
        self.complete = False
        self.unusable += 1


def canonical_ip(value) -> str:
    """The IP in its canonical text form, or "" when it is not an address at all.

    Canonicalising matters for IDENTITY: `2001:db8::1` and `2001:0db8:0000::1` are the same host, and a
    record keyed on the raw text would be fetched and stored twice."""
    if not isinstance(value, str):
        return ""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return ""
    # an IPv4-MAPPED v6 address names the same host as the v4 address it embeds, and Shodan answers on
    # the v4 form. Two keys for one host would fetch it twice and store it twice.
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped or addr)


def ip_group(ip: str) -> str:
    """The fairness GROUP for an address: its /24 (v4) or /48 (v6).

    One dense netblock must not monopolise a bounded run — the same host-fair rule the other lanes use,
    transposed to address space. Returns "" for a value that is not an address, which the caller filters
    before ordering."""
    # review-B1.7#5: this grouped the RAW value, so `::ffff:1.1.1.1` — which `canonical_ip` folds to
    # `1.1.1.1` — was grouped under `::/48` while its record was owned under the v4 key. Ownership and
    # fairness have to see the same host family.
    canon = canonical_ip(ip)
    if not canon:
        return ""
    addr = ipaddress.ip_address(canon)
    net = ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False)
    return str(net)


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _scalar(doc, key: str, rec: HostRecord) -> str:
    """A string field. ABSENT is fine — the provider does not always know an ISP.

    review-B1.7r2#2: PRESENT-NULL is distinguished from absent, and both are fine: the measured envelope
    carries `"os": null` and `"area_code": null`, so `null` is this provider's own way of saying "unknown"
    and counting it would flag every record ever fetched. Present-but-not-a-string is different — that is a
    part we could not READ — and it is counted."""
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
    """DNS names from a list, lowercased and dot-stripped. A non-list is one dropped part; a non-string
    member is one more. Nothing is invented and nothing is silently ignored."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        rec.drop()
        return []
    out = []
    for h in raw:
        raw_name = _text(h)
        # review-B1.7#2: lower+rstrip accepted `../admin.example.com`. `canon_host_strict` is Quarry's ONE
        # name contract (IDNA2008/UTS-46 non-transitional, label and length rules) and a third divergent
        # copy is exactly what it exists to prevent.
        name = normalize.canon_host_strict(raw_name) if raw_name else None
        if not name or "." not in name:
            # a bare label names no domain, so it can be neither scoped nor attributed
            rec.drop()
            continue
        if name not in out:
            out.append(name)
    return out


def _vulns(raw, rec: HostRecord) -> list:
    """CVE ids from either shape Shodan has used. ABSENT means none — that is measured, and it is not the
    same as a shape we do not recognise, which is counted."""
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
    """A banner's string field, counted when it is present and unreadable. Absent and null are fine — not
    every module reports a timestamp or a transport."""
    if not isinstance(src, dict) or key not in src or src[key] is None:
        return ""
    text = _text(src[key])
    if not text:
        rec.drop()
        return ""
    return text


def _banner_transport(b, rec: HostRecord) -> str:
    """The banner's transport, lower-cased and checked against the measured vocabulary.

    It is half of `PortObs.key`, so anything accepted here becomes a SERVICE IDENTITY: `TCP` alongside
    `tcp` would report one host as running two services on one port, and `banana` would invent one."""
    raw = _banner_text(b, "transport", rec)
    if not raw:
        return ""
    transport = raw.lower()
    if transport not in _TRANSPORTS:
        rec.drop()
        return ""                              # the PORT survives; its transport is unknown
    return transport


def _banner_time(b, rec: HostRecord) -> str:
    """The banner's own sighting time, only when it has the MEASURED shape.

    It is the value reconciliation orders by, so a string we cannot read as a time must not be allowed to
    win that comparison — and it is not silently blanked either (review-B1.7r3#3)."""
    raw = _banner_text(b, "timestamp", rec)
    if not raw:
        return ""
    if not _TS_RE.match(raw):
        rec.drop()
        return ""
    # review-B1.7r4#2: the shape check accepted `2026-99-99T99:99:99`, and this value SELECTS the latest
    # sighting — so an impossible date would win every comparison. The fraction is already shape-checked
    # and `fromisoformat` disagrees about fraction lengths across the supported interpreters, so the
    # calendar part is validated on its own.
    try:
        _dt.datetime.strptime(raw.split(".", 1)[0], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        rec.drop()
        return ""
    return raw


def _banner_tls(b, rec: HostRecord) -> bool:
    """Whether TLS was SEEN on this banner. `ssl` is absent on most banners (measured: 3 of 12 carry it);
    present-but-not-an-object is a part we could not read, and answering False would assert plaintext."""
    if "ssl" not in b or b["ssl"] is None:
        return False
    if not isinstance(b["ssl"], dict):
        rec.drop()
        return False
    return True


def _merge_obs(prev: PortObs, new: PortObs, rec: HostRecord) -> PortObs:
    """Reconcile two banners for the SAME (port, transport).

    review-B1.7r2#3: the first was kept unconditionally, so a second `443/tcp` banner that added TLS, a
    newer sighting or another module was discarded while the record reported `complete`. An exact duplicate
    is harmless; a CONFLICT is either merged — TLS seen once is seen, and the LATEST sighting is the one
    worth reporting — or, where we can only model one value, counted as the loss it is."""
    module, seen_at = prev.module, prev.seen
    if new.module and new.module != prev.module:
        if prev.module:
            rec.drop()                         # two modules for one service: we model a single name
        else:
            module = new.module
    if new.seen and new.seen > seen_at:
        seen_at = new.seen                     # ISO-8601 from one provider: lexical order IS chronological
    return PortObs(port=prev.port, transport=prev.transport, module=module,
                   tls=prev.tls or new.tls, seen=seen_at)


def _ports(doc, rec: HostRecord) -> list:
    """Banners first, `ports` second, reconciled.

    `data[]` carries the transport, the module and whether TLS was seen; `ports` is a bare list that
    sometimes holds a port no banner does. Both are the provider's own answer about the same host, so a
    port in either is kept — a port we know less about is still a port."""
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
        # review-B1.7r2#2: these were coerced to blank/False in silence, so a banner whose `transport` was
        # `1` or whose `ssl` was the string "yes" reported a clean observation that had quietly lost what
        # the provider actually said.
        obs = PortObs(port=port, transport=_banner_transport(b, rec),
                      module=_banner_text(meta, "module", rec),
                      tls=_banner_tls(b, rec),
                      seen=_banner_time(b, rec))
        # keyed by (port, TRANSPORT): 53/tcp and 53/udp are two services and the record carries both.
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
    """An HTTP status as an exact int. review-B1.7r11#5: `http_code=200.0` passed because `200.0 == 200`, and
    `store_envelope` then coerced it with `int()` — so a status we never received could satisfy the measured
    contract. A status is an integer or it is not a status."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def read_host(raw, *, ip: str, http_code: int = 200):
    """`(kind, record_or_reason)` for one `/shodan/host/{ip}` response. NEVER raises.

    `kind` is `HOST_RECORD` with a `HostRecord`, `HOST_EMPTY` with the provider's own words, or
    `HOST_INVALID` with why the body cannot be trusted.

    The envelope must IDENTIFY ITSELF: a 200 whose `ip_str` is not the address we asked about is not
    evidence about that address, whatever else it contains. That rule is why the other providers' page
    readers exist in this shape too — a body accepted on faith becomes a permanent wrong answer in the
    ledger."""
    want = canonical_ip(ip)
    if not want:
        return HOST_INVALID, f"not an IP address: {ip!r}"
    code = _exact_status(http_code)
    if code is None:
        return HOST_INVALID, f"http status is not an integer ({http_code!r})"
    http_code = code
    # review-B1.7#4: `json.loads` raises TypeError on None, an int, a bool or an arbitrary object, and the
    # contract here is "never raises". Decoding is STRICT too: "replace" turned malformed UTF-8 into
    # plausible JSON, so bytes that are not text became a record.
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

    # `null` is read as ABSENT, the same rule the scalars use: the provider is not signalling anything, and
    # rejecting an otherwise-valid record over it would discard real evidence.
    if doc.get("error") is not None:
        # review-B1.7r2#2: a non-string `error` was ignored, so a body whose only content was an unreadable
        # signal fell through and was read as a record.
        # review-B1.7r3#4: and `"   "` was read as no error at all. A SUCCESS was measured without the key
        # entirely, so a present error we cannot make sense of is exactly as unreadable as a dict.
        if not isinstance(doc["error"], str):
            return HOST_INVALID, f"unreadable error field ({type(doc['error']).__name__})"
        if not _text(doc["error"]):
            return HOST_INVALID, "empty error field"
    said = _text(doc.get("error"))
    if said:
        # the provider is speaking about the request rather than the host. Coverage requires BOTH measured
        # facts: the 404 status and the measured wording. A 500 that happens to carry the same sentence is
        # an outage, and reading it as "this IP has no record" would report absence we never established.
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

    # the envelope must LOOK like a record, not merely name the right host: a 200 with no `ports` and no
    # `data` carries no evidence, and reporting it as a complete record would assert that this host has no
    # open ports — a measurement we never made.
    # review-B1.7r3#1: PRESENCE was not enough. `ports: null` and `data: {}` passed the check and then read
    # as "absent" downstream, producing a clean complete record with no evidence in it. The measured type is
    # part of the contract; `[]` stays the explicit empty answer.
    bad = [f"{k} is {'absent' if k not in doc else 'null' if doc[k] is None else type(doc[k]).__name__}"
           for k in _EVIDENCE_KEYS if not isinstance(doc.get(k), list)]
    if bad:
        return HOST_INVALID, f"success envelope: {', '.join(bad)}"

    rec = HostRecord(ip=want)
    # review-B1.7r3#2: a MISSING soft collection was counted while a present `null` one became a clean empty
    # collection. Only ABSENCE was measured (and only for `vulns`), so a null collection is a part we could
    # not read — the scalars' null rule is about the provider's "unknown" for a VALUE, and it does not
    # extend to a container whose measured form is always a list.
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
    # review-B1.7#2: these went through `_text`, which silently returns "" for a non-string — so an `asn`
    # of `13335` (an int) or an `org` of `{...}` vanished while the record still reported `complete`.
    rec.org = _scalar(doc, "org", rec)
    rec.isp = _scalar(doc, "isp", rec)
    rec.asn = _scalar(doc, "asn", rec)
    rec.last_update = _scalar(doc, "last_update", rec)
    return HOST_RECORD, rec


def empty_or_raise(err, *, ip: str):
    """A failed request's body, read for the provider's measured no-data answer.

    The transport layer raises on a 404, so "this IP is not in Shodan" — the ORDINARY case for most
    eligible addresses — arrives as an exception. Returns the empty answer's wording, or None when the
    failure is a real one and the caller must report it as such."""
    body = getattr(err, "body_bytes", None)
    if not body:
        return None
    kind, detail = read_host(body, ip=ip, http_code=getattr(err, "code", 0) or 0)
    return detail if kind == HOST_EMPTY else None


def host_body_error(reason: str) -> ProviderBodyError:
    """An unusable body, as the taxonomy's parse failure."""
    return ProviderBodyError(PROVIDER_PARSE, reason, "shodan")


# ── the eligible set ──────────────────────────────────────────────────────────────────────────────────
# OBSERVED IPs ONLY. A declared CIDR is a scope FILTER, never an address GENERATOR: a /16 in target.yaml
# is 65,534 addresses Quarry has no reason to believe exist, and enumerating them would spend a run's
# throughput on emptiness while reporting "coverage". Every address here is one Quarry actually saw —
# resolved from an in-scope host, or observed on a port record we already own — so each one carries its
# own reason to be asked about.

@dataclass(frozen=True)
class IpTarget:
    """One address to look up, with the evidence that made it eligible.

    `hosts` is why we believe it belongs to the target, and it travels with every entity the lane writes:
    a port on an address nobody can attribute is a lead an operator cannot act on."""

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
    """An exact port number. review-B1.7r6#2: a row is only PORT EVIDENCE if it says which port — an
    address qualified by `10.0.0.5:not-a-port` was qualified by nothing."""
    return not isinstance(value, bool) and isinstance(value, int) and 1 <= value <= 65535


def _ip_from_id(value) -> str:
    """The address out of a `"ip:port"` composite id — a COMPATIBILITY path only.

    review-B1.7r5#2: the bare-naabu writer stored only `id`, so rows an earlier run wrote have no `ip`
    field and would silently drop out of eligibility. The producer now stores both; this reads the old
    shape. `rsplit` because an IPv6 literal is full of colons and only the LAST one is the port — and the
    port is VALIDATED, not skipped over (review-B1.7r6#2)."""
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
    """Every address Quarry has OBSERVED for this target, deduplicated by canonical form.

    Two sources, both already scoped by the run that produced them:

      · `resolved` — the A/AAAA records of in-scope, non-OOS hosts. The host is the attribution.
      · `port` / `web_port` — addresses we already hold port evidence for. A record we scanned is a record
        worth asking Shodan about, and `web_port` carries the host that reached it.

    A CIDR in the profile FILTERS (`scope.ip_in_scope`) and never generates. An address that is neither
    attributable to an in-scope host nor inside a declared range is left out — not because it is
    uninteresting, but because nothing in the run says it is ours.

    review-B1.7#RoE: an OOS host's address is NOT eligible. The boundary is observe-and-mine OOS evidence,
    never expand against it — and a lookup is an expansion of the address set we act on, even a free one."""
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
            # a port row earns its address only by naming a port. Either shape must prove one.
            ip = (rec.get("ip") or "") if _valid_port(rec.get("port")) else ""
            ip = ip or _ip_from_id(rec.get("id"))
            host = (rec.get("host") or "").lower().rstrip(".")
            if host and not usable_host(host):
                continue                       # attributed to a host we may not expand against
            canon = canonical_ip(ip)
            if not canon:
                continue
            if not host and not scope.ip_in_scope(canon):
                # unattributed: only a DECLARED range makes it ours. Filtering, not generating.
                continue
            _add_target(acc, canon, host, entity)
    return list(acc.values())


def _dedupe(targets) -> list:
    """One entry per canonical address, merging the reasons. Identity is the address."""
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
    """PROJECT-LEVEL scheduling progress: when each address was last ASKED about.

    review-B1.7r9#2: ownership is run-scoped by design — the endpoint is free and its records are live, so a
    project-global evidence ledger would replay a months-old snapshot forever. But `ctx.run.dir` is a FRESH
    directory every invocation, so under a nonzero time budget every run started from an empty ledger, asked
    the same deterministic prefix, and the tail was never reached at all.

    The fix separates the two facts. EVIDENCE stays per-run. SCHEDULING PROGRESS is durable, and it bounds
    nothing: it only ORDERS. Never-asked addresses go first, then the longest-unasked — so a bounded run
    always advances, and an unbounded run still sweeps everything and refreshes what it already had.

    Best-effort by construction: a progress file we cannot read or write costs ordering quality, never
    coverage. Losing it degrades to "ask in netblock-fair order", which is where this lane started."""

    #: bump when the record's meaning changes; a bump simply starts a fresh rotation.
    SCHEMA = 1

    def __init__(self, path, *, held: bool = False):
        self.path = Path(path) if path else None
        self.asked: dict = {}
        self.loaded = False
        # `held` = the caller (a `sweep_session`) ALREADY owns the lock. POSIX `flock` is per open file
        # DESCRIPTION, so a second `open()` in the same process is a second description — re-locking it
        # blocks on ourselves forever. Measured: the suite hung outright.
        self.held = held
        self._read()

    @staticmethod
    def _usable_time(when) -> "float | None":
        """A timestamp we can ORDER by. review-B1.7r10#1: `isinstance(x, float)` accepts NaN and infinities —
        NaN makes every comparison false (so it sorts unpredictably) and an infinity pins an address to one
        end of the rotation forever. A negative time is a clock we cannot reason about."""
        if isinstance(when, bool) or not isinstance(when, (int, float)):
            return None
        value = float(when)
        if not _math.isfinite(value) or value < 0.0:
            return None
        return value

    @classmethod
    def _parse(cls, text: str) -> dict:
        """The `{ip: when}` map from a progress document, keeping only entries that can order anything."""
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
        """MERGE this run's asks into whatever is on disk, under a lock, and replace atomically.

        review-B1.7r10#1: a plain overwrite through one shared `.tmp` name let two runs on one project
        clobber each other — the later save discarded the earlier run's rotation, so both kept asking the
        same prefix, and two processes writing one temp path could publish a torn document. The critical
        section is read-merge-write, the temp name is per-process, and MAX-WINS on merge because a later
        ask is the one that must push an address down the rotation."""
        if self.path is None:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        # review-B1.7r12#2: the bounded wait returned None on timeout (and on a filesystem with no lock
        # support), the write then happened UNLOCKED, and `save()` still answered True — so a contended run
        # reported an atomic save that had raced. Best effort may LOSE rotation; it may not CLAIM it.
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


#: how long a WAITING acquire tries before giving up, and how often it retries. Giving up does NOT proceed
#: unlocked: `save()` reports False, because a write we could not serialize is not an atomic save.
_PROGRESS_LOCK_WAIT_S = 5.0
_PROGRESS_LOCK_POLL_S = 0.05


class SweepBusy(RuntimeError):
    """Another run on this project holds the sweep.

    review-B1.7r13#1: this once read "not a failure — the work is being done by someone else", and the lane
    recorded a SKIP on that basis. It is wrong: EVIDENCE is run-scoped, so the holder's records never reach
    this run, the two runs' eligible sets can differ, and the holder may fail before covering anything. For
    THIS run it is a gap, and the lane reports it as one."""


def _open_lock(path, *, blocking: bool):
    """The lock file handle, or None when this filesystem cannot lock at all.

    review-B1.7r11#1: ACQUISITION and the protected BODY were handled by one `try`, so an `OSError` thrown
    by the body — a failing `os.replace` — was caught by the helper, which then yielded a SECOND time and
    raised `RuntimeError: generator didn't stop after throw()`. A best-effort save became a machinery
    failure. Acquisition is settled here; the body's exceptions are none of this function's business."""
    lock = Path(path).with_name(Path(path).name + ".lock")
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        fh = lock.open("a+")
    except OSError:
        return None                                # no lock file at all — the caller decides what that costs
    # ALWAYS non-blocking at the syscall, even when the caller asked to wait: a `LOCK_EX` that blocks forever
    # turns a stuck holder — or, as this lane found the hard way, a second lock on the same file from the
    # SAME process — into a frozen run with no diagnosis. Waiting is a BOUNDED retry instead.
    # review-B1.7r13: giving up returns None, and the CALLER treats that as a failed save (`save()` answers
    # False) — it does NOT write unlocked and claim success. Losing rotation is allowed; claiming it is not.
    deadline = _time.monotonic() + (_PROGRESS_LOCK_WAIT_S if blocking else 0.0)
    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except OSError as e:
            if e.errno not in (errno.EACCES, errno.EAGAIN):
                fh.close()
                return None                        # no lock SUPPORT is different from a lock being HELD
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
    """Serialize the progress read-modify-write across processes on one project. ONE yield, always."""
    fh = _open_lock(path, blocking=blocking)
    try:
        yield
    finally:
        _release(fh)


@contextlib.contextmanager
def sweep_session(path):
    """`with sweep_session(p) as progress:` — the lock held across LOAD, SCHEDULE, NOTE and SAVE.

    review-B1.7r11#2: locking only the merge preserved both runs' records and still let both SELECT the same
    address: each loaded the file before either saved, so each saw it as never-asked. Rotation is only
    meaningful if reading it and acting on it are one operation.

    NON-BLOCKING on purpose: an unbounded sweep can run for a long time, and a second run queueing behind it
    would look like a hang. Contention raises `SweepBusy`, and the caller reports it as a GAP IN ITS OWN
    COVERAGE — review-B1.7r13#1: the holder's evidence is written to the HOLDER's run directory and never
    reaches this run, their eligible sets can differ, and the holder may fail before covering anything."""
    fh = _open_lock(path, blocking=False)
    try:
        # `held=True`: the session owns the lock for the whole lifecycle, so `save()` must not take it again.
        yield SweepProgress(path, held=fh is not None)
    finally:
        _release(fh)


def progress_path(project_dir):
    """`<project>/recon/state/shodan-host/v<schema>/sweep.json` — beside the other per-project state, and
    OUTSIDE any single run's directory, which is the whole point."""
    return (Path(project_dir) / "recon" / "state" / "shodan-host"
            / f"v{SweepProgress.SCHEMA}" / "sweep.json")


def schedule(targets, progress=None) -> list:
    """Host-fair order across NETBLOCKS: /24 for v4, /48 for v6.

    Bounded throughput must not mean "one dense netblock and nothing else". Rank is uniform — there is no
    value ordering among addresses we have all equally observed — so this is pure round-robin across
    groups, which `order_ranked_fair` gives with a constant rank. Membership is never bounded: the full
    list comes back, and a budget that stops early has done a FAIR prefix of it."""
    # rank tiers come from PROGRESS when we have it: never-asked first, then longest-unasked. Uniform
    # otherwise — there is no value ordering among addresses we have all equally observed.
    usable = [t for t in targets if t.group]
    if progress is None:
        return budget.order_ranked_fair(usable, rank=lambda t: 0, group=lambda t: t.group)
    # AGE IS THE RANK, one tier per distinct last-asked time. A coarse "never asked / asked" split is not
    # enough: once everything has been asked once, every address shares one tier and netblock fairness
    # reorders it back to the same prefix — the starvation this exists to prevent, one level up. Addresses
    # that share an age (every never-asked one) share a tier, so fairness still spreads them.
    ages = sorted({progress.rank(t.ip) for t in usable})
    tier = {age: i for i, age in enumerate(ages)}
    return budget.order_ranked_fair(usable, rank=lambda t: tier[progress.rank(t.ip)],
                                    group=lambda t: t.group)


# ── the free work loop ────────────────────────────────────────────────────────────────────────────────
# NOT `shodan_sched.run_work`. That coordinator's whole subject is CREDITS — a balance, a spendable bound,
# a reserve, a stop cause naming who ran out — and this endpoint costs none (MEASURED at a zero balance).
# Wiring a free lane through it would make every credit control apply to work no credit pays for, and an
# exhausted account would stop a lane it cannot affect. What IS reused is everything that is not about
# money: `budget.Ledger` ownership, the digest-bound artifact handshake, the provider taxonomy, and the
# same machinery-boundary discipline B1.7a forced out of the coordinator.

def store_envelope(ip: str, http_code: int, body: bytes) -> bytes:
    """What we STORE for one answer: the provider's body VERBATIM, plus the status it arrived with.

    review-B1.7r5#1: an empty answer was marked done in memory only, so a run bounded to one request asked
    the same absent address again on every resume and never reached the rest of the set. Owning it means
    storing it — and the no-data contract is `404 + the measured wording`, so the STATUS is part of the
    evidence. A bare body could never re-establish it on replay."""
    # review-B1.7r10#2: a STRICT decode here raised on a non-UTF-8 body — reproduced with b"\xff\xfe" — so a
    # refusal whose bytes are not text became a machinery failure and was never retained. The bytes are the
    # evidence: text when it IS text (an artifact an operator can read), base64 otherwise, never lost.
    code = _exact_status(http_code)
    if code is None:
        # a status we cannot store faithfully must not be stored at all: the replay contract reads it back
        # and compares it, so a coerced value would let an answer prove something it never had.
        raise ValueError(f"http status is not an integer ({http_code!r})")
    env = {"schema": SHODAN_HOST_SCHEMA, "ip": ip, "http_code": code}
    try:
        env["body"] = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        env["body_b64"] = base64.b64encode(bytes(body)).decode("ascii")
    return json.dumps(env).encode()


def read_stored(raw, *, ip: str):
    """`(kind, payload)` for a stored answer — the same three kinds `read_host` returns.

    The envelope is OURS, so it is validated as strictly as a provider body: a stored answer that does not
    identify its own address, status and schema cannot re-establish what it claimed."""
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
    # review-B1.7r6#3: `schema: true` passed, because `True == 1`. The wrapper claims strict validation, so
    # it gets the same exact-int rule `http_code` has.
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SHODAN_HOST_SCHEMA:
        return HOST_INVALID, f"stored answer is schema {schema!r}"
    if canonical_ip(env.get("ip")) != canonical_ip(ip):
        return HOST_INVALID, f"stored answer is about {env.get('ip')!r}, not {ip}"
    code = env.get("http_code")
    if isinstance(code, bool) or not isinstance(code, int):
        return HOST_INVALID, "stored answer has no usable status or body"
    # review-B1.7r11#4: with BOTH present the reader silently preferred `body`, so a stored answer could
    # carry two different bodies and replay whichever we happened to check first.
    # review-B1.7r12#3: and testing `is not None` checked VALUES, so `{"body": null, "body_b64": "..."}`
    # slipped through as one carrier. The SHAPE is what has to be exact: one key present, then its type.
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
    """Identity of a FAILED or UNUSABLE answer's body. A distinct namespace from `item_key`, so a retained
    explanation can never be mistaken for an answer we own (the paid lanes' rule — review-B1.7r9-P2)."""
    return hashlib.sha256(f"{SHODAN_HOST_SCHEMA}|{ip}|error".encode()).hexdigest()


def item_key(ip: str) -> str:
    """The per-ADDRESS completion identity: (schema, ip). No budget or reserve is folded in — nothing here
    is paid for, and a record's bytes do not depend on any control."""
    raw = f"{SHODAN_HOST_SCHEMA}|{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class HostOutcome:
    """What one lifecycle of the host lane did. Every field is a fact the terminal or coverage needs."""

    eligible: int = 0
    attempted: int = 0                  # addresses we actually issued a request for
    replayed: int = 0                   # records read back from our own store, free
    # of the addresses we ASKED about, how many answered at all (a record OR a measured empty). Separate
    # from `records`/`empty`, which include what replay contributed and therefore cannot measure requests.
    answered: int = 0
    records: int = 0                     # addresses that answered WITH a record
    empty: int = 0                        # addresses the provider said it has no data for — an ANSWER
    # review-B1.7r5#3: what the PROVIDER said, and what the store actually TOOK, are different facts. The
    # ingested counters used to be incremented before `ingest`, so a rejected sink still reported
    # `ports=2, hostnames=1` while delivering neither.
    ports_seen: int = 0
    hostnames_seen: int = 0
    vulns_seen: int = 0
    ports: int = 0                        # ...and these are CONSUMED: the sink took them
    hostnames: int = 0
    vulns: int = 0                         # banner-inferred CVE ids (UNVERIFIED by construction)
    incomplete: int = 0                  # records with at least one part we could not read
    unusable_parts: int = 0              # ...and how many parts that was, across the run
    evidence_invalid: int = 0            # a stored record whose artifact no longer validates
    publish_failed: int = 0              # records we could not durably store
    records_journaled: bool = True
    unconsumed: int = 0                  # records we own but could not ingest (see B1.7a)
    fail_classes: dict = field(default_factory=dict)
    fail_reason: str = ""
    # the FIRST reason for each class, so a terminal that names a class can quote a sentence about THAT
    # class rather than about whichever failure happened first (review-B1.7r8#3).
    fail_reasons: dict = field(default_factory=dict)
    not_attempted: list = field(default_factory=list)   # EXACT addresses, never a count alone
    machinery: list = field(default_factory=list)
    stop_cause: str = ""
    # review-B1.7r10#5: an ENTITY ROW is not an OBSERVATION. One `ip:53` row can hold TCP and UDP, so
    # counting observations as produced entities claimed two rows where one was written. And an answer whose
    # persistence failed is answered but NOT owned.
    port_rows: int = 0                   # `port` entity rows the sink actually wrote
    owned: int = 0                        # answers that reached the store AND the ledger
    error_bodies: int = 0                # failure/unusable bodies retained as RETRYABLE evidence
    persisted: bool = True
    #: whether the durable SCHEDULING progress was written. Separate from `persisted`, which is about
    #: evidence: losing rotation costs ordering quality, losing evidence costs the work itself.
    progress_saved: bool = True
    requests: int = 0                    # requests issued, including those that failed


def _record_machinery(o: HostOutcome, e: BaseException) -> None:
    """OUR OWN failure, without discarding what the lifecycle established. The FIRST cause names the stop
    (a later one is its consequence); every cause is kept (B1.7a)."""
    o.machinery.append(f"{type(e).__name__}: {e}")
    o.stop_cause = o.stop_cause or f"machinery:{type(e).__name__}"
    o.fail_reason = o.fail_reason or f"host state machinery failed ({type(e).__name__}: {e})"


def _fold(o: HostOutcome, rec: HostRecord) -> None:
    """What the PROVIDER answered. Nothing here claims the store took any of it."""
    o.records += 1
    o.ports_seen += len(rec.ports)
    o.hostnames_seen += len(rec.hostnames)
    o.vulns_seen += len(rec.vulns)
    if not rec.complete:
        o.incomplete += 1
        o.unusable_parts += rec.unusable


#: what a sink can report having stored, so the consumed counters name the same things the seen ones do.
WROTE_PORT, WROTE_HOSTNAME, WROTE_VULN = "port", "hostname", "vuln"
#: ...and the ROW a sink wrote, which is a different unit from the observations inside it.
WROTE_PORT_ROW = "port_row"


def _consume(o: HostOutcome, rec: HostRecord, target, art, ingest) -> None:
    """Hand one record to the sink, counting each entity AS IT IS STORED.

    review-B1.7r7#3: counting after `ingest` RETURNED made a partial write invisible — the first port
    stored, the second raising, and the run reporting `ports=0` about a port that is in the store. The sink
    reports its own writes, so the count is exact on every path.

    An ingest that raises leaves the record OWNED — it is stored and journaled, and dropping it would have
    the next run fetch it again — with the shortfall counted in its own unit (B1.7a)."""
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
    """Count one failure and keep the reason PAIRED with its own class.

    review-B1.7r8#3: `fail_reason` held the FIRST failure while the terminal picked the most frequent
    class, so a transport error followed by two server errors reported `server` with a transport reason —
    a class and a sentence about different events."""
    o.fail_classes[cls] = o.fail_classes.get(cls, 0) + 1
    o.fail_reasons.setdefault(cls, f"{cls}: {why}")
    o.fail_reason = o.fail_reason or f"{cls}: {why}"


def _replay_owned(targets, o: HostOutcome, done: set, *, ledger, ingest) -> None:
    """Re-ingest every record we already own, before anything is requested.

    Free or not, a record we hold is evidence THIS run should report — and re-reading it costs nothing.
    Ownership is RUN-SCOPED for this lane (the ledger lives under the run directory), because the endpoint
    is free and its records are live: a project-global ledger would replay a months-old snapshot of a host
    forever rather than asking again for nothing."""
    for t in targets:
        art = ledger.artifact(item_key(t.ip))
        if art is None:
            # not recorded, or recorded and DISOWNED at load because the digest no longer matched. Both mean
            # "we do not hold this record", and for a free endpoint the answer to that is simply to ask. A
            # `has()` branch here would be unreachable: `_safe_path` does no existence check, so an artifact
            # that vanished after the load still returns a path and lands in the read below.
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
    """Retain a failure's body as EVIDENCE, never as a completion.

    review-B1.7r9-P2: the paid lanes keep the bytes behind a refusal so an operator can see what the
    provider actually said, and so a class we have not measured yet is diagnosable after the fact. Free work
    owes the same: `add_evidence` claims nothing about ownership, so the address stays retryable."""
    if not body:
        return ""
    art = attempt_dir / f"{error_key(ip)}.json"
    raw = store_envelope(ip, http_code, body)
    dig = hashlib.sha256(raw).hexdigest()
    # review-B1.7r10#2: a retention failure used to be silent, so a quota body we could not store still
    # finished as a clean provider limit — hiding OUR evidence loss behind THEIR boundary. It is a gap, it
    # outranks the limit, and it stops us asking for more we cannot keep.
    if not budget.publish_bytes(art, raw, digest=dig):
        o.publish_failed += 1
        return "publish_failed"
    if not ledger.add_evidence(error_key(ip), art, digest=dig):
        o.records_journaled = False
        return "ledger_unwritable"
    o.error_bodies += 1
    return ""


def _keep(o: HostOutcome, ledger, attempt_dir, ip: str, http_code: int, body: bytes) -> str:
    """Store one ANSWER — record or measured-empty — and BIND it, under the same durability handshake the
    paid lanes use.

    Free work still has to be resumable: an answer we cannot store is one an interrupted run asks for
    again, and one we cannot journal is one we will not know we have. Returns "" or WHICH sink failed."""
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
    measured 404, a `body_bytes` the provider's no-data answer can be read out of.

    review-B1.7r9#1: the adapter returned bytes only, so a success was ASSUMED to be 200 and stored as 200 —
    an HTTP 201 with a valid-looking body was accepted as the measured contract and owned. The status is the
    provider's, not ours to fill in.

    A DEADLINE bounds throughput, never membership: whatever it does not reach stays in `not_attempted`,
    by exact address, for the next run to pick up."""
    should_stop = should_stop or (lambda cls: False)
    probed: list = []

    def sinks_ready() -> str:
        """review-B1.7r5#4: writability was discovered AFTER the first answer came back, so a broken store
        cost a request and threw the answer away. Probed once, lazily — only when pending work exists, so a
        lifecycle that owns everything never touches either sink — and before anything is asked."""
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
            continue                           # the remainder is derived, once, from what we ASKED
        if bound is not None and bound.exhausted():
            # review-B1.7r7#1: the shared `budget.Budget` — checked BETWEEN addresses, so one already
            # started always finishes, and 0 really is unbounded (`settings.concurrency` clamps 0 to 1,
            # which turned "no bound" into a one-second run).
            o.stop_cause = o.stop_cause or "budget_time"
            continue
        unusable = sinks_ready()
        if unusable:
            o.stop_cause = o.stop_cause or unusable
            continue
        asked.add(t.ip)
        if progress is not None:
            # recorded when the request is ISSUED, not when it succeeds: the next run must rotate past an
            # address we already spent a request on, whatever the answer was.
            progress.note(t.ip, _time.time())
        o.attempted += 1
        o.requests += 1
        raw, code, err = fetch(t.ip)
        if err is not None:
            said = empty_or_raise(err, ip=t.ip)
            if said is not None:
                # the provider ANSWERED: it has nothing for this address. Coverage, not a failure.
                # review-B1.7r6#1: counted HERE, before storage is attempted — what the provider said and
                # whether we managed to keep it are independent facts, and a failing store used to erase the
                # answer from the run's own accounting.
                o.empty += 1
                o.answered += 1
                # ...and it is OWNED like any other answer, or a bounded run would ask the same absent
                # address on every resume and never reach the rest of the set (review-B1.7r5#1).
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
            # retention FIRST, so a failure to keep the explanation sets the stop cause before a provider
            # boundary can claim it — ours is the gap that outranks their limit.
            lost = _keep_error(o, ledger, attempt_dir, t.ip, code,
                               getattr(err, "body_bytes", b"") or b"")
            if lost:
                o.stop_cause = o.stop_cause or lost
                continue
            if should_stop(cls):
                # a refusal the next address would meet identically. It stops us ASKING and stays a gap:
                # the class is whatever it is, and nothing here reclassifies it (B1.5r4#1).
                o.stop_cause = o.stop_cause or f"provider_stop:{cls}"
            continue
        kind, payload = read_host(raw, ip=t.ip, http_code=code)
        if kind == HOST_EMPTY:
            # review-B1.7r14#1: this path counted the answer and marked it done IN MEMORY only — no `_keep`,
            # no `owned` — so an adapter that returns a measured 404 as a normal result (the fetch contract
            # allows it: `(body, 404, None)`) had its empty answer re-asked on every resume. Fresh and
            # replay owe the same contract, and so do the two ways the same answer can arrive.
            o.empty += 1                       # the ANSWER, before any question of keeping it
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
            # an unusable SUCCESS body is exactly as worth keeping as a refusal: it is how a shape change
            # gets diagnosed, and the address stays retryable because evidence is not ownership.
            lost = _keep_error(o, ledger, attempt_dir, t.ip, code, raw)
            if lost:
                o.stop_cause = o.stop_cause or lost
            continue
        # what the provider ANSWERED, before any question of keeping it (review-B1.7r6#1). Ownership and
        # consumption are the two facts a storage failure is allowed to prevent — not this one.
        o.answered += 1
        _fold(o, payload)
        why = _keep(o, ledger, attempt_dir, t.ip, code, raw)
        if why:
            # a store we cannot write to is a GLOBAL problem: every further record would be unrecordable
            # too, so stop asking rather than collect evidence we cannot keep.
            o.stop_cause = o.stop_cause or why
            continue
        done.add(t.ip)
        o.owned += 1
        _consume(o, payload, t, attempt_dir / f"{item_key(t.ip)}.json", ingest)
        if not ledger_writable(ledger):
            o.stop_cause = o.stop_cause or "ledger_unwritable"


def _remainder(targets, o: HostOutcome, done: set, asked: set) -> None:
    """Addresses this lifecycle NEVER REACHED, by exact identity.

    "Never asked" is not the same as "asked and failed": a failure is already counted by class, and listing
    it here as well would both overstate the remainder and hide that the attempt happened.

    A SNAPSHOT, not an accumulator: it is reachable twice — once normally, once after a machinery failure —
    and appending to a list that already held the first pass would double the remainder (B1.7a)."""
    o.not_attempted = [t.ip for t in targets if t.ip not in done and t.ip not in asked]


def run_hosts(targets, *, fetch, ingest, ledger, attempt_dir, bound=None,
              should_stop=None, progress=None) -> HostOutcome:
    """Look up every eligible address, replaying anything already owned. FREE: no balance, no reserve.

    `bound` is a `budget.Budget` (None or `unbounded` = no bound, the default): the endpoint costs nothing,
    so the only reason to stop early is wall-clock, and what a bound does not reach is a counted, resumable
    remainder. The SAME object is what the caller reports selection coverage from, so the budget a run
    honored and the budget it reports can never disagree.

    `ingest(target, record, artifact, wrote)` calls `wrote(kind)` for each entity it actually stores, so a
    write that fails halfway through a record leaves the consumed counters exact (review-B1.7r7#3).

    Ordinary machinery failures are contained here rather than escaping to the caller with the outcome
    (B1.7a): replay, asking, remainder accounting and the ledger save each keep what the lifecycle already
    established. `KeyboardInterrupt` and `SystemExit` still cancel the run."""
    # review-B1.7r5#5: `schedule` was correct and OPTIONAL — the loop consumed whatever order it was
    # handed, so netblock fairness depended on a caller remembering to compose it. It is part of the loop.
    # Deduplicated first: two `IpTarget`s for one address would be asked about twice.
    targets = schedule(_dedupe(targets), progress)
    o = HostOutcome(eligible=len(targets))
    done: set = set()
    asked: set = set()
    # NB no unbounded special-case: `Budget.exhausted()` already answers False for `seconds == 0`, and a
    # second guard here would be a branch nothing can falsify.
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
            # ordering progress is best-effort: losing it costs rotation quality, never coverage. It is
            # saved on EVERY path, including a machinery failure, because the requests were still spent.
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
            o.persisted = True                 # the snapshot IS the durable answer; nothing else to ask
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
