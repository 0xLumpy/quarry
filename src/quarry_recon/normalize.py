"""Normalizers — raw tool output to stable entities with provenance.

Each function takes raw text plus a source label and yields entity dicts; scope-filtering and writing them
into the store belong to the phase code.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit as _urlsplit
from typing import Iterator

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _prov(source: str, raw_ref: str | None) -> dict:
    p = {"sources": [source]}
    if raw_ref:
        p["raw_ref"] = raw_ref
    return p


def hosts(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    """Plain host-per-line output (subfinder, github-subdomains, tls SAN grep)."""
    for line in raw.splitlines():
        h = line.strip().lower().rstrip(".")
        if h and _HOST_RE.match(h) and "." in h:
            yield {"host": h, **_prov(source, raw_ref)}


def dnsx_resolved(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    """dnsx -json lines -> resolved host + A records."""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # plain host output fallback
            h = line.lower().rstrip(".")
            if _HOST_RE.match(h) and "." in h:
                yield {"host": h, "a": [], **_prov(source, raw_ref)}
            continue
        host = (obj.get("host") or "").lower().rstrip(".")
        if host:
            yield {"host": host, "a": obj.get("a", []) or [],
                   "cname": obj.get("cname", []) or [], **_prov(source, raw_ref)}


_DNS_STR_TYPES = ("a", "aaaa", "cname", "ns", "mx", "txt", "caa")


def _aslist(v):
    """Coerce a dnsx field to a list — it may arrive as a scalar or a dict (e.g. `soa`) instead."""
    if v is None:
        return []
    if isinstance(v, (str, dict)):
        return [v]
    return list(v) if isinstance(v, (list, tuple)) else [v]


def dnsx_records(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    """dnsx -json lines -> one dns_record per (host, type, value) across a/aaaa/cname/ns/mx/txt/caa,
    plus soa (object → its primary NS / compact JSON), asn (as_number, + as_name), and cdn_name."""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (obj.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        for t in _DNS_STR_TYPES:
            for v in _aslist(obj.get(t)):
                if v:
                    yield {"id": f"{host}|{t}|{v}", "host": host, "type": t,
                           "value": str(v), **_prov(source, raw_ref)}
        for s in _aslist(obj.get("soa")):
            if isinstance(s, dict):
                v = s.get("ns") or json.dumps(s, separators=(",", ":"))
            else:
                v = s
            if v:
                yield {"id": f"{host}|soa|{v}", "host": host, "type": "soa",
                       "value": str(v), **_prov(source, raw_ref)}
        asn = obj.get("asn")
        if isinstance(asn, dict) and asn.get("as_number"):
            rec = {"id": f"{host}|asn|{asn['as_number']}", "host": host, "type": "asn",
                   "value": str(asn["as_number"]), **_prov(source, raw_ref)}
            if asn.get("as_name"):
                rec["asn_name"] = asn["as_name"]
            yield rec
        cdn = obj.get("cdn_name") or (obj.get("cdn") if isinstance(obj.get("cdn"), str) else None)
        if cdn:
            yield {"id": f"{host}|cdn|{cdn}", "host": host, "type": "cdn",
                   "value": str(cdn), **_prov(source, raw_ref)}


def tlsx_certs(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    """tlsx -json lines -> certificate entities (host/cn/san/issuer/expiry/serial/wildcard)."""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (o.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        san = [s.lower().rstrip(".") for s in (o.get("subject_an") or []) if s]
        port = str(o.get("port") or "443")
        yield {"id": f"{host}:{port}", "host": host, "port": port,
               "cn": o.get("subject_cn"), "san": san,
               "issuer": o.get("issuer_cn"), "issuer_org": o.get("issuer_org") or [],
               "not_after": o.get("not_after"), "serial": o.get("serial"),
               "sha1": (o.get("fingerprint_hash") or {}).get("sha1"),
               "wildcard": any(s.startswith("*.") for s in san),
               **_prov(source, raw_ref)}


def httpx_json(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    """httpx -json lines -> live service entities (the probe source of truth)."""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if not url:
            continue
        raw_cdn = obj.get("cdn") if "cdn" in obj else None
        cdn = raw_cdn if type(raw_cdn) is bool else None
        state = "detected" if cdn is True else "not_detected" if cdn is False else "unknown"
        yield {
            "url": url,
            "host": (obj.get("input") or obj.get("host") or "").lower().rstrip("."),
            "status_code": obj.get("status_code"),
            "title": obj.get("title"),
            "tech": obj.get("tech", []) or [],
            "webserver": obj.get("webserver"),
            # Absence is not a negative detector result.  Keep the nullable
            # compatibility field and make the three-state contract explicit.
            "cdn": cdn,
            "cdn_state": state,
            "cdn_name": obj.get("cdn_name"),
            "ip": obj.get("host") if obj.get("a") is None else None,
            "a": obj.get("a", []) or [],
            "cname": obj.get("cname", []) or [],
            "content_length": obj.get("content_length"),
            "favicon": obj.get("favicon"),
            "location": obj.get("location"),
            "final_url": obj.get("final_url") or obj.get("url"),
            "asn": (obj.get("asn") or {}).get("as_number") if isinstance(obj.get("asn"), dict) else obj.get("asn"),
            "asn_org": (obj.get("asn") or {}).get("as_name") if isinstance(obj.get("asn"), dict) else None,
            **_prov(source, raw_ref),
        }


def cdn_state(record: dict) -> str:
    """Return the conservative merged CDN state with positive evidence precedence.

    Store merges preserve conflicting later scalars under ``_alt``.  Ignoring
    those values made a detector-positive observation look negative/unknown
    solely because a weaker row arrived first.  Any positive marker wins;
    unknown wins over negative; an unqualified legacy false remains unknown.
    """
    if type(record) is not dict:
        return "unknown"
    alt = record.get("_alt") if type(record.get("_alt")) is dict else {}

    def values(field):
        out = [record[field]] if field in record else []
        held = alt.get(field)
        out.extend(held if type(held) is list else ([held] if held is not None else []))
        return out

    raw_states = values("cdn_state")
    valid_states = ("detected", "not_detected", "unknown")
    states = [value for value in raw_states
              if type(value) is str and value in valid_states]
    markers = values("cdn")
    # Reject malformed evidence before applying positive precedence.  Otherwise
    # a valid positive marker could launder a conflicting non-contract value.
    if (any(type(value) is not str or value not in valid_states
            for value in raw_states)
            or any(value is not None and type(value) is not bool
                   for value in markers)):
        return "unknown"
    if "detected" in states or any(value is True for value in markers):
        return "detected"
    if "unknown" in states:
        return "unknown"
    if states and all(value == "not_detected" for value in states):
        return "not_detected"
    # A false marker without the explicit state is ambiguous: older httpx
    # normalization inserted false when the provider omitted the field.
    return "unknown"


def urls(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    """Generic URL extraction (gau, waymore -mode U, katana, hakrawler)."""
    seen = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = line if line.lower().startswith(("http://", "https://")) else None
        if m is None:
            found = _URL_RE.search(line)
            m = found.group(0) if found else None
        if m and m not in seen:
            seen.add(m)
            yield {"url": m, **_prov(source, raw_ref)}


def jsluice_urls(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        u = obj.get("url")
        if u:
            yield {"url": u, "method": obj.get("method"),
                   "type": obj.get("type"), **_prov(source, raw_ref)}


def jsluice_secrets(raw: str, source: str, raw_ref: str | None = None) -> Iterator[dict]:
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = obj.get("kind") or obj.get("type") or "secret"
        data = obj.get("data") or obj.get("match") or obj
        sid = f"{kind}:{json.dumps(data, sort_keys=True)[:120]}"
        occurrence = {"source": source, **({"raw_ref": raw_ref} if raw_ref else {})}
        for field in ("url", "file", "line", "column", "start", "end"):
            if field in obj:
                occurrence[field] = obj[field]
        yield {"id": sid, "kind": kind, "data": data,
               "severity": obj.get("severity", "unknown"),
               "occurrences": [occurrence], "provider_record": obj,
               **_prov(source, raw_ref)}


def host_of_url(url: str) -> str:
    """The host an HTTP client would actually contact, or "" when that cannot be determined.

    Every scope decision in the repo runs through here, so the answer is fail-closed — "" makes a scope
    check refuse. It is "" for any scheme other than `http`/`https`, for a netloc carrying userinfo
    (`user:pass@host`, which no recon input needs), and for an invalid port or IPv6 literal.
    """
    if type(url) is not str:
        return ""
    try:
        parts = _urlsplit(url.strip())
    except (TypeError, ValueError):
        return ""
    if parts.scheme.lower() not in ("http", "https"):
        return ""
    if "@" in parts.netloc:
        return ""
    try:
        host = parts.hostname or ""          # raises on a malformed port/IPv6 literal
        parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    # URL parsing returns Unicode host spelling unchanged.  Scope roots use
    # Quarry's IDNA2008/UTS-46 A-label policy, so returning that Unicode value
    # would make one authority compare as two different destinations.  IP
    # literals remain addresses rather than being sent through IDNA.
    import ipaddress
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        return canon_host_strict(host) or ""

def idna_ascii(s: str):
    """The single IDNA encode in the repo: IDNA2008 / UTS-46, non-transitional. Returns the A-label form,
    or None when the input cannot be encoded. Callers keep their own failure policy — config raises
    ProfileError, store falls back best-effort, canon_host_strict returns None."""
    import idna as _idna
    try:
        return _idna.encode(s, uts46=True, transitional=False).decode("ascii")
    except Exception:
        return None


def canon_host_strict(h: str):
    """Canonicalize a hostname under Quarry's one IDNA policy, or None when it cannot be a real hostname.

    Strict, unlike store._canon_host's best-effort fallback to the lowered form: anything that is not a
    syntactically valid hostname returns None, because the caller is about to contact it."""
    s = str(h).strip().lower().rstrip(".")
    if not s or "/" in s or ".." in s or any(c.isspace() for c in s):
        return None
    core = idna_ascii(s)
    if core is None:
        return None
    if len(core) > 253:
        return None
    for label in core.split("."):
        if not (1 <= len(label) <= 63) or label[0] == "-" or label[-1] == "-":
            return None
        if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label):
            return None
    return core
