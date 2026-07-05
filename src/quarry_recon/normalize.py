"""Normalizers — convert raw tool output into stable entities with provenance.

Each function takes raw text + a source label and yields entity dicts. The phase code
is responsible for scope-filtering and writing them into the store. Keeping parsing
here (not inline in phases) means provenance stays consistent after dedup (design §4).
"""
from __future__ import annotations

import json
import re
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
    """Coerce a dnsx field to a list — dnsx may emit a scalar or a dict (e.g. `soa`) instead of a
    list; iterating those directly would yield chars / dict-keys, not records."""
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
        yield {
            "url": url,
            "host": (obj.get("input") or obj.get("host") or "").lower().rstrip("."),
            "status_code": obj.get("status_code"),
            "title": obj.get("title"),
            "tech": obj.get("tech", []) or [],
            "webserver": obj.get("webserver"),
            "cdn": obj.get("cdn", False),
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
        yield {"id": sid, "kind": kind, "data": data,
               "severity": obj.get("severity", "unknown"), **_prov(source, raw_ref)}


def host_of_url(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""
