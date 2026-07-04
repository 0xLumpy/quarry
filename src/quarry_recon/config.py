"""Target profile parsing + scope matcher.

The target profile (YAML) is the single per-engagement config. It compiles into a
ScopeMatcher that every phase consults so scope decisions are explicit and auditable
(design principles 3 + 4) — replacing the old regex-in-every-script approach.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

# HTTP probe set from the proven manual workflow. Empty PORTS.HTTP means use this full set;
# populate PORTS.HTTP only when an engagement needs to narrow or override it.
# Heavy: 90+ ports * many hosts. Pair with conservative HTTP rate limits when required.
FULL_HTTP_PORTS = [
    80, 443, 81, 300, 591, 593, 832, 981, 1010, 1311, 1099, 2082, 2095, 2096, 2480,
    3000, 3001, 3002, 3003, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108,
    5280, 5281, 5601, 5800, 6543, 7000, 7001, 7396, 7474, 8000, 8001, 8008, 8014, 8042,
    8060, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8095, 8118, 8123, 8172, 8181, 8222,
    8243, 8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043,
    9060, 9080, 9090, 9091, 9092, 9200, 9443, 9502, 9800, 9981, 10000, 10250, 11371,
    12443, 15672, 16080, 17778, 18091, 18092, 20720, 32000, 55440, 55672,
]


class ProfileError(Exception):
    pass


# Content-discovery recursion is capped — content discovery is deliberately conservative. Raise
# this only for an engagement that truly needs it. Depth 4-5 warns at run time; > MAX fails loud.
MAX_CONTENT_RECURSION = 5


@dataclass
class ScopeMatcher:
    """Compiled, reusable scope decisions."""

    apex_domains: list[str]
    oos_patterns: list[re.Pattern]
    cidrs: list[ipaddress._BaseNetwork]
    passive_only: bool

    def _matches_apex(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == a or host.endswith("." + a) for a in self.apex_domains)

    def is_oos(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(p.search(host) for p in self.oos_patterns)

    def in_scope(self, host: str) -> bool:
        """In scope for COLLECTION (passive). Apex match and not explicitly OOS."""
        return self._matches_apex(host) and not self.is_oos(host)

    def active_allowed(self, host: str) -> bool:
        """Allowed for ACTIVE probing/scanning. Passive-only mode blocks everything."""
        if self.passive_only:
            return False
        return self.in_scope(host)

    def ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.cidrs)

    def filter_hosts(self, hosts: Iterable[str], active: bool = False) -> list[str]:
        keep = self.active_allowed if active else self.in_scope
        seen, out = set(), []
        for h in hosts:
            h = h.strip().lower().rstrip(".")
            if h and h not in seen and keep(h):
                seen.add(h)
                out.append(h)
        return out


@dataclass
class TargetProfile:
    target: str
    apex_domains: list[str]
    oos: list[str]
    cidr: list[str]
    asn: list[str]
    ratelimit: dict
    http_ports: list[int]
    modes: dict
    notes: list[str]
    path: Path | None = None
    _raw: dict = field(default_factory=dict, repr=False)

    # ── rate-limit accessors (empty => None => tool default) ──
    @property
    def http_rl(self) -> int | None:
        v = self.ratelimit.get("HTTP")
        return None if v in (None, "") else int(v)

    @property
    def dns_rate(self) -> int | None:
        v = self.ratelimit.get("DNS")
        return None if v in (None, "") else int(v)

    @property
    def portscan_rate(self) -> int | None:
        v = self.ratelimit.get("PORTSCAN")
        return None if v in (None, "") else int(v)

    @property
    def passive_only(self) -> bool:
        return bool(self.modes.get("PASSIVE_ONLY", False))

    @property
    def headless(self) -> bool:
        return bool(self.modes.get("HEADLESS", False))

    @property
    def screenshots(self) -> bool:
        return bool(self.modes.get("SCREENSHOTS", True))

    @property
    def portscan(self) -> bool:
        return bool(self.modes.get("PORTSCAN", True))

    @property
    def takeover(self) -> bool:
        return bool(self.modes.get("TAKEOVER", True))

    @property
    def content_discovery(self) -> str:
        """Phase 11 intensity: off | light | balanced | deep. Default OFF (candidate-driven, opt-in)."""
        v = self.modes.get("CONTENT_DISCOVERY", "off")
        v = ("off" if v is False else "on" if v is True else str(v)).strip().lower()
        return v if v in ("off", "light", "balanced", "deep") else "off"

    @property
    def content_recursion(self) -> int:
        """Content-discovery recursion depth (separate knob; 0 = off). 11.2 honors it."""
        v = self.modes.get("CONTENT_RECURSION", 0)
        if v is True:
            return 1
        try:
            return min(MAX_CONTENT_RECURSION, max(0, int(v)))   # load() already range-checks; clamp defensively
        except (TypeError, ValueError):
            return 0

    @property
    def deep_evidence(self) -> bool:
        """Opt-in DOWNLOAD of heavy artifacts (actuator heapdump/threaddump/DB dump). OFF by default:
        a GET to a heapdump forces server-side generation, so pulling it is DELIBERATE human intent.
        When off, heavy exposures are detected + flagged (never fetched)."""
        v = self.modes.get("DEEP_EVIDENCE", False)
        if isinstance(v, bool):
            return v
        return str(v).strip().lower() in ("on", "true", "yes", "1", "deep")

    @property
    def org_names(self) -> list[str]:
        # optional OSINT anchors (org/registrant names to pivot from)
        return [str(x).strip() for x in (self._raw.get("ORG_NAMES") or []) if x]

    @property
    def brands(self) -> list[str]:
        return [str(x).strip() for x in (self._raw.get("BRANDS") or []) if x]

    @property
    def waymore_limit(self) -> int:
        # max archived responses to download per apex (waymore -l). 0 = all (heavy).
        v = (self._raw.get("LIMITS") or {}).get("WAYMORE_RESPONSES")
        return 5000 if v in (None, "") else int(v)

    @property
    def ports(self) -> list[int]:
        # Explicit profile list wins; blank means the methodology's full HTTP probe set.
        if self.http_ports:
            return self.http_ports
        return list(FULL_HTTP_PORTS)

    @property
    def ports_are_default(self) -> bool:
        """True when using the built-in full HTTP set (no explicit PORTS.HTTP) — lets the banner
        collapse the ~93-port dump to `default (N)` instead of enumerating it."""
        return not self.http_ports

    def scope(self) -> ScopeMatcher:
        pats = []
        for raw in self.oos:
            try:
                pats.append(re.compile(raw, re.IGNORECASE))
            except re.error as e:
                raise ProfileError(f"bad OOS regex {raw!r}: {e}")
        nets = []
        for c in self.cidr:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError as e:
                raise ProfileError(f"bad CIDR {c!r}: {e}")
        return ScopeMatcher(
            apex_domains=[a.lower().rstrip(".") for a in self.apex_domains],
            oos_patterns=pats,
            cidrs=nets,
            passive_only=self.passive_only,
        )

    @classmethod
    def load(cls, path: str | Path) -> "TargetProfile":
        path = Path(path)
        if not path.exists():
            raise ProfileError(f"target profile not found: {path}")
        raw = yaml.safe_load(path.read_text()) or {}
        if not raw.get("TARGET"):
            raise ProfileError("profile missing required field: TARGET")
        apexes = [str(d).strip() for d in (raw.get("APEX_DOMAINS") or []) if d]
        if not apexes:
            raise ProfileError("profile must list at least one APEX_DOMAINS entry")
        cdv = (raw.get("MODES") or {}).get("CONTENT_DISCOVERY", "off")
        # YAML parses bare `off`/`on` as booleans — map back before validating.
        cd = ("off" if cdv is False else "on" if cdv is True else str(cdv)).strip().lower()
        if cd not in ("off", "light", "balanced", "deep"):     # opt-in phase: fail loud on a typo
            raise ProfileError(f"invalid MODES.CONTENT_DISCOVERY {cd!r} (use off|light|balanced|deep)")
        crv = (raw.get("MODES") or {}).get("CONTENT_RECURSION", 0)
        crv = 1 if crv is True else (0 if crv is False else crv)
        try:
            cr_i = int(crv)
        except (TypeError, ValueError):
            raise ProfileError(f"invalid MODES.CONTENT_RECURSION {crv!r} (int 0-{MAX_CONTENT_RECURSION} or true)")
        if not 0 <= cr_i <= MAX_CONTENT_RECURSION:     # caged: a typo like 20 must fail, not roar
            raise ProfileError(
                f"MODES.CONTENT_RECURSION {cr_i} out of range (0-{MAX_CONTENT_RECURSION}; content discovery is capped)")
        ports = [int(p) for p in (raw.get("PORTS") or {}).get("HTTP") or [] if p]
        return cls(
            target=str(raw["TARGET"]).strip(),
            apex_domains=apexes,
            oos=[str(p) for p in (raw.get("OOS") or []) if p],
            cidr=[str(c) for c in (raw.get("CIDR") or []) if c],
            asn=[str(a).strip() for a in (raw.get("ASN") or []) if a],
            ratelimit=raw.get("RATELIMIT") or {},
            http_ports=ports,
            modes=raw.get("MODES") or {},
            notes=[str(n) for n in (raw.get("NOTES") or []) if n],
            path=path,
            _raw=raw,
        )
