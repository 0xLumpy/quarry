"""Target profile parsing + scope matcher.

The target profile (YAML) is the single per-engagement config. It compiles into a ScopeMatcher that
every phase consults, so scope decisions are explicit and auditable.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

# HTTP probe set. Empty PORTS.HTTP means use this full set; populate it only to narrow or override.
# Heavy: 90+ ports × many hosts — pair with conservative HTTP rate limits.
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


# content-discovery recursion cap. Depth 4-5 warns at run time; above it fails loud.
MAX_CONTENT_RECURSION = 5
#: ceiling for MODES.JS_CHUNK_BRUTE. Guessing chunk ids manufactures requests for paths no bundle named,
#: so it is a caged engagement decision — never a machine-wide setting and never lifted by a flag.
MAX_JS_CHUNK_BRUTE = 3000

# ── profile-input validation: reject malformed/dangerous input; never narrows what can be targeted ──
_TRUE_STRS = {"true", "yes", "on", "1"}
_FALSE_STRS = {"false", "no", "off", "0", ""}


def _flag(raw, default: bool) -> bool:
    """Strict boolean coercion for MODES: native `true`/`false` pass through, a quoted string is parsed
    (`"false"` → False, not truthy), `None` → `default`, anything ambiguous raises. Arming flags with
    their own stricter rule (SECRET_VERIFICATION stays `is True`) are not governed here."""
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):                    # YAML 1/0 only (already-bool handled above); 2/-1 are typos
        if raw in (0, 1):
            return raw == 1
        raise ProfileError(f"invalid boolean {raw!r} (use true/false or 0/1)")
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in _TRUE_STRS:
            return True
        if s in _FALSE_STRS:
            return False
    raise ProfileError(f"invalid boolean {raw!r} (use true/false)")


def _strict_int(v, ctx: str) -> int:
    """Integer coercion that never truncates or coerces: rejects bool and float, accepts a real int or a
    signed-digit string. Keeps `true`→1 / `80.9`→80 out of a port/rate."""
    if isinstance(v, bool):
        raise ProfileError(f"{ctx} must be an integer, got boolean {v!r}")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and re.fullmatch(r"[+-]?\d+", v.strip()):
        return int(v.strip())
    raise ProfileError(f"{ctx} must be an integer, got {v!r}")


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# one DNS label: 1-63 chars, letters/digits/hyphen, no leading/trailing hyphen. A single-label
# internal zone (e.g. `corp`) is allowed.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


def _canon_domain(d: str) -> str:
    """Validate + canonicalize an APEX_DOMAINS entry to a hostname root. A leading `*.` wildcard is
    stripped to its root (Quarry's scope is root-based). Unicode is IDNA2008 / UTS-46 non-transitional
    (`faß.de` → `xn--fa-hia.de`, not the builtin codec's `fass.de`, which would contact a different
    domain). Accepts a single-label internal zone; rejects IP literals, path/traversal, whitespace and
    empty labels — closing the apex→filename path escape."""
    s = str(d).strip().rstrip(".").lower()
    if s.startswith("*."):
        s = s[2:]                                          # wildcard -> root (already covers subs + bare apex)
    if not s:
        raise ProfileError(f"invalid APEX_DOMAINS entry {d!r} (empty)")
    from . import normalize as _n
    core = _n.idna_ascii(s)                      # shared policy; raising is this site's choice
    if core is None:
        raise ProfileError(f"invalid domain in APEX_DOMAINS: {d!r}")
    if not _DOMAIN_RE.match(core) or _looks_like_ip(core):
        raise ProfileError(f"invalid domain in APEX_DOMAINS: {d!r} (not a hostname)")
    return core


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
        """In scope for collection (passive): apex match and not explicitly OOS."""
        return self._matches_apex(host) and not self.is_oos(host)

    def active_allowed(self, host: str) -> bool:
        """Allowed for active probing/scanning; passive-only mode blocks everything."""
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
        return _flag(self.modes.get("PASSIVE_ONLY"), False)

    @property
    def block_private_targets(self) -> bool:
        """Opt-in: don't contact private (RFC1918/CGNAT/ULA) targets. Default False — a private-resolving
        in-scope name is a lead and the reachable service is tested. Set true for a paranoid VPS-external
        posture. Scan-box/cloud-metadata destinations are always withheld regardless of this flag."""
        return _flag(self.modes.get("BLOCK_PRIVATE_TARGETS"), False)

    @property
    def oob_enabled(self) -> bool:
        """Independent OOB transport switch.  Public/self-hosted OOB stays enabled by default; setting
        this false disables Nuclei Interactsh, Quarry callback issue/poll, and Dalfox blind OOB without
        disabling local callback-log import or changing the private-target posture."""
        return _flag(self.modes.get("OOB_ENABLED"), True)

    @property
    def verify_secrets(self) -> bool:
        """Opt-in authorized lane: actively verify discovered secrets. Default False — trufflehog's
        default verification sends discovered target credentials to their third-party provider APIs,
        turning offline secret mining into active credential use against a third party (an RoE concern).
        Discovery is unaffected: every secret is found and reported (as unverified) either way. Set true
        only when the engagement authorizes it, which arms verification across all detected providers.
        Strict `is True`: an arming flag must not fail open on quoted YAML."""
        return self.modes.get("SECRET_VERIFICATION", False) is True

    @property
    def blind_xss(self) -> bool:
        """MODES.BLIND_XSS — arm the blind/stored-XSS OOB channel (dalfox `--blind-oob`). Default off.

        Blind XSS persists a payload on the target that fires later, in someone else's browser, and
        phones home to a callback host — a deliberate engagement decision. Reflected and DOM XSS are
        found either way. One gate: arming this is the consent, and `oob.callback_server` (+ optional
        `auth_token`) moves the backend off the public interactsh pool onto your own box.

        Ownership. Correlation is always dalfox's: it mints the nonce, registers, polls and maps it back,
        so findings are recorded `oob_owner: dalfox`. The server depends on the backend — public
        interactsh (Quarry owns nothing; its operator sees the raw callbacks, the same exposure nuclei's
        OAST and Quarry's SSRF probes already accept) or self-hosted (you own the host, Quarry owns
        credential handling: `auth_token` in an ephemeral 0600 `--config` file, never argv).

        Strict `is True`, like every arming flag: it must not fail open on quoted YAML."""
        return self.modes.get("BLIND_XSS", False) is True

    @property
    def headless(self) -> bool:
        return _flag(self.modes.get("HEADLESS"), False)

    @property
    def js_ast(self) -> bool:
        """MODES.JS_AST — the ast-analyzer collection lane, normalised into path/sink observations that
        triage reads. Default off: opt-in, and one bundle can want gigabytes of memory."""
        return _flag(self.modes.get("JS_AST"), False)

    @property
    def screenshots(self) -> bool:
        return _flag(self.modes.get("SCREENSHOTS"), True)

    @property
    def portscan(self) -> bool:
        # gates only the infra port scan (naabu top-1000 over CIDR → nmap -sV), default off so adding
        # CIDR scope can't silently arm it. Not the web-port SYN prefilter, which is always on.
        return _flag(self.modes.get("PORTSCAN"), False)

    @property
    def takeover(self) -> bool:
        return _flag(self.modes.get("TAKEOVER"), True)

    @property
    def content_discovery(self) -> str:
        """Content-discovery intensity: off | light | balanced | deep. Default off (opt-in)."""
        v = self.modes.get("CONTENT_DISCOVERY", "off")
        v = ("off" if v is False else "on" if v is True else str(v)).strip().lower()
        return v if v in ("off", "light", "balanced", "deep") else "off"

    @property
    def content_recursion(self) -> int:
        """Content-discovery recursion depth (separate knob; 0 = off)."""
        v = self.modes.get("CONTENT_RECURSION", 0)
        if v is True:
            return 1
        try:
            return min(MAX_CONTENT_RECURSION, max(0, int(v)))   # load() already range-checks; clamp defensively
        except (TypeError, ValueError):
            return 0

    @property
    def js_chunk_brute(self) -> int:
        """How many chunk ids the JS-chunk analyzer may guess (0 = never, the default).

        Derived chunk names (declared in a bundle's own map) are free processing of evidence in hand;
        guessed integers are new requests to the target and need the operator's consent per engagement."""
        v = self.modes.get("JS_CHUNK_BRUTE", 0)
        if v is True:
            return 1
        # exact int only: `int("50")`/`int(1.9)` would let an unvalidated value authorise manufactured
        # requests.
        return min(MAX_JS_CHUNK_BRUTE, max(0, v)) if type(v) is int else 0

    @property
    def deep_evidence(self) -> bool:
        """Opt-in download of heavy artifacts (actuator heapdump/threaddump/DB dump). Off by default: a
        GET to a heapdump forces server-side generation, so pulling it is deliberate. When off, heavy
        exposures are detected and flagged, never fetched."""
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
        """True when using the built-in full HTTP set (no explicit PORTS.HTTP)."""
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
        # canonicalize + validate every apex (closes the apex→filename path escape), then dedup:
        # `example.com` and `*.example.com` share a root, so keep it once. dict.fromkeys keeps order.
        apexes = list(dict.fromkeys(_canon_domain(d) for d in (raw.get("APEX_DOMAINS") or []) if str(d).strip()))
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
        jcb = (raw.get("MODES") or {}).get("JS_CHUNK_BRUTE", 0)
        jcb = 1 if jcb is True else (0 if jcb is False else jcb)
        if type(jcb) is not int:                       # a float or a quoted string is a typo, not a policy
            raise ProfileError(f"invalid MODES.JS_CHUNK_BRUTE {jcb!r} — an exact int 0-{MAX_JS_CHUNK_BRUTE} "
                               f"or true (every unit of it is a request for a path no bundle named)")
        jcb_i = jcb
        if not 0 <= jcb_i <= MAX_JS_CHUNK_BRUTE:
            raise ProfileError(f"MODES.JS_CHUNK_BRUTE {jcb_i} out of range (0-{MAX_JS_CHUNK_BRUTE}; every "
                               f"guess is a request for a path the bundle never named)")
        # ports: strict int in 1..65535 — a typo'd 99999 / 0 / -1 must fail loud.
        ports = []
        for p in (raw.get("PORTS") or {}).get("HTTP") or []:
            if p in (None, ""):
                continue
            pi = _strict_int(p, f"PORTS.HTTP entry {p!r}")   # rejects bool/float (no true->1 / 80.9->80)
            if not (1 <= pi <= 65535):
                raise ProfileError(f"PORTS.HTTP port {pi} out of range (1-65535)")
            ports.append(pi)
        # rate limits: a present RATELIMIT must be a positive integer — fail loud at load.
        rl = raw.get("RATELIMIT") or {}
        for k in ("HTTP", "DNS", "PORTSCAN"):
            v = rl.get(k)
            if v in (None, ""):
                continue
            if _strict_int(v, f"RATELIMIT.{k}") <= 0:
                raise ProfileError(f"RATELIMIT.{k} must be > 0, got {v!r}")
        # boolean MODES: validate the known flags parse now, before side effects.
        modes = raw.get("MODES") or {}
        for k in ("PASSIVE_ONLY", "BLOCK_PRIVATE_TARGETS", "OOB_ENABLED", "HEADLESS", "SCREENSHOTS",
                  "PORTSCAN", "TAKEOVER"):
            if k in modes:
                _flag(modes[k], False)          # raises ProfileError on an ambiguous value
        # arming flags: a present value must be a bare boolean — a quoted string must fail loud.
        if "SECRET_VERIFICATION" in modes and not isinstance(modes["SECRET_VERIFICATION"], bool):
            raise ProfileError(f"MODES.SECRET_VERIFICATION must be a bare boolean true/false "
                               f"(got {modes['SECRET_VERIFICATION']!r})")
        if "BLIND_XSS" in modes and not isinstance(modes["BLIND_XSS"], bool):
            raise ProfileError(f"MODES.BLIND_XSS must be a bare boolean true/false "
                               f"(got {modes['BLIND_XSS']!r})")
        if "DEEP_EVIDENCE" in modes:
            dv = modes["DEEP_EVIDENCE"]
            if not (isinstance(dv, bool) or str(dv).strip().lower() in _TRUE_STRS | _FALSE_STRS | {"deep"}):
                raise ProfileError(f"MODES.DEEP_EVIDENCE invalid value {dv!r} (use true/false)")
        return cls(
            target=str(raw["TARGET"]).strip(),
            apex_domains=apexes,
            oos=[str(p) for p in (raw.get("OOS") or []) if p],
            cidr=[str(c) for c in (raw.get("CIDR") or []) if c],
            asn=[str(a).strip() for a in (raw.get("ASN") or []) if a],
            ratelimit=rl,
            http_ports=ports,
            modes=modes,
            notes=[str(n) for n in (raw.get("NOTES") or []) if n],
            path=path,
            _raw=raw,
        )
