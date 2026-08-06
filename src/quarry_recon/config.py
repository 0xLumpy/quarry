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
#: ceiling for MODES.JS_CHUNK_BRUTE. Guessing chunk ids MANUFACTURES requests for paths no bundle ever
#: named (measured: 98% of a 3000-guess run is enumeration), so it is an engagement decision with a cage
#: around it — never a machine-wide setting and never something a flag can lift.
MAX_JS_CHUNK_BRUTE = 3000

# ── profile-input validation (T1.7 / C04) — conservative hardening of MALFORMED/DANGEROUS input only;
# it never narrows WHAT can be targeted, only rejects garbage that would otherwise misfire silently. ──
_TRUE_STRS = {"true", "yes", "on", "1"}
_FALSE_STRS = {"false", "no", "off", "0", ""}


def _flag(raw, default: bool) -> bool:
    """Strict boolean coercion for MODES. YAML native `true`/`false` pass through; a QUOTED string is
    PARSED (`"false"` -> False, not `bool("false")` == True — the footgun that could silently flip
    PASSIVE_ONLY on and suppress the whole active scan). `None` -> `default`. Anything ambiguous fails
    LOUD (never fail-open). Does NOT govern arming flags with their own stricter rule (SECRET_VERIFICATION
    stays `is True`)."""
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):                    # YAML 1/0 ONLY (already-bool handled above); 2/-1 are typos
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
    """Integer coercion that does NOT quietly truncate/coerce: rejects bool (a truthy int subclass) and
    float (`80.9`), accepts a real int or a signed-digit string. Prevents `true`->1 / `80.9`->80 slipping
    into a port/rate."""
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


# one DNS label: 1-63 chars, letters/digits/hyphen, no leading/trailing hyphen. Allow a SINGLE-label
# internal zone (e.g. `corp`) — 2+ labels was too strict and narrowed internal-engagement scope.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


def _canon_domain(d: str) -> str:
    """Validate + canonicalize an APEX_DOMAINS entry to a hostname ROOT. A leading `*.` wildcard is
    STRIPPED to its root — Quarry's scope model is root-based (the root matches the bare apex AND every
    subdomain), so `*.example.com` and `example.com` are the same anchor here. Unicode is IDNA2008 / UTS-46
    non-transitional (`faß.de` -> `xn--fa-hia.de`, NOT the builtin codec's transitional `fass.de`, which
    would contact a DIFFERENT domain). Accepts a single-label internal zone; rejects IP literals, path/
    traversal (`/`, `..`), whitespace, and empty labels — also closing the apex->filename path escape.
    Never narrows a legitimate target — only rejects input that could not be a real domain."""
    s = str(d).strip().rstrip(".").lower()
    if s.startswith("*."):
        s = s[2:]                                          # wildcard -> root (already covers subs + bare apex)
    if not s:
        raise ProfileError(f"invalid APEX_DOMAINS entry {d!r} (empty)")
    from . import normalize as _n
    core = _n.idna_ascii(s)                      # shared policy; raising is THIS site's choice
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
        return _flag(self.modes.get("PASSIVE_ONLY"), False)

    @property
    def block_private_targets(self) -> bool:
        """Conservative opt-in: DON'T contact private (RFC1918/CGNAT/ULA) targets. Default False —
        Quarry is offensive, a private-resolving in-scope name is a LEAD (recorded either way) and the
        reachable service is tested to validate ownership. Set true for a paranoid VPS-external posture.
        Scan-box/cloud-metadata destinations are ALWAYS withheld regardless of this flag."""
        return _flag(self.modes.get("BLOCK_PRIVATE_TARGETS"), False)

    @property
    def verify_secrets(self) -> bool:
        """Opt-in authorized lane: actively VERIFY discovered secrets. Default False — trufflehog's
        default verification sends discovered TARGET credentials to their THIRD-PARTY provider APIs
        (github/aws/etc.), turning offline secret mining into active credential use against a third party
        (an RoE/legal concern). This is a DIFFERENT axis from target contact-by-default and does NOT
        suppress discovery: every secret is still found and reported (as unverified) either way. Set true
        only when the engagement explicitly authorizes credential verification — which arms verification
        across ALL detected providers (a per-provider allowlist can be a later refinement).
        Strict `is True` (not bool()): an arming flag must NOT fail open on quoted YAML (`"false"` ->
        disabled) — stricter than the general MODES `_flag` parser (T1.7) which the other booleans use."""
        return self.modes.get("SECRET_VERIFICATION", False) is True

    @property
    def blind_xss(self) -> bool:
        """MODES.BLIND_XSS — arm the blind/stored-XSS OOB channel (dalfox `--blind-oob`).

        Default OFF. Blind XSS PERSISTS a payload on the target that fires later, in someone else's
        browser, and phones home to a callback host — a heavier engagement decision than a reflected
        probe, and one an operator makes deliberately. Discovery is unaffected either way: reflected and
        DOM XSS are found regardless.

        ONE gate, deliberately (Lumpy, 2026-08-06). An earlier version needed a second flag before the
        default PUBLIC interactsh backend could be used. That was inconsistent — nuclei's OAST and
        Quarry's own SSRF probes already use public interactsh ungated — and it put the common case
        (no self-hosted server) behind two flags, which mostly means no blind XSS at all. Arming this IS
        the consent; `oob.interactsh_server` (+ optional `interactsh_token`) moves the backend to your
        own box when you have one.

        Ownership, precisely (review#12 + review#19, Lumpy). CORRELATION is dalfox's in every case: it
        mints the nonce, registers, polls, waits and maps the nonce back to the injection, so findings
        from this channel are recorded `oob_owner: dalfox`, never as Quarry-issued tokens. The SERVER is
        a separate question and depends on the backend:

          * public backend (no `oob.interactsh_server`) — the server is ProjectDiscovery's public
            interactsh pool. Quarry owns NOTHING here: not the host, not the credentials, and the
            operator of that pool sees the raw callbacks, which is the same exposure nuclei's OAST and
            Quarry's own SSRF probes already accept.
          * self-hosted backend — you own the host, and Quarry owns the credential handling for it
            (`interactsh_token` in an ephemeral 0600 `--config` file, never argv).

        Strict `is True`, like every other arming flag: it must not fail open on quoted YAML."""
        return self.modes.get("BLIND_XSS", False) is True

    @property
    def blind_xss_dual(self) -> bool:
        """MODES.BLIND_XSS_DUAL — permit the native OOB channel AND a legacy `-b` collector together.

        Default OFF. dalfox injects a blind payload for EACH channel, so dual mode doubles the blind
        payloads, adds requests and runs two callback lifecycles for one finding. With BLIND_XSS armed
        and `oob.blind_xss_url` also set, the lane REFUSES until this says the duplication is intended
        (review#17, Lumpy). Strict `is True`: an arming flag must not fail open."""
        return self.modes.get("BLIND_XSS_DUAL", False) is True

    @property
    def headless(self) -> bool:
        return _flag(self.modes.get("HEADLESS"), False)

    @property
    def js_ast(self) -> bool:
        """MODES.JS_AST — the ast-analyzer COLLECTION lane. Default off: it publishes artifacts nothing
        reads yet (the observation layer is a later step), and one bundle can want gigabytes of memory
        for a minute and a half."""
        return _flag(self.modes.get("JS_AST"), False)

    @property
    def screenshots(self) -> bool:
        return _flag(self.modes.get("SCREENSHOTS"), True)

    @property
    def portscan(self) -> bool:
        # Gates ONLY the INFRA port scan (naabu top-1000 over CIDR -> nmap -sV) — the weeks-long
        # side-stream. Default OFF: it must be a deliberate opt-in, so adding CIDR scope can't silently
        # arm it. Does NOT gate the web-port SYN prefilter (probe._web_port_prefilter over resolved host
        # IPs -> httpx-on-open-only), which is main-river and always on when naabu is present.
        return _flag(self.modes.get("PORTSCAN"), False)

    @property
    def takeover(self) -> bool:
        return _flag(self.modes.get("TAKEOVER"), True)

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
    def js_chunk_brute(self) -> int:
        """How many chunk ids the JS-chunk analyzer may GUESS (0 = never, the default).

        Derived chunk names — the ones a bundle's own map declares — are free processing of evidence we
        already hold and always run. Guessed integers are new requests to the target, so they need the
        operator's explicit consent per engagement."""
        v = self.modes.get("JS_CHUNK_BRUTE", 0)
        if v is True:
            return 1
        # EXACT int only. `int("50")`/`int(1.9)` would let a value that never passed validation authorise
        # manufactured requests — and this is the one knob where that matters most.
        return min(MAX_JS_CHUNK_BRUTE, max(0, v)) if type(v) is int else 0

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
        # canonicalize + validate every apex (rejects path/traversal/garbage — also closes the
        # apex->filename path escape). Never narrows a legitimate target; only rejects non-domains.
        # DEDUP after canonicalization — `example.com` and `*.example.com` both canonicalize to the same root, so
        # keep it once (else a per-apex loop double-runs it and overwrites its evidence). dict.fromkeys preserves
        # first-seen order.
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
        if type(jcb) is not int:                       # a float or a quoted string is a TYPO, not a policy
            raise ProfileError(f"invalid MODES.JS_CHUNK_BRUTE {jcb!r} — an exact int 0-{MAX_JS_CHUNK_BRUTE} "
                               f"or true (every unit of it is a request for a path no bundle named)")
        jcb_i = jcb
        if not 0 <= jcb_i <= MAX_JS_CHUNK_BRUTE:
            raise ProfileError(f"MODES.JS_CHUNK_BRUTE {jcb_i} out of range (0-{MAX_JS_CHUNK_BRUTE}; every "
                               f"guess is a request for a path the bundle never named)")
        # ports: strict int + valid range (1..65535) — a typo'd 99999 / 0 / -1 must fail loud, not be
        # silently handed to a scanner as a nonsense target.
        ports = []
        for p in (raw.get("PORTS") or {}).get("HTTP") or []:
            if p in (None, ""):
                continue
            pi = _strict_int(p, f"PORTS.HTTP entry {p!r}")   # rejects bool/float (no true->1 / 80.9->80)
            if not (1 <= pi <= 65535):
                raise ProfileError(f"PORTS.HTTP port {pi} out of range (1-65535)")
            ports.append(pi)
        # rate limits: a present RATELIMIT must be a POSITIVE integer — a 0/negative/garbage rate is a
        # footgun (a per-target RoE cap of 0 or a crash mid-run), so fail loud at load.
        rl = raw.get("RATELIMIT") or {}
        for k in ("HTTP", "DNS", "PORTSCAN"):
            v = rl.get(k)
            if v in (None, ""):
                continue
            if _strict_int(v, f"RATELIMIT.{k}") <= 0:
                raise ProfileError(f"RATELIMIT.{k} must be > 0, got {v!r}")
        # boolean MODES: validate the known flags parse now (fail loud BEFORE side effects) — a quoted
        # `"false"` must not silently become True, and a typo like `maybe` must not silently pick a default.
        modes = raw.get("MODES") or {}
        for k in ("PASSIVE_ONLY", "BLOCK_PRIVATE_TARGETS", "HEADLESS", "SCREENSHOTS", "PORTSCAN", "TAKEOVER"):
            if k in modes:
                _flag(modes[k], False)          # raises ProfileError on an ambiguous value
        # ARMING flags (danger lanes): a PRESENT value must be an explicit bare boolean — a quoted string
        # like "true"/"maybe" must fail loud, never silently leave the lane DISABLED against operator intent.
        if "SECRET_VERIFICATION" in modes and not isinstance(modes["SECRET_VERIFICATION"], bool):
            raise ProfileError(f"MODES.SECRET_VERIFICATION must be a bare boolean true/false "
                               f"(got {modes['SECRET_VERIFICATION']!r})")
        for _arm in ("BLIND_XSS", "BLIND_XSS_DUAL"):
            if _arm in modes and not isinstance(modes[_arm], bool):
                raise ProfileError(f"MODES.{_arm} must be a bare boolean true/false "
                                   f"(got {modes[_arm]!r})")
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
