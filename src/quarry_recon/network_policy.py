"""Canonical protected-destination policy and transport-door inventory.

This module deliberately contains no subprocess wrapper and no ambient service
manager dependency.  Native HTTP callers bind an approved literal address.  A
target-facing external tool is admitted only when the fixed runner launcher can
install the inherited seccomp-notification authority implemented by
``network_broker``; the runner integration refuses rather than executing without
that authority.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .oos_regex import OOSRegexError, compile_oos, oos_search


class NetworkPolicyError(RuntimeError):
    """A target transport could not acquire or settle network authority."""


@dataclass(frozen=True)
class TransportDoor:
    source_id: str
    kind: str
    authority_class: str
    profile: str
    argv0: tuple[str, ...]
    helpers: tuple[str, ...]
    descendants: tuple[str, ...]
    required_argv: tuple[str, ...]
    connect_time_peer: bool
    broker_required: bool
    supported: bool
    unsupported_reason: str


AUTHORITY_CLASSES = (
    "target",
    "public-provider",
    "operator-infrastructure",
    "held-control",
    "offline",
)


def _door(source_id: str, kind: str, authority_class: str, profile: str, *,
          argv0=(), helpers=(), descendants=(), required_argv=(),
          connect_time_peer=True, broker_required=True, supported=True,
          unsupported_reason="") -> TransportDoor:
    return TransportDoor(
        source_id, kind, authority_class, profile, tuple(argv0), tuple(helpers),
        tuple(descendants), tuple(required_argv), connect_time_peer,
        broker_required, supported, unsupported_reason,
    )


# This is deliberately keyed by SOURCE_ID, never by executable basename.  A
# basename is not an authority: ffuf has two materially different Host rules,
# smap is a public-provider client rather than a target-IP scanner, and one
# TruffleHog argv shape is offline while another uses discovered credentials.
# Production integration must present both the source id and the exact argv0 or
# native helper to ``transport_door``; an unknown/mismatched pair refuses.
_registered_doors: dict[str, TransportDoor] = {}


def _register(source_ids, kind, authority_class, profile, **kwargs) -> None:
    for source_id in source_ids:
        if source_id in _registered_doors:
            raise RuntimeError(f"duplicate transport source id: {source_id}")
        _registered_doors[source_id] = _door(
            source_id, kind, authority_class, profile, **kwargs,
        )


# Native target transports.  Evidence sublanes are below in the auxiliary
# registry because they are internal acquisition owners rather than entries in
# data/sources.yaml.
_register(("horizontal.csp",), "native-pinned-http", "target",
          "native-target-http", helpers=("fetch.scoped_headers",),
          broker_required=False)
_register(("crawl.js_fetch", "crawl.sourcemaps"), "native-pinned-http", "target",
          "native-target-http", helpers=("fetch.scoped_get",),
          broker_required=False)
_register(("params.redirect_confirm",), "native-pinned-http", "target",
          "native-no-redirect", helpers=("fetch.redirect_location",),
          broker_required=False)
_register(("horizontal.cloud_buckets",), "native-provider-http", "public-provider",
          "cloud-bucket-provider", helpers=("cloud.discover",),
          broker_required=False)

# Quarry-owned provider adapters.  These are public-provider authorities:
# their answers may never inherit the engagement's private-target permission.
for _sid, _helper in {
    "probe.favicon": "probe.shodan_count",
    "probe.cert": "probe.shodan_count",
    "probe.shodan_host": "probe.shodan_host",
    "vertical.censys": "vertical.censys",
    "vertical.certspotter": "vertical.certspotter",
    "vertical.crtsh": "vertical.crtsh",
    "vertical.shosubgo": "vertical.shodan_dns",
}.items():
    _register((_sid,), "native-provider-http", "public-provider",
              "native-public-provider", helpers=(_helper,),
              broker_required=False)

# Target-facing external HTTP/TLS/browser doors.  Redirect-capable tools need
# the pinned per-authority proxy at integration; a union of approved IPs is not
# enough to bind Host/SNI and every redirect.
_register(("content.ffuf",), "external-http", "target", "content-ffuf",
          argv0=("ffuf",))
_register(("probe.ffuf_vhost",), "external-http", "target", "vhost-ffuf",
          argv0=("ffuf",))
_register(("crawl.katana_standard",), "external-http", "target",
          "target-http-proxy", argv0=("katana",), required_argv=("-duc",))
_register(("crawl.katana_headless",), "external-browser", "target",
          "browser-pipe-proxy", argv0=("katana",),
          descendants=("chromium", "chrome_crashpad_handler"), required_argv=("-duc",))
_register(("probe.gowitness", "enrich.gowitness"), "external-browser", "target",
          "browser-pipe-proxy", argv0=("gowitness",),
          descendants=("chromium", "chrome_crashpad_handler"))
_register(("probe.httpx", "enrich.httpx", "vertical.wildcard_http",
           "enrich.wildcard_a1d"), "external-http", "target",
          "target-http-proxy", argv0=("httpx",), required_argv=("-duc",))
_register(("params.arjun",), "external-http", "target", "target-http-proxy",
          argv0=("arjun",))
_register(("params.blind_xss", "params.dalfox", "params.dalfox_xss_fast"),
          "external-http", "target", "target-http-proxy", argv0=("dalfox",))
_register(("params.nuclei_oast", "params.nuclei_scan", "params.nuclei_takeover",
           "probe.nuclei_waf", "enrich.nuclei_waf"), "external-template-http", "target",
          "nuclei-authorized-http", argv0=("nuclei",), required_argv=("-duc",))

# DNS and literal target doors.  puredns' attested massdns child is named here
# explicitly; it is not a second anonymous source.
_register(("dns.dnsx_records", "enrich.dnsx_cname", "enrich.dnsx_resolve",
           "horizontal.revdns"), "external-dns", "target", "target-dns",
          argv0=("dnsx",), required_argv=("-duc",))
_register(("vertical.puredns_brute", "vertical.puredns_resolve",
           "enrich.a1d_brute"), "external-dns", "target", "target-dns",
          argv0=("puredns",), descendants=("massdns",))
_register(("horizontal.tlsx_san", "probe.tlsx_certs"), "external-tls", "target",
          "target-tls", argv0=("tlsx",), required_argv=("-duc",))
_register(("probe.naabu_web", "probe.naabu_infra"), "external-ip", "target",
          "target-connect-scan", argv0=("naabu",),
          required_argv=("-duc", "-scan-type", "c"))
_register(("probe.nmap_service",), "external-ip", "target",
          "target-connect-service", argv0=("nmap",), required_argv=("-sT",))

# Public-provider subprocesses.  These do not gain target-private permission.
_register(("vertical.subfinder",), "external-provider", "public-provider",
          "public-provider", argv0=("subfinder",), required_argv=("-duc",))
_register(("vertical.github_subs",), "external-provider", "public-provider",
          "github-provider", argv0=("github-subdomains",))
_register(("horizontal.asnmap",), "external-provider", "public-provider",
          "public-provider", argv0=("asnmap",), required_argv=("-duc",))
_register(("horizontal.caduceus",), "external-tls", "target",
          "target-cidr-tls", argv0=("caduceus",))
_register(("crawl.gau",), "external-provider", "public-provider",
          "public-provider", argv0=("gau",))
_register(("crawl.waymore_urls", "crawl.waymore_responses"), "external-provider",
          "public-provider", "public-provider", argv0=("waymore",))
_register(("probe.smap", "enrich.smap"), "external-provider", "public-provider",
          "shodan-internetdb-provider", argv0=("smap",))

# The target probe and collector control plane are separate effect identities:
# the target helper must not inherit private/control infrastructure authority.
_register(("params.oob_probe",), "native-pinned-http", "target",
          "native-no-redirect", helpers=("fetch.redirect_location",),
          broker_required=False)

# Local/internal and external offline transforms.  External transforms still
# require the inherited deny-all broker profile: "offline" is a runtime fact,
# not permission to execute an unconfined child.
_register(("horizontal.kaeferjaeger",), "local-corpus", "offline",
          "local-internal", helpers=("horizontal.kaeferjaeger",),
          connect_time_peer=False, broker_required=False)
_register(("origin.correlation",), "local-transform", "offline",
          "local-internal", helpers=("origin.correlation",),
          connect_time_peer=False, broker_required=False)
_register(("horizontal.mapcidr",), "cidr-transform", "offline", "deny-all",
          argv0=("mapcidr",), required_argv=("-duc",), connect_time_peer=False)
_register(("vertical.openintel",), "offline-corpus", "offline", "deny-all",
          argv0=("openintel-subs",), connect_time_peer=False)
_register(("vertical.alterx_permute",), "offline-transform", "offline", "deny-all",
          argv0=("alterx",), required_argv=("-duc",), connect_time_peer=False)
_register(("params.gf",), "offline-transform", "offline", "deny-all",
          argv0=("gf",), connect_time_peer=False)
_register(("crawl.js_beautify",), "offline-transform", "offline", "deny-all",
          argv0=("js-beautify",), connect_time_peer=False)
_register(("crawl.jsluice_urls", "crawl.jsluice_secrets"), "offline-transform",
          "offline", "deny-all", argv0=("jsluice",), connect_time_peer=False)
_register(("crawl.xnlinkfinder",), "offline-transform", "offline", "deny-all",
          argv0=("xnLinkFinder",), connect_time_peer=False)
_register(("crawl.gitleaks",), "offline-transform", "offline", "deny-all",
          argv0=("gitleaks",), connect_time_peer=False)
_register(("crawl.trufflehog",), "offline-transform", "offline", "deny-all",
          argv0=("trufflehog",), required_argv=("--no-update", "--no-verification"),
          connect_time_peer=False)
_register(("crawl.jxscout_ast",), "offline-transform", "offline",
          "unsupported-systemd-sandbox-escape", argv0=("systemd-run",),
          descendants=("sh", "bwrap", "bun"), connect_time_peer=False,
          supported=False,
          unsupported_reason="systemd-run escapes the runner cgroup/filter inheritance")
_register(("crawl.jxscout_chunks",), "offline-transform", "offline",
          "unsupported-nested-sandbox", argv0=("bwrap",),
          descendants=("sh", "node"), connect_time_peer=False, supported=False,
          unsupported_reason="nested namespace setup is not yet in the trusted pre-filter launcher")

REGISTERED_TRANSPORT_DOORS = MappingProxyType(dict(_registered_doors))

# Canonical internal/OSINT/notification transport owners outside the phase
# source registry.  This exception set is exact and tested; no prefix wildcard
# can silently add a new ambient network caller.
_auxiliary_doors = {
    **{
        source_id: _door(source_id, "native-pinned-http", "target",
                         "native-target-http", helpers=("fetch.scoped_get_file",),
                         broker_required=False)
        for source_id in (
            "evidence.exposed_fetch", "evidence.graphql_introspect",
            "evidence.actuator_probe", "evidence.deep_evidence",
            "evidence.openapi", "evidence.framework_probe", "evidence.ssti_probe",
        )
    },
    "osint.asrank": _door("osint.asrank", "native-provider-http", "public-provider",
                           "native-public-provider", helpers=("osint.http",),
                           broker_required=False),
    "osint.azmap": _door("osint.azmap", "native-provider-http", "public-provider",
                          "native-public-provider", helpers=("osint.http",),
                          broker_required=False),
    "osint.whoxy": _door("osint.whoxy", "native-provider-http", "public-provider",
                          "native-public-provider", helpers=("osint.whoxy",),
                          broker_required=False),
    "osint.rdap": _door("osint.rdap", "native-provider-http", "public-provider",
                         "native-public-provider", helpers=("osint.http",),
                         broker_required=False),
    "osint.asnmap": _door("osint.asnmap", "external-provider", "public-provider",
                           "public-provider", argv0=("asnmap",), required_argv=("-duc",)),
    "osint.porch_pirate": _door("osint.porch_pirate", "external-provider",
                                 "public-provider", "public-provider",
                                 argv0=("porch-pirate",)),
    "osint.whois": _door("osint.whois", "external-provider", "public-provider",
                          "provider-referral", argv0=("whois",)),
    "osint.dmarc": _door("osint.dmarc", "external-dns", "target", "target-dns",
                          argv0=("dig",)),
    "probe.cdncheck": _door("probe.cdncheck", "offline-transform", "offline",
                             "deny-all", argv0=("cdncheck",), required_argv=("-duc",),
                             connect_time_peer=False),
    "params.oob_control": _door(
        "params.oob_control", "external-control-plane", "operator-infrastructure",
        "oob-control", argv0=("interactsh-client",), required_argv=("-duc",),
    ),
    **{
        source_id: _door(source_id, "native-control-http", "operator-infrastructure",
                         "operator-channel", helpers=("notify.post",),
                         broker_required=False)
        for source_id in (
            "notify.slack", "notify.discord", "notify.telegram", "notify.webhook",
        )
    },
}
AUXILIARY_TRANSPORT_DOORS = MappingProxyType(dict(_auxiliary_doors))
TRANSPORT_DOORS = MappingProxyType({**_registered_doors, **_auxiliary_doors})
del _sid, _helper

_PROXY_BOUND_PROFILES = frozenset({
    "browser-pipe-proxy", "content-ffuf", "vhost-ffuf",
    "target-http-proxy", "nuclei-authorized-http",
})
_CIDR_PEER_PROFILES = frozenset({
    "target-connect-scan", "target-connect-service", "target-cidr-tls",
})


def broker_transport_semantics(source_id: str, tool: str) -> dict[str, str]:
    """Return canonical source-derived semantics for a serialized broker policy.

    This lookup deliberately cannot be influenced by the child policy payload.
    ``from_json`` repeats it and requires byte-level parity.  DNS permission is
    for Quarry's validating mediator only; it is never part of a tracee's
    ordinary ``connect`` authority.
    """
    if source_id == "run" and tool == "network-policy":
        return {
            "authority_class": "offline",
            "transport_profile": "scope-record",
            "peer_mode": "deny-all",
            "resolver_mode": "none",
        }
    door = TRANSPORT_DOORS.get(source_id)
    if door is None or not door.supported or type(tool) is not str:
        raise NetworkPolicyError("broker source has no canonical transport door")
    if tool == "native-dns":
        if not door.helpers:
            raise NetworkPolicyError("broker DNS mediator source is not native")
    elif not door.argv0 or Path(tool).name not in door.argv0:
        raise NetworkPolicyError("broker tool does not match its transport door")

    if door.authority_class == "offline" or door.profile in _PROXY_BOUND_PROFILES:
        peer_mode = "deny-all"
    elif door.profile == "target-dns":
        # Address-only mediation cannot validate a DNS message/qname.  These
        # subprocess doors remain fail-closed until the dedicated DNS adapter
        # owns their complete wire protocol.
        peer_mode = "deny-all"
    elif door.profile in _CIDR_PEER_PROFILES:
        peer_mode = "effective-cidr"
    elif door.authority_class == "public-provider":
        peer_mode = "public-unicast"
    elif door.authority_class in {"target", "operator-infrastructure"}:
        peer_mode = "approved"
    else:
        peer_mode = "deny-all"

    resolver_mode = (
        "mediated-public"
        if door.authority_class in {"target", "public-provider"}
        and door.authority_class != "offline"
        else "none"
    )
    return {
        "authority_class": door.authority_class,
        "transport_profile": door.profile,
        "peer_mode": peer_mode,
        "resolver_mode": resolver_mode,
    }

PRIVATE_POLICY_ENV = "QUARRY_RUNNER_NETWORK_POLICY"
_proxy_names = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
})
_proxy_flags = frozenset({
    "-proxy", "--proxy", "-http-proxy", "--http-proxy",
    "-socks5", "--socks5", "-socks-proxy", "--socks-proxy",
})
_request_id_re = re.compile(r"[0-9a-f]{32}\Z")
_source_id_re = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z")
_s3_bucket_authority_re = re.compile(
    r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?\.s3\.amazonaws\.com\Z",
)
_public_provider_hosts = MappingProxyType({
    "probe.favicon": ("api.shodan.io",),
    "probe.cert": ("api.shodan.io",),
    "probe.shodan_host": ("api.shodan.io",),
    "vertical.shosubgo": ("api.shodan.io",),
    "vertical.censys": ("api.platform.censys.io",),
    "vertical.certspotter": ("api.certspotter.com",),
    "vertical.crtsh": ("crt.sh",),
    "osint.asrank": ("api.asrank.caida.org",),
    "osint.azmap": ("azmap.dev",),
    "osint.whoxy": ("api.whoxy.com",),
    "osint.rdap": ("rdap.org",),
})
_MAX_TRACE_BYTES = 64 * 1024
_MAX_BROKER_POLICY_BYTES = 48 * 1024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_maximum_control_plane_cidrs = 128
_maximum_effective_cidrs = 4096
_maximum_resolvers = 16


def transport_door(source_id: str, *, argv=None, helper: str | None = None) -> TransportDoor | None:
    """Return an exact source-bound door, or ``None`` for any mismatch.

    Callers must present exactly one transport identity: a complete argv for a
    child, or the canonical native helper name.  Looking up by basename alone
    is intentionally impossible.
    """
    if (type(source_id) is not str or not source_id or "\x00" in source_id
            or _source_id_re.fullmatch(source_id) is None):
        return None
    door = TRANSPORT_DOORS.get(source_id)
    if door is None or not door.supported or (argv is None) == (helper is None):
        return None
    if helper is not None:
        if type(helper) is not str or helper not in door.helpers:
            return None
        return door
    if (type(argv) not in (tuple, list) or not argv
            or any(type(value) is not str or not value or "\x00" in value for value in argv)):
        return None
    if Path(argv[0]).name not in door.argv0:
        return None
    if any(required not in argv for required in door.required_argv):
        return None
    return door


def _canonical_network(value, *, require_canonical: bool = True):
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise NetworkPolicyError("protected network must be canonical CIDR text")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise NetworkPolicyError("protected network must be canonical CIDR text") from exc
    if require_canonical and str(network) != value.lower():
        raise NetworkPolicyError("protected network must be canonical CIDR text")
    return network


def canonical_control_plane_cidrs(values) -> tuple[str, ...]:
    """Validate a finite exact CIDR list; hostnames and implicit masks refuse."""
    if type(values) not in (list, tuple):
        raise NetworkPolicyError("control-plane destinations require canonical CIDRs")
    if len(values) > _maximum_control_plane_cidrs:
        raise NetworkPolicyError("control-plane destination list exceeds its bound")
    networks = [_canonical_network(value) for value in values]
    identities = {
        (network.version, int(network.network_address), network.prefixlen)
        for network in networks
    }
    if len(identities) != len(networks):
        raise NetworkPolicyError("control-plane destination list contains duplicates")
    return tuple(str(network) for network in sorted(
        networks,
        key=lambda item: (item.version, int(item.network_address), item.prefixlen),
    ))


def _exclude_one(network, protected):
    if network.version != protected.version or not network.overlaps(protected):
        return [network]
    if network.subnet_of(protected):
        return []
    if protected.subnet_of(network):
        return list(network.address_exclude(protected))
    raise NetworkPolicyError("network overlap could not be represented exactly")


def subtract_protected_cidrs(cidrs, protected_cidrs) -> tuple[str, ...]:
    """Return a canonical exact partition with protected addresses removed."""
    if type(cidrs) not in (list, tuple):
        raise NetworkPolicyError("engagement CIDRs require a finite list")
    requested = [_canonical_network(value, require_canonical=False) for value in cidrs]
    protected = [_canonical_network(value) for value in protected_cidrs]
    result = []
    for requested_network in requested:
        fragments = [requested_network]
        for denied in protected:
            fragments = [
                piece
                for fragment in fragments
                for piece in _exclude_one(fragment, denied)
            ]
            if len(fragments) > _maximum_effective_cidrs:
                raise NetworkPolicyError("protected CIDR subtraction exceeds its bound")
        result.extend(fragments)
        if len(result) > _maximum_effective_cidrs:
            raise NetworkPolicyError("effective CIDR set exceeds its bound")
    collapsed = [
        network
        for version in (4, 6)
        for network in ipaddress.collapse_addresses(
            item for item in result if item.version == version
        )
    ]
    return tuple(str(network) for network in sorted(
        collapsed,
        key=lambda item: (item.version, int(item.network_address), item.prefixlen),
    ))


def _canonical_bytes(document: dict) -> bytes:
    try:
        body = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NetworkPolicyError("network trace is not canonical JSON") from exc
    if len(body) > _MAX_TRACE_BYTES:
        raise NetworkPolicyError("network trace exceeds its bounded record size")
    return body


def _resolver_snapshot(path: str = "/etc/resolv.conf") -> tuple[str, ...]:
    """Read a bounded literal nameserver snapshot; malformed input refuses."""
    try:
        with open(path, "r", encoding="ascii", errors="strict") as handle:
            body = handle.read(64 * 1024 + 1)
    except (OSError, UnicodeError) as exc:
        raise NetworkPolicyError("resolver configuration is unavailable") from exc
    if len(body) > 64 * 1024 or "\x00" in body:
        raise NetworkPolicyError("resolver configuration exceeds its bound")
    values = []
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] != "nameserver":
            continue
        if len(parts) != 2:
            raise NetworkPolicyError("resolver nameserver entry is malformed")
        value = parts[1]
        if "%" in value:
            raise NetworkPolicyError("resolver nameserver scope ids are forbidden")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise NetworkPolicyError("resolver nameserver must be a literal address") from exc
        if address.is_unspecified or address.is_multicast:
            raise NetworkPolicyError("resolver nameserver address is unusable")
        values.append(str(getattr(address, "ipv4_mapped", None) or address))
    if not values or len(values) > _maximum_resolvers:
        raise NetworkPolicyError("resolver nameserver set is empty or exceeds its bound")
    return tuple(sorted(set(values), key=lambda value: (
        ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)),
    )))


def _public_resolvers(values) -> tuple[str, ...]:
    """Return one exact public resolver set or refuse before any DNS plan."""
    try:
        snapshot = tuple(values)
        if any(type(value) is not str for value in snapshot):
            raise ValueError("resolver is not a string")
        normalized = []
        for value in snapshot:
            address = ipaddress.ip_address(value)
            if (isinstance(address, ipaddress.IPv6Address)
                    and address.scope_id is not None):
                raise ValueError("resolver scope id is not canonical authority")
            normalized.append(str(getattr(address, "ipv4_mapped", None) or address))
        canonical = tuple(sorted(set(normalized), key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        )))
    except (TypeError, ValueError) as exc:
        raise NetworkPolicyError("resolver nameserver set is invalid") from exc
    if (not canonical or len(canonical) > _maximum_resolvers
            or any(not ipaddress.ip_address(value).is_global
                   for value in canonical)):
        raise NetworkPolicyError(
            "mediated-public resolver set contains a non-public address",
        )
    return canonical


def _explicit_resolvers(values) -> tuple[str, ...]:
    """Validate an ambient resolver snapshot as exact DNS-only authority."""
    from . import netguard

    try:
        canonical = netguard.canonical_ip_set(values)
        local_broadcasts = netguard.interface_snapshot().broadcast_ips
        unusable = any(
            ipaddress.ip_address(value).is_unspecified
            or ipaddress.ip_address(value).is_multicast
            or ipaddress.ip_address(value).is_link_local
            or value in local_broadcasts
            or (netguard.is_non_unicast_ip(value)
                and not ipaddress.ip_address(value).is_loopback
                and not netguard.is_private_ip(value))
            for value in canonical
        )
    except (OSError, TypeError, ValueError) as exc:
        raise NetworkPolicyError("resolver nameserver set is invalid") from exc
    if not canonical or len(canonical) > _maximum_resolvers or unusable:
        raise NetworkPolicyError("explicit resolver set contains an unusable address")
    return canonical


@dataclass(frozen=True)
class PeerDecision:
    decision: str
    reason: str
    peer: str
    port: int
    socket_type: int
    protocol: int
    own_ips: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class NetworkInvocation:
    """Parent-local authority claim consumed by the fixed runner worker."""

    def __init__(self, scope, *, request_id: str, source_id: str, tool: str,
                 runtime_identity=None, private_unix_roots=(),
                 approved_peers=()):
        self.scope = scope
        self.request_id = request_id
        self.source_id = source_id
        self.tool = tool
        self._settled = False
        self.policy = scope.broker_policy(
            request_id=request_id, source_id=source_id, tool=tool,
            runtime_identity=runtime_identity,
            private_unix_roots=private_unix_roots,
            approved_peers=approved_peers,
        )

    def attach(self, environment: dict[str, str]) -> dict[str, str]:
        if type(environment) is not dict or PRIVATE_POLICY_ENV in environment:
            raise NetworkPolicyError("network policy environment is not exclusively owned")
        attached = dict(environment)
        attached[PRIVATE_POLICY_ENV] = json.dumps(
            self.policy, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        )
        return attached

    def settle(self, *, decision: str, reason: str, summary: dict | None = None) -> None:
        if self._settled:
            return
        if decision not in {"allow", "deny"} or type(reason) is not str:
            raise NetworkPolicyError("network invocation settlement is invalid")
        self.scope._trace({
            "schema_version": "quarry.network-policy-trace.v1",
            "record_type": "settlement",
            "request_id": self.request_id,
            "source_id": self.source_id,
            "tool": self.tool,
            "decision": decision,
            "reason": reason,
            "authority": {"backend": "seccomp-user-notification-v1"},
            "summary": summary or {},
        })
        self._settled = True


class NetworkPolicyScope:
    """Run-scoped policy, refreshed per effect at the final peer decision."""

    def __init__(self, *, block_private_targets: bool, control_plane_cidrs=(),
                 requested_cidrs=(), apex_domains=(), oos_patterns=(),
                 own_ips=None, resolver_ips=None):
        from . import netguard
        from . import normalize
        from .network_broker import NetworkEffectFence

        if type(block_private_targets) is not bool:
            raise NetworkPolicyError("private-target policy must be an exact boolean")
        self.block_private_targets = block_private_targets
        self.effect_fence = NetworkEffectFence()
        self.control_plane_cidrs = canonical_control_plane_cidrs(
            list(control_plane_cidrs),
        )
        try:
            current_own = netguard.own_ips() if own_ips is None else own_ips
            self.own_ips = netguard.canonical_ip_set(current_own)
        except (OSError, ValueError) as exc:
            raise NetworkPolicyError("scanner interface snapshot is unavailable") from exc
        if not self.own_ips:
            raise NetworkPolicyError("scanner interface snapshot is empty")
        if resolver_ips is None:
            self.resolver_ips = _explicit_resolvers(_resolver_snapshot())
            self.resolver_mode = "mediated-explicit"
        else:
            self.resolver_ips = _public_resolvers(resolver_ips)
            self.resolver_mode = "mediated-public"
        self.protected_cidrs = netguard.protected_cidrs(
            own_ips=self.own_ips,
            control_plane_cidrs=self.control_plane_cidrs,
            block_private=block_private_targets,
        )
        self.requested_cidrs = tuple(
            str(_canonical_network(value, require_canonical=False))
            for value in requested_cidrs
        )
        self.effective_cidrs = subtract_protected_cidrs(
            list(self.requested_cidrs), list(self.protected_cidrs),
        )
        try:
            apexes = tuple(apex_domains)
            patterns = tuple(oos_patterns)
        except TypeError as exc:
            raise NetworkPolicyError("active hostname scope is not finite") from exc
        if len(apexes) > 1024 or len(patterns) > 1024:
            raise NetworkPolicyError("active hostname scope exceeds its bound")
        self.apex_domains = tuple(sorted(set(apexes)))
        if (len(self.apex_domains) != len(apexes)
                or any(type(value) is not str
                       or normalize.canon_host_strict(value) != value
                       for value in self.apex_domains)):
            raise NetworkPolicyError("active apex scope is not canonical")
        self.oos_patterns = tuple(sorted(set(patterns)))
        if len(self.oos_patterns) != len(patterns):
            raise NetworkPolicyError("out-of-scope pattern set contains duplicates")
        for value in self.oos_patterns:
            if (type(value) is not str or not value
                    or len(value.encode("utf-8")) > 4096 or "\x00" in value):
                raise NetworkPolicyError("out-of-scope pattern is invalid")
            try:
                compile_oos(value)
            except OOSRegexError as exc:
                raise NetworkPolicyError("out-of-scope pattern is invalid") from exc
        self._repository = None

    @classmethod
    def from_profile(cls, profile):
        return cls(
            block_private_targets=profile.block_private_targets,
            control_plane_cidrs=getattr(profile, "protected_control_plane_cidrs", ()),
            requested_cidrs=profile.cidr,
            apex_domains=profile.apex_domains,
            oos_patterns=profile.oos,
        )

    def bind(self, repository) -> None:
        if self._repository not in (None, repository):
            raise NetworkPolicyError("network policy is bound to another repository")
        existing = getattr(repository, "_network_policy_scope", None)
        if existing not in (None, self):
            raise NetworkPolicyError("repository already has another network policy")
        setattr(repository, "_network_policy_scope", self)
        self._repository = repository
        self._trace({
            "schema_version": "quarry.network-policy-trace.v1",
            "record_type": "scope",
            "request_id": "0" * 32,
            "source_id": "run",
            "tool": "network-policy",
            "decision": "allow",
            "reason": "protected-destination policy bound before active work",
            "policy": self.broker_policy(
                request_id="0" * 32, source_id="run", tool="network-policy",
            ),
        })

    def _trace(self, document: dict) -> None:
        if self._repository is None:
            raise NetworkPolicyError("network policy trace has no repository authority")
        try:
            self._repository._append_base_artifact(
                ("network-policy.jsonl",), _canonical_bytes(document),
            )
        except BaseException as exc:
            raise NetworkPolicyError("network policy trace could not be persisted") from exc

    def broker_policy(self, *, request_id: str, source_id: str, tool: str,
                      runtime_identity=None, private_unix_roots=(),
                      approved_peers=()) -> dict:
        from . import netguard

        if (_request_id_re.fullmatch(request_id) is None
                or _source_id_re.fullmatch(source_id) is None):
            raise NetworkPolicyError("network invocation identity is invalid")
        semantics = broker_transport_semantics(source_id, tool)
        if semantics["resolver_mode"] == "mediated-public":
            semantics = {**semantics, "resolver_mode": self.resolver_mode}
        control_helpers = []
        control_clients = []
        if runtime_identity is not None:
            if type(runtime_identity) is not dict:
                raise NetworkPolicyError("runtime identity for network policy is invalid")
            identities = runtime_identity.get("identities")
            if type(identities) is not list:
                raise NetworkPolicyError("runtime identity for network policy is invalid")
            for identity in identities:
                if type(identity) is not dict or identity.get("role") not in {"browser", "adapter"}:
                    continue
                executable = identity.get("executable")
                if (type(executable) is not dict
                        or type(executable.get("sha256")) is not str
                        or len(executable["sha256"]) != 64
                        or any(value not in "0123456789abcdef"
                               for value in executable["sha256"])
                        or type(executable.get("bytes")) is not int
                        or not 1 <= executable["bytes"] <= _MAX_EXECUTABLE_BYTES):
                    raise NetworkPolicyError("browser control identity is invalid")
                collection = (
                    control_helpers if identity.get("role") == "browser"
                    else control_clients
                )
                collection.append({
                    "sha256": executable["sha256"], "bytes": executable["bytes"],
                })
        control_helpers = sorted(
            { (item["sha256"], item["bytes"]): item
              for item in control_helpers }.values(),
            key=lambda item: (item["sha256"], item["bytes"]),
        )
        control_clients = sorted(
            { (item["sha256"], item["bytes"]): item
              for item in control_clients }.values(),
            key=lambda item: (item["sha256"], item["bytes"]),
        )
        if type(private_unix_roots) not in (tuple, list) or len(private_unix_roots) > 8:
            raise NetworkPolicyError("private Unix root set is invalid")
        unix_roots = []
        for value in private_unix_roots:
            if (type(value) is not str or not value.startswith("/") or "\x00" in value
                    or value != os.path.normpath(value)
                    or len(os.fsencode(value)) > 4096):
                raise NetworkPolicyError("private Unix root is invalid")
            unix_roots.append(value)
        if len(set(unix_roots)) != len(unix_roots) or unix_roots != sorted(unix_roots):
            raise NetworkPolicyError("private Unix root set is not canonical")
        if tool in {"gowitness", "katana", "nuclei"} and runtime_identity is not None \
                and len(control_helpers) != 1:
            raise NetworkPolicyError("browser transport requires one exact helper identity")
        if type(approved_peers) not in {tuple, list}:
            raise NetworkPolicyError("approved peer set must be finite")
        try:
            approved = netguard.canonical_ip_set(approved_peers)
        except (TypeError, ValueError) as exc:
            raise NetworkPolicyError("approved peer set is invalid") from exc
        if (len(approved) > _maximum_effective_cidrs
                or tuple(approved_peers) != approved):
            raise NetworkPolicyError("approved peer set is not canonical")
        document = {
            "schema_version": "quarry.network-broker-policy.v1",
            "request_id": request_id,
            "source_id": source_id,
            "tool": tool,
            **semantics,
            "block_private_targets": self.block_private_targets,
            "control_plane_cidrs": list(self.control_plane_cidrs),
            "initial_own_ips": list(self.own_ips),
            "resolver_ips": list(self.resolver_ips),
            "apex_domains": list(self.apex_domains),
            "oos_patterns": list(self.oos_patterns),
            "effective_cidrs": list(self.effective_cidrs),
            "approved_peers": list(approved),
            "control_helpers": control_helpers,
            "control_clients": control_clients,
            "private_unix_roots": unix_roots,
            "proxy_inheritance": "disabled",
        }
        try:
            encoded = json.dumps(
                document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise NetworkPolicyError("network broker policy is not canonical JSON") from exc
        if len(encoded) > _MAX_BROKER_POLICY_BYTES:
            raise NetworkPolicyError("network broker policy exceeds its trace envelope")
        return document

    def decide_peer(self, peer: str, port: int, socket_type: int,
                    protocol: int, *, source_id: str) -> PeerDecision:
        """Re-snapshot interfaces and decide one exact kernel peer."""
        from . import netguard

        if (type(port) is not int or not 0 <= port <= 65535
                or isinstance(socket_type, bool) or not isinstance(socket_type, int)
                or isinstance(protocol, bool) or not isinstance(protocol, int)
                or type(source_id) is not str):
            raise NetworkPolicyError("peer socket metadata is invalid")
        socket_type = int(socket_type)
        protocol = int(protocol)
        door = TRANSPORT_DOORS.get(source_id)
        if door is None or not door.helpers:
            raise NetworkPolicyError("native peer source has no exact transport door")
        try:
            normalized = netguard.canonical_ip_set((peer,))
            current_own = netguard.own_ips()
        except (OSError, ValueError) as exc:
            raise NetworkPolicyError("scanner interface refresh failed") from exc
        if len(normalized) != 1 or not current_own:
            raise NetworkPolicyError("peer or scanner interface snapshot is invalid")
        value = normalized[0]
        address = ipaddress.ip_address(value)
        protected = netguard.is_self_attack_ip(
                value, own_ips=current_own,
                control_plane_cidrs=self.control_plane_cidrs)
        base_kind = socket_type & 0xF
        expected_protocol = {
            socket.SOCK_STREAM: {0, socket.IPPROTO_TCP},
            socket.SOCK_DGRAM: {0, socket.IPPROTO_UDP},
        }
        if (base_kind not in expected_protocol
                or protocol not in expected_protocol[base_kind]):
            decision, reason = (
                "deny", "socket type/protocol is outside TCP/UDP policy",
            )
        elif protected:
            decision, reason = "deny", "protected scanner/metadata/control-plane peer"
        elif (address.is_unspecified or address.is_multicast
              or (address.version == 4 and int(address) == 0xFFFFFFFF)):
            decision, reason = "deny", "unspecified/multicast/broadcast peer"
        elif netguard.is_non_unicast_ip(value):
            decision, reason = "deny", "peer is not a unicast target address"
        elif (door.authority_class == "public-provider"
              and netguard.is_private_ip(value)):
            decision, reason = "deny", "public provider resolved to private infrastructure"
        elif door.authority_class not in {"target", "public-provider"}:
            decision, reason = "deny", "native peer authority class is not admitted"
        elif self.block_private_targets and netguard.is_private_ip(value):
            decision, reason = "deny", "private-target opt-out"
        else:
            decision, reason = "allow", "peer admitted by engagement policy"
        return PeerDecision(
            decision, reason, value, port, socket_type, protocol,
            tuple(current_own),
        )

    def host_allowed(self, host: str, *, source_id: str) -> tuple[str, str]:
        """Authorize a native transport authority before any DNS request."""
        from . import normalize

        if (type(host) is not str or type(source_id) is not str
                or _source_id_re.fullmatch(source_id) is None or "%" in host):
            return "deny", "native HTTP authority is not canonical"
        door = TRANSPORT_DOORS.get(source_id)
        if door is None or not door.helpers or not door.supported:
            return "deny", "native HTTP source has no exact transport door"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            canonical = normalize.canon_host_strict(host)
            if canonical is None or canonical != host:
                return "deny", "native HTTP authority is not canonical"
            if source_id == "horizontal.cloud_buckets":
                if (canonical == "storage.googleapis.com"
                        or _s3_bucket_authority_re.fullmatch(canonical) is not None):
                    return "allow", "declared cloud-bucket provider authority"
                return "deny", "authority is outside the cloud-bucket provider policy"
            if door.authority_class == "public-provider":
                if canonical in _public_provider_hosts.get(source_id, ()):
                    return "allow", "declared public-provider authority"
                return "deny", "authority is outside the public-provider policy"
            if door.authority_class != "target":
                return "deny", "native authority class requires an explicit endpoint"
            if not any(canonical == apex or canonical.endswith("." + apex)
                       for apex in self.apex_domains):
                return "deny", "native HTTP authority is outside active apex scope"
            if any(oos_search(pattern, canonical)
                   for pattern in self.oos_patterns):
                return "deny", "native HTTP authority matches an out-of-scope rule"
            return "allow", "native HTTP authority is inside active apex scope"
        if source_id == "horizontal.cloud_buckets":
            return "deny", "literal authority is outside cloud provider policy"
        if door.authority_class != "target":
            return "deny", "literal authority is outside provider/control policy"
        if any(address.version == network.version and address in network
               for network in map(ipaddress.ip_network, self.effective_cidrs)):
            return "allow", "literal authority is inside effective CIDR scope"
        return "deny", "literal authority is outside effective CIDR scope"

    def trace_native_planned(self, *, request_id: str, source_id: str,
                             host: str, answers, approved, denied) -> None:
        self._trace({
            "schema_version": "quarry.network-policy-trace.v1",
            "record_type": "planned",
            "request_id": request_id,
            "source_id": source_id,
            "tool": "native-http",
            "decision": "allow" if approved else "deny",
            "reason": "literal peers resolved and classified before effect",
            "destination": {
                "host": host, "answers": list(answers),
                "approved": list(approved), "denied": list(denied),
            },
        })

    def trace_native_settled(self, *, request_id: str, source_id: str,
                             host: str, decision: str, reason: str,
                             selected_peer: str | None = None) -> None:
        self._trace({
            "schema_version": "quarry.network-policy-trace.v1",
            "record_type": "settlement",
            "request_id": request_id,
            "source_id": source_id,
            "tool": "native-http",
            "decision": decision,
            "reason": reason,
            "destination": {"host": host, "selected_peer": selected_peer},
        })

    # Temporary compatibility name while callers move to the two-state trace.
    def trace_native(self, **kwargs) -> None:
        request_id = kwargs["request_id"]
        self.trace_native_planned(
            request_id=request_id, source_id=kwargs["source_id"], host=kwargs["host"],
            answers=kwargs.get("answers", ()), approved=kwargs.get("approved", ()),
            denied=kwargs.get("denied", ()),
        )
        self.trace_native_settled(
            request_id=request_id, source_id=kwargs["source_id"], host=kwargs["host"],
            decision=kwargs["decision"], reason=kwargs["reason"],
            selected_peer=kwargs.get("selected_peer"),
        )

    def prepare_invocation(self, *, request_id: str, source_id: str, tool: str,
                           argv, environment, timeout=None, runtime_identity=None,
                           private_unix_roots=(), approved_peers=None) -> NetworkInvocation:
        del timeout
        door = transport_door(source_id, argv=argv)
        if door is None or not door.broker_required:
            raise NetworkPolicyError(
                "source/argv is not an exact broker-enforced transport door",
            )
        if (type(argv) not in (tuple, list) or not argv
                or any(type(value) is not str or "\x00" in value for value in argv)
                or type(environment) is not dict
                or type(tool) is not str or Path(tool).name != Path(argv[0]).name):
            raise NetworkPolicyError("network invocation inputs are invalid")
        if _proxy_names.intersection(environment):
            raise NetworkPolicyError("ambient proxy configuration is forbidden")
        for value in argv:
            if value.split("=", 1)[0] in _proxy_flags:
                raise NetworkPolicyError("tool proxy flags are forbidden")
        if approved_peers is None:
            raise NetworkPolicyError(
                "network invocation lacks a pre-resolved approved peer set",
            )
        invocation = NetworkInvocation(
            self, request_id=request_id, source_id=source_id,
            tool=Path(tool).name, runtime_identity=runtime_identity,
            private_unix_roots=private_unix_roots,
            approved_peers=approved_peers,
        )
        self._trace({
            "schema_version": "quarry.network-policy-trace.v1",
            "record_type": "planned",
            "request_id": request_id,
            "source_id": source_id,
            "tool": Path(tool).name,
            "decision": "allow",
            "reason": "seccomp broker authority required before target exec",
            "authority": {"backend": "seccomp-user-notification-v1"},
        })
        return invocation


def new_request_id() -> str:
    return secrets.token_hex(16)


def scope_for(repository) -> NetworkPolicyScope | None:
    scope = getattr(repository, "_network_policy_scope", None)
    return scope if type(scope) is NetworkPolicyScope else None
