"""Run-scoped Nuclei corpus, accepted-policy, and provenance authority.

All four Nuclei owners consume one detached template/config snapshot.  The immutable policy artifact
describes the exact executable identity, complete corpus closure, selected-template inventory, helpers,
flags, rates, private-target posture, and OOB posture.  Its digest is the coverage identity callers fold
into work units and resume state.
"""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import stat
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import budget, events, runtime_identity, secrets, settings, store


SCHEMA_VERSION = "quarry.nuclei-policy.v1"
POLICY_ID = "quarry.broad-active-verification.v1"
OWNERS = (
    "probe.nuclei_waf",
    "enrich.nuclei_waf",
    "params.nuclei_takeover",
    "params.nuclei_scan",
)
OOB_CHANNELS = (
    "params.oob_probe",
    "quarry.oob_poll",
    "params.dalfox_blind_oob",
    "quarry.oob_import",
)

_MAIN_SEVERITIES = ("critical", "high", "medium")
_MAIN_EXCLUDED_TAGS = ("intrusive", "fuzz", "dos", "brute-force")
_SUPPORTED_TEMPLATE_SUFFIXES = frozenset({".yaml", ".json"})
_ENGINE_MISC_DIRECTORIES = frozenset({".git", ".github", "helpers"})
_ENGINE_CONFIG_FILES = frozenset({"cves.json", "contributors.json", "TEMPLATES-STATS.json"})
_LOAD_BLOCKING_CAPABILITIES = (
    "headless", "code", "javascript", "dast", "self-contained", "file",
)
_POLICY_ARTIFACT = "raw/nuclei-policy/policy.json"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(rb"(?m)^#\s*digest:\s*[^\r\n]+\s*$")
_RISK_WORD_RE = re.compile(
    rb"(?i)\b(?:upload|write|delete|remove|create|update|modify|execute|execution|command|"
    rb"cmd|configuration|state[-_ ]?chang(?:e|ing))\b",
)
_HELPER_SUFFIXES = frozenset({
    ".yaml", ".yml", ".json", ".jsonl", ".txt", ".js", ".py", ".sh", ".go", ".wasm",
    ".bin", ".dat", ".xml", ".html", ".md",
})

# Parser/resource limits are deliberately aligned with the runtime tree attestation and kept private to
# this evidence parser (they are integrity bounds, not operator coverage knobs).
_tree_file_bound = runtime_identity._max_dynamic_files
_tree_byte_bound = runtime_identity._max_dynamic_bytes
_tree_depth_bound = 64
_yaml_byte_bound = 16 * 1024 * 1024
_yaml_node_bound = 2_000_000
_yaml_alias_bound = 10_000
_yaml_depth_bound = 96
_yaml_event_loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_semantic_classifier = "quarry.nuclei-semantic-risk.v1"
_semantic_classes = ("not_detected", "potentially_state_changing", "unknown")
_selected_template_fields = (
    "id", "path", "sha256", "severity", "tags", "signature_state",
    "signature_marker_digest", "semantic_class", "semantic_reasons",
)


class NucleiPolicyError(RuntimeError):
    """The exact Nuclei policy cannot be constructed, verified, or applied."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8", "strict")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _regular_file(path: Path, *, byte_bound: int, collect: bool
                  ) -> tuple[bytes | None, str, int, os.stat_result]:
    """Read/hash one stable no-follow file without ever crossing an admitted byte bound."""
    before = path.lstat()
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise NucleiPolicyError(f"Nuclei policy input cannot be opened safely: {path}") from exc
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise NucleiPolicyError(f"Nuclei policy input identity changed before read: {path}")
        if opened.st_size > byte_bound:
            raise NucleiPolicyError(f"Nuclei policy input exceeds its offline byte bound: {path}")
        chunks: list[bytes] | None = [] if collect else None
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > byte_bound:
                raise NucleiPolicyError(f"Nuclei policy input exceeds its offline byte bound: {path}")
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        named = path.lstat()
    except OSError as exc:
        raise NucleiPolicyError(f"Nuclei policy input disappeared during read: {path}") from exc
    identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key)
           or getattr(after, key) != getattr(named, key) for key in identity_fields):
        raise NucleiPolicyError(f"Nuclei policy input changed during inventory: {path}")
    if size != after.st_size:
        raise NucleiPolicyError(f"Nuclei policy input length changed during inventory: {path}")
    return (b"".join(chunks) if chunks is not None else None,
            digest.hexdigest(), size, after)


def _regular_bytes(path: Path, *, byte_bound: int) -> tuple[bytes, os.stat_result]:
    """Read one stable regular file only after its descriptor size is admitted."""
    data, _digest, _size, identity = _regular_file(
        path, byte_bound=byte_bound, collect=True,
    )
    assert data is not None
    return data, identity


def _file_row(root: Path, path: Path, *, byte_bound: int) -> dict:
    observed = path.lstat()
    relative = path.relative_to(root).as_posix()
    if stat.S_ISREG(observed.st_mode):
        _data, digest, size, _identity = _regular_file(
            path, byte_bound=byte_bound, collect=False,
        )
        return {"bytes": size, "kind": "file", "path": relative,
                "sha256": "sha256:" + digest}
    if stat.S_ISLNK(observed.st_mode):
        target = os.readlink(path).encode("utf-8", "strict")
        try:
            path.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise NucleiPolicyError(f"Nuclei corpus contains an escaping helper alias: {relative}") from exc
        if len(target) > byte_bound:
            raise NucleiPolicyError("Nuclei tree exceeds its offline file/byte bound")
        return {"bytes": len(target), "kind": "symlink", "path": relative,
                "sha256": _sha256(target)}
    raise NucleiPolicyError(f"Nuclei corpus contains an unsupported object: {relative}")


def _inventory(root: Path) -> list[dict]:
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise NucleiPolicyError(f"Nuclei snapshot is unavailable: {root}") from exc
    rows, objects, total = [], 0, 0
    for path in root.rglob("*"):
        objects += 1
        if objects > _tree_file_bound:
            raise NucleiPolicyError("Nuclei tree exceeds its offline object bound")
        relative = path.relative_to(root)
        if len(relative.parts) > _tree_depth_bound:
            raise NucleiPolicyError(f"Nuclei tree exceeds its path-depth bound: {relative.as_posix()}")
        if path.is_dir() and not path.is_symlink():
            continue
        remaining = _tree_byte_bound - total
        if remaining < 0:
            raise NucleiPolicyError("Nuclei tree exceeds its offline file/byte bound")
        row = _file_row(root, path, byte_bound=remaining)
        total += row["bytes"]
        if len(rows) >= _tree_file_bound or total > _tree_byte_bound:
            raise NucleiPolicyError("Nuclei tree exceeds its offline file/byte bound")
        rows.append(row)
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    return rows


def _inventory_bytes(root: Path, row: dict, *, yaml_input: bool = False) -> bytes:
    if row.get("kind") != "file":
        raise NucleiPolicyError(f"Nuclei policy cannot parse an aliased input: {row.get('path')}")
    data, _identity = _regular_bytes(
        root / row["path"], byte_bound=min(
            row["bytes"], _yaml_byte_bound if yaml_input else row["bytes"],
        ),
    )
    if len(data) != row["bytes"] or _sha256(data) != row["sha256"]:
        raise NucleiPolicyError(f"Nuclei policy input changed after inventory: {row['path']}")
    return data


class _BoundedSafeLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._quarry_nodes = 0
        self._quarry_aliases = 0
        self._quarry_depth = 0

    def compose_node(self, parent, index):
        self._quarry_nodes += 1
        self._quarry_depth += 1
        try:
            if self._quarry_nodes > _yaml_node_bound:
                raise NucleiPolicyError("Nuclei YAML exceeds its offline node bound")
            if self._quarry_depth > _yaml_depth_bound:
                raise NucleiPolicyError("Nuclei YAML exceeds its offline depth bound")
            if self.check_event(yaml.AliasEvent):
                self._quarry_aliases += 1
                if self._quarry_aliases > _yaml_alias_bound:
                    raise NucleiPolicyError("Nuclei YAML exceeds its alias bound")
            return super().compose_node(parent, index)
        finally:
            self._quarry_depth -= 1


def _validate_yaml_graph(value: object) -> None:
    active: set[int] = set()
    seen: set[int] = set()
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _yaml_node_bound or depth > _yaml_depth_bound:
            raise NucleiPolicyError("Nuclei YAML expands beyond its offline graph bound")
        if not isinstance(item, (dict, list, tuple, set)):
            return
        identity = id(item)
        if identity in active:
            raise NucleiPolicyError("Nuclei YAML contains a recursive alias")
        if identity in seen:
            return
        seen.add(identity)
        active.add(identity)
        try:
            children = item.items() if isinstance(item, dict) else enumerate(item)
            for key, child in children:
                visit(key, depth + 1)
                visit(child, depth + 1)
        finally:
            active.remove(identity)

    visit(value, 0)


def _load_yaml(raw: bytes, *, label: str) -> object:
    try:
        document = yaml.load(raw, Loader=_BoundedSafeLoader)
        _validate_yaml_graph(document)
        return document
    except NucleiPolicyError as exc:
        raise NucleiPolicyError(f"{exc}: {label}") from exc
    except (UnicodeError, yaml.YAMLError) as exc:
        raise NucleiPolicyError(f"Nuclei YAML cannot be inventoried offline: {label}") from exc


def _load_json(raw: bytes, *, label: str) -> object:
    def invalid_constant(value: str):
        raise ValueError(f"invalid JSON constant {value}")

    try:
        document = json.loads(raw.decode("utf-8", "strict"), parse_constant=invalid_constant)
        _validate_yaml_graph(document)
        return document
    except NucleiPolicyError as exc:
        raise NucleiPolicyError(f"{exc}: {label}") from exc
    except (UnicodeError, ValueError, RecursionError, MemoryError) as exc:
        raise NucleiPolicyError(f"Nuclei JSON cannot be inventoried offline: {label}") from exc


def _validate_yaml_stream(raw: bytes, *, label: str) -> None:
    """Validate all YAML bytes without materializing an unselected template graph.

    Selection only needs a template's top-level metadata, but syntax and resource safety apply to the
    entire installed corpus.  PyYAML's event stream keeps giant matcher tables out of memory while still
    giving us exact node, alias and nesting accounting.  Active-anchor tracking rejects recursive aliases
    even when the template is excluded by accepted-policy tags and would never reach ``_load_yaml``.
    """
    nodes = aliases = depth = documents = 0
    defined_anchors: set[str] = set()
    active_anchors: set[str] = set()
    container_anchors: list[str | None] = []
    try:
        for event in yaml.parse(raw, Loader=_yaml_event_loader):
            if isinstance(event, yaml.events.DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise NucleiPolicyError("Nuclei YAML contains multiple documents")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent,
                                  yaml.events.ScalarEvent, yaml.events.AliasEvent)):
                nodes += 1
                if nodes > _yaml_node_bound:
                    raise NucleiPolicyError("Nuclei YAML exceeds its offline node bound")
            if isinstance(event, yaml.events.AliasEvent):
                aliases += 1
                if aliases > _yaml_alias_bound:
                    raise NucleiPolicyError("Nuclei YAML exceeds its alias bound")
                if event.anchor not in defined_anchors:
                    raise NucleiPolicyError("Nuclei YAML contains an undefined alias")
                if event.anchor in active_anchors:
                    raise NucleiPolicyError("Nuclei YAML contains a recursive alias")
            elif isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent,
                                    yaml.events.ScalarEvent)):
                anchor = event.anchor
                if anchor is not None:
                    if anchor in defined_anchors:
                        raise NucleiPolicyError("Nuclei YAML contains a duplicate anchor")
                    defined_anchors.add(anchor)
                if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                    depth += 1
                    if depth > _yaml_depth_bound:
                        raise NucleiPolicyError("Nuclei YAML exceeds its offline depth bound")
                    container_anchors.append(anchor)
                    if anchor is not None:
                        active_anchors.add(anchor)
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                if not container_anchors:
                    raise NucleiPolicyError("Nuclei YAML container nesting is malformed")
                anchor = container_anchors.pop()
                if anchor is not None:
                    active_anchors.remove(anchor)
                depth -= 1
        if depth or container_anchors:
            raise NucleiPolicyError("Nuclei YAML container nesting is incomplete")
    except NucleiPolicyError as exc:
        raise NucleiPolicyError(f"{exc}: {label}") from exc
    except (UnicodeError, yaml.YAMLError) as exc:
        raise NucleiPolicyError(f"Nuclei YAML cannot be inventoried offline: {label}") from exc


def _tags(value: object) -> set[str]:
    if isinstance(value, str):
        return {item.strip().lower() for item in value.split(",") if item.strip()}
    if isinstance(value, list):
        return {str(item).strip().lower() for item in value if str(item).strip()}
    return set()


def _resolve_helper_reference(template_relative: str, text: str, inventory: dict[str, dict],
                              *, required: bool) -> str | None:
    """Resolve one engine-visible helper reference without guessing between ancestor roots."""
    text = text.strip().strip("'\"")
    unsafe = (not text or "\n" in text or "\r" in text or "{{" in text or "://" in text
              or "\x00" in text or Path(text).is_absolute())
    if unsafe:
        if required:
            raise NucleiPolicyError(
                f"Nuclei template {template_relative} has an unsafe/unresolved helper reference: {text!r}"
            )
        return None
    if not required and Path(text).suffix.lower() not in _HELPER_SUFFIXES and "/" not in text:
        return None
    candidate = Path(text)
    base = Path(template_relative).parent
    matches: set[str] = set()
    while True:
        relative = posixpath.normpath((base / candidate).as_posix())
        if relative not in {"", ".", ".."} and not relative.startswith("../"):
            row = inventory.get(relative)
            if row is not None and row.get("kind") == "file":
                matches.add(relative)
        if not base.parts:
            break
        base = base.parent
    if len(matches) > 1:
        raise NucleiPolicyError(
            f"Nuclei template {template_relative} has an ambiguous helper reference {text!r}: "
            + ", ".join(sorted(matches))
        )
    if not matches:
        if required:
            raise NucleiPolicyError(
                f"Nuclei template {template_relative} has an unresolved helper reference: {text!r}"
            )
        return None
    return next(iter(matches))


def _collect_helper_path(template_relative: str, raw: str, inventory: dict[str, dict],
                         found: set[str], *, required: bool = False) -> None:
    explicit = re.findall(r"(?:file|readFile)\(\s*['\"]([^'\"]+)['\"]\s*\)", raw)
    for text in explicit:
        resolved = _resolve_helper_reference(
            template_relative, text, inventory, required=True,
        )
        assert resolved is not None
        found.add(resolved)
    # A scalar payload value is a filename in the pinned engine.  Other scalar values are only treated as
    # helpers when their whole value has the shape of a relative file reference.
    if required or not explicit:
        resolved = _resolve_helper_reference(
            template_relative, raw, inventory, required=required,
        )
        if resolved is not None:
            found.add(resolved)


def _payload_file_references(document: object):
    """Yield the pinned engine's scalar payload-file references; list payloads are inline values."""
    for key, value in _walk_items(document):
        if key != "payloads" or not isinstance(value, dict):
            continue
        for payload in value.values():
            if isinstance(payload, str):
                yield payload


def _walk_scalars(value: object):
    seen: set[int] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _yaml_node_bound or depth > _yaml_depth_bound:
            raise NucleiPolicyError("Nuclei helper graph exceeds its offline bound")
        if isinstance(item, str):
            yield item
            continue
        if not isinstance(item, (dict, list, tuple)):
            continue
        identity = id(item)
        if identity in seen:
            continue
        seen.add(identity)
        children = list(item.values()) if isinstance(item, dict) else list(item)
        stack.extend((child, depth + 1) for child in reversed(children))


def _walk_items(value: object):
    seen: set[int] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _yaml_node_bound or depth > _yaml_depth_bound:
            raise NucleiPolicyError("Nuclei semantic graph exceeds its offline bound")
        if not isinstance(item, (dict, list, tuple)):
            continue
        identity = id(item)
        if identity in seen:
            continue
        seen.add(identity)
        if isinstance(item, dict):
            pairs = list(item.items())
            for key, child in pairs:
                yield str(key).strip().lower().replace("_", "-"), child
            stack.extend((child, depth + 1) for _key, child in reversed(pairs))
        else:
            stack.extend((child, depth + 1) for child in reversed(item))


def _required_load_capabilities(document: dict) -> list[str]:
    """Mirror the v3.11 load-blocking capability gates used by the accepted argv."""
    required: set[str] = set()
    if isinstance(document.get("headless"), list) and document["headless"]:
        required.add("headless")
    if isinstance(document.get("code"), list) and document["code"]:
        required.add("code")
    if isinstance(document.get("javascript"), list) and document["javascript"]:
        required.add("javascript")
    if isinstance(document.get("file"), list) and document["file"]:
        required.add("file")
    if document.get("self-contained") is True:
        required.add("self-contained")

    request_sections = []
    for name in ("http", "requests", "headless", "network", "tcp"):
        value = document.get(name)
        if isinstance(value, list):
            request_sections.extend(value)
    for key, value in _walk_items(request_sections):
        if key == "fuzzing" and value not in (None, False, [], {}):
            required.add("dast")
        if key == "self-contained" and value is True:
            required.add("self-contained")
    return [name for name in _LOAD_BLOCKING_CAPABILITIES if name in required]


def _semantic_risk(raw: bytes, document: dict | None = None) -> tuple[str, list[str]]:
    """Versioned, deliberately non-blocking request-semantic telemetry.

    This classifier never narrows selection.  It flags explicit risk indicators and uses ``unknown``
    when a template exposes no request shape that the v1 heuristic understands; absence of an indicator
    is not represented as a safety claim.
    """
    reasons: set[str] = set()
    lowered = raw.lower()
    if b"interactsh-url" in lowered:
        reasons.add("oast_placeholder")
    if _RISK_WORD_RE.search(lowered):
        reasons.add("mutation_or_command_term")

    keys = {
        match.group(1).decode("ascii").lower().replace("_", "-")
        for match in re.finditer(rb"(?mi)^[ \t-]*([a-z][a-z0-9_-]*)[ \t]*:", raw)
    }
    parsed_items = list(_walk_items(document)) if isinstance(document, dict) else []
    keys.update(key for key, _value in parsed_items)
    recognized_keys = {"http", "requests", "dns", "tcp", "network", "ssl", "websocket", "whois"}
    dynamic_keys = {"headless", "code", "javascript"}
    recognized = bool(keys & (recognized_keys | dynamic_keys))
    dynamic = bool(keys & (dynamic_keys | {"flow", "workflows"}))
    for match in re.finditer(rb"(?mi)^[ \t-]*method[ \t]*:[ \t]*([^\r\n#]+)", raw):
        methods = {value.decode("ascii", "ignore").strip(" []'\"").upper()
                   for value in match.group(1).split(b",")}
        if any(method and method not in {"GET", "HEAD", "OPTIONS"} for method in methods):
            reasons.add("non_read_method")
    for key, value in parsed_items:
        if key == "method":
            methods = value if isinstance(value, list) else [value]
            if any(str(method).strip().upper() not in {"GET", "HEAD", "OPTIONS"}
                   for method in methods if str(method).strip()):
                reasons.add("non_read_method")
    if re.search(rb"(?mi)^[ \t-]*(?:body|raw)[ \t]*:[ \t]*\S", raw):
        reasons.add("request_body_or_raw_request")
    if any(key in {"body", "raw"} and value not in (None, "", [], {})
           for key, value in parsed_items):
        reasons.add("request_body_or_raw_request")
    if dynamic:
        reasons.add("dynamic_or_workflow_semantics")
    ordered = sorted(reasons)
    if ordered:
        return "potentially_state_changing", ordered
    if not recognized:
        return "unknown", ["unclassified_request_shape"]
    return "not_detected", []


def _template_metadata(raw: bytes, *, label: str) -> dict | None:
    """Stream top-level YAML metadata, falling back to a bounded graph only for aliases/complex keys."""
    _validate_yaml_stream(raw, label=label)
    stack: list[dict] = []
    root_mapping = False
    fallback = False
    template_id: str | None = None
    info_mapping = False
    severity: str | None = None
    tags: str | list[str] | None = None
    tag_items: list[str] = []

    def value_path(frame: dict) -> tuple:
        if frame["kind"] == "map":
            return (*frame["path"], frame["pending"])
        return (*frame["path"], frame["index"])

    def complete(frame: dict) -> None:
        if frame["kind"] == "map":
            frame["expect_key"] = True
            frame["pending"] = None
        else:
            frame["index"] += 1

    try:
        for event in yaml.parse(raw, Loader=_yaml_event_loader):
            if isinstance(event, yaml.events.AliasEvent):
                fallback = True
                continue
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                kind = "map" if isinstance(event, yaml.events.MappingStartEvent) else "seq"
                if not stack:
                    path = ()
                    root_mapping = kind == "map"
                else:
                    parent = stack[-1]
                    if parent["kind"] == "map" and parent["expect_key"]:
                        fallback = True
                        path = (*parent["path"], "<complex-key>")
                    else:
                        path = value_path(parent)
                if path == ("info",) and kind == "map":
                    info_mapping = True
                if path == ("info", "tags") and kind == "seq":
                    tags = tag_items
                stack.append({"kind": kind, "path": path, "expect_key": kind == "map",
                              "pending": None, "index": 0})
                continue
            if isinstance(event, yaml.events.ScalarEvent) and stack:
                frame = stack[-1]
                if frame["kind"] == "map" and frame["expect_key"]:
                    frame["pending"] = event.value
                    frame["expect_key"] = False
                    continue
                path = value_path(frame)
                if path == ("id",):
                    template_id = event.value
                elif path == ("info", "severity"):
                    severity = event.value
                elif path == ("info", "tags"):
                    tags = event.value
                elif len(path) == 3 and path[:2] == ("info", "tags"):
                    tag_items.append(event.value)
                complete(frame)
                continue
            if isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)) and stack:
                stack.pop()
                if stack:
                    complete(stack[-1])
    except (UnicodeError, yaml.YAMLError) as exc:
        raise NucleiPolicyError(f"Nuclei YAML cannot be inventoried offline: {label}") from exc

    if fallback:
        document = _load_yaml(raw, label=label)
        if not isinstance(document, dict) or not isinstance(document.get("info"), dict):
            return None
        return document
    if not root_mapping or template_id is None or not info_mapping:
        return None
    return {"id": template_id, "info": {"severity": severity, "tags": tags}}


def _engine_template_path(path: str) -> bool:
    relative = Path(path)
    lowered = [part.lower() for part in relative.parts]
    return (relative.suffix.lower() in _SUPPORTED_TEMPLATE_SUFFIXES
            and not any(name in relative.name for name in _ENGINE_CONFIG_FILES)
            and not any(part in _ENGINE_MISC_DIRECTORIES for part in lowered[:-1]))


def _engine_path_match(path: str, pattern: str) -> bool:
    """Match the pinned engine's ``filepath.Match`` path semantics on detached POSIX paths."""
    def component(candidate: str, selector: str) -> bool:
        tokens: list[tuple] = []
        index = 0
        while index < len(selector):
            char = selector[index]
            index += 1
            if char == "*":
                if not tokens or tokens[-1][0] != "star":
                    tokens.append(("star",))
            elif char == "?":
                tokens.append(("any",))
            elif char == "\\":
                if index >= len(selector):
                    return False
                tokens.append(("literal", selector[index]))
                index += 1
            elif char == "[":
                negated = index < len(selector) and selector[index] == "^"
                if negated:
                    index += 1
                ranges: list[tuple[str, str]] = []
                while True:
                    if index >= len(selector):
                        return False
                    if selector[index] == "]" and ranges:
                        index += 1
                        break

                    def class_char(at: int) -> tuple[str, int] | None:
                        if at >= len(selector) or selector[at] in "-]":
                            return None
                        if selector[at] == "\\":
                            at += 1
                            if at >= len(selector):
                                return None
                        return selector[at], at + 1

                    parsed = class_char(index)
                    if parsed is None:
                        return False
                    low, index = parsed
                    high = low
                    if index < len(selector) and selector[index] == "-":
                        parsed = class_char(index + 1)
                        if parsed is None:
                            return False
                        high, index = parsed
                    ranges.append((low, high))
                tokens.append(("class", negated, tuple(ranges)))
            else:
                tokens.append(("literal", char))

        reachable = {0}
        for token in tokens:
            if token[0] == "star":
                reachable = set(range(min(reachable), len(candidate) + 1)) if reachable else set()
                continue
            advanced: set[int] = set()
            for offset in reachable:
                if offset >= len(candidate):
                    continue
                observed = candidate[offset]
                if token[0] == "any":
                    matched = True
                elif token[0] == "literal":
                    matched = observed == token[1]
                else:
                    in_range = any(low <= observed <= high for low, high in token[2])
                    matched = in_range != token[1]
                if matched:
                    advanced.add(offset + 1)
            reachable = advanced
        return len(candidate) in reachable

    path_parts = path.split("/")
    pattern_parts = pattern.split("/")
    return (len(path_parts) == len(pattern_parts)
            and all(component(part, selector)
                    for part, selector in zip(path_parts, pattern_parts)))


def _basic_eligible(row: dict) -> bool:
    return ((row["severity"] in _MAIN_SEVERITIES
             and not set(row["tags"]) & set(_MAIN_EXCLUDED_TAGS))
            or "takeover" in row["tags"] or "waf" in row["tags"])


def _ignored(row: dict, ignore: dict) -> bool:
    return (row["path"] in set(ignore["resolved_files"])
            or bool(set(row["tags"]) & set(ignore["tags"])))


def _template_rows(root: Path, inventory: list[dict], ignore: dict) -> list[dict]:
    by_path = {row["path"]: row for row in inventory}
    templates: list[dict] = []
    for relative in sorted(path for path, row in by_path.items()
                           if row["kind"] == "file"
                           and _engine_template_path(path)):
        raw = _inventory_bytes(root, by_path[relative], yaml_input=True)
        suffix = Path(relative).suffix.lower()
        parsed = _load_json(raw, label=relative) if suffix == ".json" else None
        metadata = (parsed if suffix == ".json" else _template_metadata(raw, label=relative))
        marker = _SIGNATURE_RE.search(raw)
        if not isinstance(metadata, dict) or not isinstance(metadata.get("info"), dict):
            templates.append({
                "id": relative,
                "path": relative,
                "bytes": by_path[relative]["bytes"],
                "sha256": by_path[relative]["sha256"],
                "severity": "unknown",
                "tags": [],
                "signature_state": "digest-marker-present-unverified" if marker else "unsigned",
                "signature_marker_digest": _sha256(marker.group(0)) if marker else None,
                "load_state": "metadata-rejected",
                "required_capabilities": [],
                "semantic_class": "unknown",
                "semantic_reasons": ["metadata-rejected"],
                "helper_paths": [],
            })
            continue
        info = metadata["info"]
        severity = str(info.get("severity") or "unknown").strip().lower()
        tags = sorted(_tags(info.get("tags")))
        row = {
            "id": str(metadata.get("id") or relative),
            "path": relative,
            "bytes": by_path[relative]["bytes"],
            "sha256": by_path[relative]["sha256"],
            "severity": severity,
            "tags": tags,
            "signature_state": "digest-marker-present-unverified" if marker else "unsigned",
            "signature_marker_digest": _sha256(marker.group(0)) if marker else None,
            "load_state": "loaded",
        }
        document = parsed if parsed is not None else _load_yaml(raw, label=relative)
        if not isinstance(document, dict) or not isinstance(document.get("info"), dict):
            continue
        required_capabilities = _required_load_capabilities(document)
        row["load_state"] = "load-excluded" if required_capabilities else "loaded"
        row["required_capabilities"] = required_capabilities
        if _basic_eligible(row) and not _ignored(row, ignore):
            helper_paths: set[str] = set()
            for scalar in _walk_scalars(document):
                _collect_helper_path(relative, scalar, by_path, helper_paths)
            for payload in _payload_file_references(document):
                _collect_helper_path(
                    relative, payload, by_path, helper_paths, required=True,
                )
            semantic_class, semantic_reasons = _semantic_risk(raw, document)
            row.update({
                "semantic_class": semantic_class,
                "semantic_reasons": semantic_reasons,
                "helper_paths": sorted(helper_paths),
            })
        else:
            row.update({
                "semantic_class": "unknown", "semantic_reasons": ["unselected-template"],
                "helper_paths": [],
            })
        templates.append(row)
    return templates


def _selected_template_closure(templates: list[dict], selected_paths: set[str]
                               ) -> tuple[list[dict], set[str]]:
    helper_paths: set[str] = set()
    enriched = []
    for row in templates:
        private_helpers = row.get("helper_paths", ())
        if row["path"] in selected_paths:
            helper_paths.update(private_helpers)
        enriched.append(dict(row))
    return enriched, helper_paths


def _ignore_policy(config_root: Path, inventory: list[dict]) -> dict:
    by_path = {row["path"]: row for row in inventory}
    row = by_path.get(".nuclei-ignore")
    if not isinstance(row, dict) or row.get("kind") != "file":
        raise NucleiPolicyError("the detached Nuclei config has no regular .nuclei-ignore authority")
    document = _load_yaml(
        _inventory_bytes(config_root, row, yaml_input=True), label=".nuclei-ignore",
    )
    if type(document) is not dict or set(document) - {"tags", "files"}:
        raise NucleiPolicyError(".nuclei-ignore has an unsupported shape")

    def string_list(name: str) -> list[str]:
        values = document.get(name, [])
        if type(values) is not list or any(type(item) is not str or not item.strip() for item in values):
            raise NucleiPolicyError(f".nuclei-ignore {name} must be a string list")
        return sorted(set(item.strip() for item in values), key=lambda item: item.encode("utf-8"))

    tags = sorted({item.lower() for item in string_list("tags")})
    files = []
    for value in string_list("files"):
        normalized = Path(value).as_posix()
        if Path(normalized).is_absolute() or ".." in Path(normalized).parts or normalized in {"", "."}:
            raise NucleiPolicyError(f".nuclei-ignore contains an unsafe file selector: {value}")
        if "\\" in normalized:
            # filepath.Match treats backslash as an escape on POSIX while Path treats it as a filename
            # byte. Refuse that ambiguous spelling instead of claiming a different selected set.
            raise NucleiPolicyError(f".nuclei-ignore contains an ambiguous file selector: {value}")
        files.append(normalized)
    return {"path": ".nuclei-ignore", "sha256": row["sha256"],
            "tags": tags, "files": sorted(set(files)), "resolved_files": []}


def _resolve_ignore_files(ignore: dict, inventory: list[dict]) -> dict:
    """Expand .nuclei-ignore selectors to the engine-visible paths in this exact snapshot."""
    template_paths = sorted(
        row["path"] for row in inventory
        if row.get("kind") == "file" and _engine_template_path(row["path"])
    )
    resolved: set[str] = set()
    for selector in ignore["files"]:
        normalized = posixpath.normpath(selector)
        prefix = normalized.rstrip("/") + "/"
        wildcard = any(char in normalized for char in "*?[")
        for path in template_paths:
            if (path == normalized or path.startswith(prefix)
                    or (wildcard and _engine_path_match(path, normalized))):
                resolved.add(path)
    return {**ignore, "resolved_files": sorted(resolved, key=lambda item: item.encode("utf-8"))}


def _flags_config_policy(config_root: Path, inventory: list[dict]) -> dict:
    by_path = {row["path"]: row for row in inventory}
    row = by_path.get("config.yaml")
    if not isinstance(row, dict) or row.get("kind") != "file":
        raise NucleiPolicyError("the detached Nuclei config has no regular config.yaml authority")
    document = _load_yaml(_inventory_bytes(config_root, row, yaml_input=True), label="config.yaml")
    if document not in (None, {}):
        # Any active goflags setting can alter selection, requests, output, credentials, or transport.
        # Quarry supplies its accepted policy on argv; hidden config overrides are therefore refused.
        raise NucleiPolicyError("Nuclei config.yaml contains active settings outside the accepted policy")
    return {"path": "config.yaml", "sha256": row["sha256"], "active_settings": False}


def _selection(owner: str, templates: list[dict], ignore: dict | None = None) -> list[dict]:
    if owner == "params.nuclei_scan":
        selected = [row for row in templates
                    if row["severity"] in _MAIN_SEVERITIES
                    and not set(row["tags"]) & set(_MAIN_EXCLUDED_TAGS)]
    elif owner == "params.nuclei_takeover":
        selected = [row for row in templates if "takeover" in row["tags"]]
    elif owner in {"probe.nuclei_waf", "enrich.nuclei_waf"}:
        selected = [row for row in templates if "waf" in row["tags"]]
    else:
        raise NucleiPolicyError(f"unknown Nuclei owner: {owner}")
    selected = [row for row in selected
                if row.get("load_state") == "loaded" and not row.get("required_capabilities")]
    if ignore is not None:
        ignored_tags = set(ignore["tags"])
        ignored_files = set(ignore["resolved_files"])
        selected = [row for row in selected
                    if not set(row["tags"]) & ignored_tags and row["path"] not in ignored_files]
    selected = sorted(selected, key=lambda row: row["path"].encode("utf-8"))
    ids: dict[str, str] = {}
    for row in selected:
        prior = ids.setdefault(row["id"], row["path"])
        if prior != row["path"]:
            raise NucleiPolicyError(
                f"Nuclei owner {owner} has duplicate template id {row['id']!r}: "
                f"{prior}, {row['path']}"
            )
    return selected


def _selected_template_row(row: dict) -> dict:
    return {key: row[key] for key in _selected_template_fields}


def _engine_identity() -> tuple[dict, str | None]:
    record, _path, tool, _root, _receipt = runtime_identity._tool_identity("nuclei")
    pin = None if tool is None else (tool.pin or tool.ref or tool.release)
    return record, pin


def _owner_flags(owner: str, profile, oob_config: dict) -> list[str]:
    disabled = not profile.oob_enabled
    rate = profile.http_rl
    if owner == "params.nuclei_scan":
        from .phases.params import _nuclei_mhe
        mhe = _nuclei_mhe()
        flags = [
            "-duc", "-ept", "javascript", "-etags", ",".join(_MAIN_EXCLUDED_TAGS),
            "-s", ",".join(_MAIN_SEVERITIES), "-stats", "-si", "30",
            "-c", str(settings.workers("nuclei", 25)),
            "-bs", str(settings.concurrency("NUCLEI_BULK_SIZE", 25)),
        ]
        flags += ["-nmhe"] if mhe == 0 else ["-mhe", str(mhe)]
    elif owner == "params.nuclei_takeover":
        flags = ["-duc", "-ept", "javascript", "-tags", "takeover"]
    elif owner in {"probe.nuclei_waf", "enrich.nuclei_waf"}:
        flags = ["-duc", "-ept", "javascript", "-tags", "waf"]
    else:
        raise NucleiPolicyError(f"unknown Nuclei owner: {owner}")
    if rate:
        flags += ["-rl", str(rate)]
    if disabled:
        flags.append("-ni")
    elif oob_config.get("callback_server"):
        flags += ["-iserver", str(oob_config["callback_server"])]
    return flags


def _freeze_oob_config(raw: dict | None) -> dict:
    values = dict(raw or {})
    if set(values) - {"callback_server", "auth_token"}:
        raise NucleiPolicyError("the self-hosted Nuclei OOB config has unsupported fields")
    server = values.get("callback_server")
    token = values.get("auth_token")
    if not server:
        return {}
    if (type(server) is not str or not server.strip()
            or any(char.isspace() or ord(char) < 0x20 for char in server)):
        raise NucleiPolicyError("the self-hosted Nuclei OOB server is malformed")
    text = server.strip()
    parsed = urllib.parse.urlsplit(text)
    try:
        port = parsed.port
    except ValueError as exc:
        raise NucleiPolicyError("the self-hosted Nuclei OOB server has an invalid port") from exc
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or parsed.scheme.lower() not in {"http", "https"}):
        raise NucleiPolicyError("the self-hosted Nuclei OOB server contains unsupported/secret URL parts")
    if port is not None and not 1 <= port <= 65535:
        raise NucleiPolicyError("the self-hosted Nuclei OOB server has an invalid port")
    host = parsed.hostname.lower()
    canonical_host = host.isascii() and not host.endswith(".")
    if ":" in host:
        try:
            host = ipaddress.IPv6Address(host).compressed
        except ValueError:
            canonical_host = False
    else:
        labels = host.split(".")
        canonical_host = canonical_host and len(host) <= 253 and all(
            len(label) <= 63
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        )
    if not canonical_host:
        raise NucleiPolicyError("the self-hosted Nuclei OOB server has a non-canonical host")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}:
        port = None
    authority = host + (f":{port}" if port is not None else "")
    canonical_server = f"{parsed.scheme.lower()}://{authority}"
    result = {"callback_server": canonical_server}
    if token not in (None, ""):
        if type(token) is not str:
            raise NucleiPolicyError("the self-hosted Nuclei OOB token is malformed")
        result["auth_token"] = token
    return result


def _oob_auth_identity(run_id: str, server: str, token: str | None) -> str | None:
    if not token:
        return None
    return _sha256(_canonical({
        "domain": "quarry.oob-auth.v1", "run_id": run_id,
        "server": server, "auth_token": token,
    }))


def _oob_config_identity(*, enabled: bool, backend: str, server: str | None,
                         auth_identity: str | None) -> str:
    return _sha256(_canonical({
        "domain": "quarry.oob-config.v1", "enabled": enabled,
        "backend": backend, "server": server, "auth_identity": auth_identity,
    }))


def _channel_row(owner: str, *, enabled: bool, backend: str,
                 config_identity: str | None) -> dict:
    row = {
        "owner": owner, "enabled": enabled, "oob_backend": backend,
        "config_identity": config_identity,
    }
    row["channel_digest"] = _sha256(_canonical(row))
    return row


def _policy_channels(profile, modes: dict) -> list[dict]:
    network_enabled = bool(modes["oob_enabled"])
    config_identity = modes["oob_config_identity"] if network_enabled else None
    blind_enabled = network_enabled and bool(getattr(profile, "blind_xss", False))
    return [
        _channel_row(
            "params.oob_probe", enabled=network_enabled,
            backend=modes["oob_backend"] if network_enabled else "off",
            config_identity=config_identity,
        ),
        _channel_row(
            "quarry.oob_poll", enabled=network_enabled,
            backend=modes["oob_backend"] if network_enabled else "off",
            config_identity=config_identity,
        ),
        _channel_row(
            "params.dalfox_blind_oob", enabled=blind_enabled,
            backend=modes["oob_backend"] if blind_enabled else "off",
            config_identity=config_identity if blind_enabled else None,
        ),
        _channel_row(
            "quarry.oob_import", enabled=True, backend="local-only", config_identity=None,
        ),
    ]


def build_document(*, run_id: str, profile, template_root: Path, config_root: Path,
                   engine_identity: dict, engine_pin: str | None = None,
                   template_source_state: str = "tree", config_source_state: str = "tree",
                   template_source_origin_kind: str | None = None,
                   config_source_origin_kind: str | None = None,
                   oob_config: dict | None = None) -> dict:
    """Build the canonical policy from detached snapshot roots; no target or update contact occurs."""
    corpus_inventory = _inventory(template_root)
    config_inventory = _inventory(config_root)
    ignore = _resolve_ignore_files(
        _ignore_policy(config_root, config_inventory), corpus_inventory,
    )
    flags_config = _flags_config_policy(config_root, config_inventory)
    templates = _template_rows(template_root, corpus_inventory, ignore)
    selected_paths = {
        row["path"] for owner in OWNERS for row in _selection(owner, templates, ignore)
    }
    templates, helper_paths = _selected_template_closure(templates, selected_paths)
    # runtime_identity hashes the same rows with bare hexadecimal file digests.  Keep human-facing file
    # rows canonical (``sha256:``) while making the tree digest directly comparable to every launch record.
    runtime_corpus_inventory = [
        {**row, "sha256": row["sha256"].removeprefix("sha256:")} for row in corpus_inventory
    ]
    runtime_config_inventory = [
        {**row, "sha256": row["sha256"].removeprefix("sha256:")} for row in config_inventory
    ]
    corpus_digest = _sha256(_canonical(runtime_corpus_inventory))
    config_digest = _sha256(_canonical(runtime_config_inventory))
    helper_by_path = {row["path"]: row for row in corpus_inventory if row["path"] in helper_paths}
    oob_config = ({} if not profile.oob_enabled else
                  _freeze_oob_config(secrets.oob() if oob_config is None else oob_config))
    oob_backend = ("off" if not profile.oob_enabled else
                   "self-hosted" if oob_config.get("callback_server") else "public-interactsh")
    oob_server = (None if not profile.oob_enabled else
                  str(oob_config["callback_server"]) if oob_config.get("callback_server")
                  else "projectdiscovery-public-default")
    auth_identity = _oob_auth_identity(
        run_id, str(oob_config.get("callback_server") or ""), oob_config.get("auth_token"),
    ) if profile.oob_enabled else None
    oob_config_identity = _oob_config_identity(
        enabled=bool(profile.oob_enabled), backend=oob_backend, server=oob_server,
        auth_identity=auth_identity,
    )
    modes = {
        "oob_enabled": profile.oob_enabled,
        "oob_backend": oob_backend,
        "oob_server": oob_server,
        "oob_auth": ("private-config" if profile.oob_enabled
                     and oob_config.get("callback_server") and oob_config.get("auth_token")
                     else "none"),
        "oob_auth_identity": auth_identity,
        "oob_config_identity": oob_config_identity,
        "block_private_targets": profile.block_private_targets,
    }
    owners = []
    for owner in OWNERS:
        selected = _selection(owner, templates, ignore)
        selection_rows = [_selected_template_row(row) for row in selected]
        flags = _owner_flags(owner, profile, oob_config)
        private_config = ("interactsh-token" if profile.oob_enabled
                          and oob_config.get("callback_server") and oob_config.get("auth_token") else None)
        semantic_counts = {
            name: sum(row["semantic_class"] == name for row in selection_rows)
            for name in _semantic_classes
        }
        owner_channel = _channel_row(
            owner, enabled=bool(profile.oob_enabled), backend=oob_backend,
            config_identity=oob_config_identity if profile.oob_enabled else None,
        )
        owners.append({
            "owner": owner,
            "description": ("broad active vulnerability verification" if owner == "params.nuclei_scan"
                            else "subdomain takeover verification" if owner == "params.nuclei_takeover"
                            else "WAF fingerprinting"),
            "flags": flags,
            "private_config": private_config,
            "oob_enabled": owner_channel["enabled"],
            "oob_backend": oob_backend,
            "oob_config_identity": owner_channel["config_identity"],
            "channel_digest": owner_channel["channel_digest"],
            "flags_digest": _sha256(_canonical({"flags": flags, "private_config": private_config})),
            "selected_count": len(selection_rows),
            "selected_templates": selection_rows,
            "selection_digest": _sha256(_canonical(selection_rows)),
            "semantic_inventory": {
                "classifier": _semantic_classifier,
                "counts": semantic_counts,
                "potentially_state_changing": [
                    {"id": row["id"], "path": row["path"]} for row in selection_rows
                    if row["semantic_class"] == "potentially_state_changing"
                ],
                "unknown": [
                    {"id": row["id"], "path": row["path"]} for row in selection_rows
                    if row["semantic_class"] == "unknown"
                ],
            },
        })
    scope_fields = {
        "target": str(getattr(profile, "target", "")),
        "apex_domains": list(getattr(profile, "apex_domains", ()) or ()),
        "oos": list(getattr(profile, "oos", ()) or ()),
        "cidr": list(getattr(profile, "cidr", ()) or ()),
        "asn": list(getattr(profile, "asn", ()) or ()),
    }
    template_source_origin_kind = (template_source_origin_kind
                                   if template_source_origin_kind is not None else
                                   "absent" if template_source_state == "absent" else "tree")
    config_source_origin_kind = (config_source_origin_kind
                                 if config_source_origin_kind is not None else
                                 "absent" if config_source_state == "absent" else "tree")
    document = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": POLICY_ID,
        "run_id": run_id,
        "policy_digest": None,
        "authorization": {
            "consent_basis": "active-profile",
            "scope_revision": _sha256(_canonical(scope_fields)),
            "verification_claim": "operator-asserted-not-legally-verified",
        },
        "engine": {"identity": engine_identity, "declared_pin": engine_pin},
        "corpus": {
            "source_state": template_source_state,
            "source_origin_kind": template_source_origin_kind,
            "digest": corpus_digest,
            "bytes": sum(row["bytes"] for row in corpus_inventory),
            "file_count": len(corpus_inventory),
            "inventory": corpus_inventory,
            "signature_verification": "inventory-only-not-cryptographically-verified",
            "trust": "unverified-inventory-only-not-an-authorship-claim",
        },
        "config": {
            "source_state": config_source_state,
            "source_origin_kind": config_source_origin_kind,
            "digest": config_digest,
            "bytes": sum(row["bytes"] for row in config_inventory),
            "file_count": len(config_inventory),
            "inventory": config_inventory,
            "private": True,
        },
        "ignore": ignore,
        "flags_config": flags_config,
        "helpers": [helper_by_path[path] for path in sorted(helper_by_path)],
        "template_inventory": templates,
        "semantic_classifier": {
            "id": _semantic_classifier,
            "effect": "telemetry-only-never-filters-selection",
            "classes": list(_semantic_classes),
        },
        "modes": modes,
        "owners": owners,
        "channels": _policy_channels(profile, modes),
    }
    document["policy_digest"] = _sha256(_canonical({**document, "policy_digest": None}))
    validate_document(document)
    return document


def _validate_accepted_flags(owner: dict, modes: dict) -> None:
    flags = owner["flags"]
    if type(flags) is not list or any(type(value) is not str or not value for value in flags):
        raise NucleiPolicyError("Nuclei owner flags are not a strict string vector")
    name = owner["owner"]
    descriptions = {
        "probe.nuclei_waf": "WAF fingerprinting",
        "enrich.nuclei_waf": "WAF fingerprinting",
        "params.nuclei_takeover": "subdomain takeover verification",
        "params.nuclei_scan": "broad active vulnerability verification",
    }
    if owner["description"] != descriptions[name]:
        raise NucleiPolicyError("Nuclei owner description misstates its accepted policy")
    if name == "params.nuclei_scan":
        prefix = [
            "-duc", "-ept", "javascript", "-etags", ",".join(_MAIN_EXCLUDED_TAGS),
            "-s", ",".join(_MAIN_SEVERITIES), "-stats", "-si", "30", "-c",
        ]
    elif name == "params.nuclei_takeover":
        prefix = ["-duc", "-ept", "javascript", "-tags", "takeover"]
    else:
        prefix = ["-duc", "-ept", "javascript", "-tags", "waf"]
    if flags[:len(prefix)] != prefix:
        raise NucleiPolicyError("Nuclei owner flags change the accepted coverage policy")
    index = len(prefix)

    def positive_integer(label: str) -> None:
        nonlocal index
        if (index >= len(flags) or not re.fullmatch(r"[1-9][0-9]*", flags[index])
                or int(flags[index]) > 1_000_000_000):
            raise NucleiPolicyError(f"Nuclei owner {label} is not a bounded canonical integer")
        index += 1

    if name == "params.nuclei_scan":
        positive_integer("concurrency")
        if index >= len(flags) or flags[index] != "-bs":
            raise NucleiPolicyError("Nuclei owner bulk-size policy is missing")
        index += 1
        positive_integer("bulk size")
        if index < len(flags) and flags[index] == "-nmhe":
            index += 1
        elif index < len(flags) and flags[index] == "-mhe":
            index += 1
            positive_integer("host-error limit")
        else:
            raise NucleiPolicyError("Nuclei owner host-error policy is missing")
    if flags[index:index + 1] == ["-rl"]:
        index += 1
        positive_integer("rate limit")
    expected_oob = (["-ni"] if modes["oob_backend"] == "off" else
                    ["-iserver", modes["oob_server"]]
                    if modes["oob_backend"] == "self-hosted" else [])
    if flags[index:] != expected_oob:
        raise NucleiPolicyError("Nuclei owner flags contradict the recorded OOB policy")


def _validate_engine_identity(identity: object) -> None:
    if type(identity) is not dict:
        raise NucleiPolicyError("Nuclei engine identity is not an object")
    host_keys = {"attestation", "executable", "identity", "runtime", "runtime_root", "closure"}
    managed_keys = host_keys | {"declared_identity", "receipt"}
    attestation = identity.get("attestation")
    if attestation == "managed-receipt":
        if set(identity) != managed_keys:
            raise NucleiPolicyError("managed Nuclei engine identity has unknown or missing fields")
    elif attestation in {"host-digest", "immutable-system-name"}:
        if set(identity) != host_keys:
            raise NucleiPolicyError("host Nuclei engine identity has unknown or missing fields")
    else:
        raise NucleiPolicyError("Nuclei engine attestation is unsupported")

    executable = identity.get("executable")
    if type(executable) is not dict or set(executable) != {"bytes", "path", "role", "sha256", "mode"}:
        raise NucleiPolicyError("Nuclei executable identity is malformed")
    if (type(executable["bytes"]) is not int or executable["bytes"] < 0
            or type(executable["mode"]) is not int or not 0 <= executable["mode"] <= 0o7777
            or any(type(executable[key]) is not str or not executable[key]
                   for key in ("path", "role"))
            or type(executable["sha256"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", executable["sha256"])):
        raise NucleiPolicyError("Nuclei executable identity fields are invalid")
    if any(type(identity.get(key)) is not str or not identity[key]
           for key in ("identity", "runtime", "runtime_root")):
        raise NucleiPolicyError("Nuclei engine identity strings are malformed")

    closure = identity.get("closure")
    if closure is not None:
        if type(closure) is not dict or set(closure) != {"bytes", "objects", "sha256"}:
            raise NucleiPolicyError("Nuclei engine closure is malformed")
        if (type(closure["bytes"]) is not int or closure["bytes"] < 0
                or type(closure["objects"]) is not int or closure["objects"] < 0
                or type(closure["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", closure["sha256"])):
            raise NucleiPolicyError("Nuclei engine closure fields are malformed")
    if attestation == "managed-receipt":
        if type(identity["declared_identity"]) is not str or not identity["declared_identity"]:
            raise NucleiPolicyError("managed Nuclei declared identity is malformed")
        receipt = identity["receipt"]
        if type(receipt) is not dict or set(receipt) != {"bytes", "path", "sha256"}:
            raise NucleiPolicyError("managed Nuclei receipt is malformed")
        if (type(receipt["bytes"]) is not int or receipt["bytes"] < 0
                or type(receipt["path"]) is not str or not receipt["path"]
                or type(receipt["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", receipt["sha256"])):
            raise NucleiPolicyError("managed Nuclei receipt fields are malformed")


def validate_document(document: dict) -> None:
    top = {"schema_version", "policy_id", "run_id", "policy_digest", "authorization", "engine",
           "corpus", "config", "ignore", "flags_config", "helpers", "semantic_classifier",
           "template_inventory", "modes", "owners", "channels"}
    if type(document) is not dict or set(document) != top:
        raise NucleiPolicyError("Nuclei policy has unknown or missing top-level fields")
    if document["schema_version"] != SCHEMA_VERSION or document["policy_id"] != POLICY_ID:
        raise NucleiPolicyError("Nuclei policy schema or accepted policy identity is unsupported")
    if type(document["run_id"]) is not str or not document["run_id"]:
        raise NucleiPolicyError("Nuclei policy has no run identity")
    digest = document["policy_digest"]
    if type(digest) is not str or not _DIGEST_RE.fullmatch(digest):
        raise NucleiPolicyError("Nuclei policy digest is malformed")
    if digest != _sha256(_canonical({**document, "policy_digest": None})):
        raise NucleiPolicyError("Nuclei policy digest does not bind its document")
    authorization = document["authorization"]
    if (type(authorization) is not dict
            or set(authorization) != {"consent_basis", "scope_revision", "verification_claim"}
            or authorization["consent_basis"] != "active-profile"
            or authorization["verification_claim"] != "operator-asserted-not-legally-verified"
            or type(authorization["scope_revision"]) is not str
            or not _DIGEST_RE.fullmatch(authorization["scope_revision"])):
        raise NucleiPolicyError("Nuclei authorization/scope identity is malformed")
    engine = document["engine"]
    if type(engine) is not dict or set(engine) != {"identity", "declared_pin"} \
            or type(engine["identity"]) is not dict \
            or (engine["declared_pin"] is not None and type(engine["declared_pin"]) is not str):
        raise NucleiPolicyError("Nuclei engine policy is not an exact identity record")
    identity = engine["identity"]
    _validate_engine_identity(identity)

    def _tree(value, *, private: bool) -> dict:
        keys = {"source_state", "source_origin_kind", "digest", "bytes", "file_count", "inventory"}
        keys.update({"private"} if private else {"signature_verification", "trust"})
        if type(value) is not dict or set(value) != keys:
            raise NucleiPolicyError("Nuclei tree identity has unknown or missing fields")
        if value["source_state"] not in {"tree", "absent", "detached-tree"}:
            raise NucleiPolicyError("Nuclei tree source state is invalid")
        if value["source_origin_kind"] not in {"tree", "absent"}:
            raise NucleiPolicyError("Nuclei tree source origin is invalid")
        if (value["source_state"] == "absent" and value["source_origin_kind"] != "absent"):
            raise NucleiPolicyError("an absent Nuclei tree has a contradictory source origin")
        if (value["source_state"] == "tree" and value["source_origin_kind"] != "tree"):
            raise NucleiPolicyError("a live Nuclei tree has a contradictory source origin")
        if private:
            if value["private"] is not True:
                raise NucleiPolicyError("Nuclei config identity is not marked private")
        elif (value["signature_verification"] != "inventory-only-not-cryptographically-verified"
              or value["trust"] != "unverified-inventory-only-not-an-authorship-claim"):
            raise NucleiPolicyError("Nuclei corpus trust/signature claim is unsupported")
        rows = value["inventory"]
        if type(rows) is not list:
            raise NucleiPolicyError("Nuclei tree inventory is not a list")
        seen, total = set(), 0
        for row in rows:
            if type(row) is not dict or set(row) != {"bytes", "kind", "path", "sha256"}:
                raise NucleiPolicyError("Nuclei tree row has unknown or missing fields")
            if (type(row["bytes"]) is not int or row["bytes"] < 0
                    or row["kind"] not in {"file", "symlink"}
                    or type(row["path"]) is not str or not row["path"]
                    or Path(row["path"]).is_absolute() or ".." in Path(row["path"]).parts
                    or type(row["sha256"]) is not str or not _DIGEST_RE.fullmatch(row["sha256"])
                    or row["path"] in seen):
                raise NucleiPolicyError("Nuclei tree row is invalid or duplicated")
            seen.add(row["path"])
            total += row["bytes"]
        if [row["path"] for row in rows] != sorted(seen, key=lambda item: item.encode("utf-8")):
            raise NucleiPolicyError("Nuclei tree inventory is not canonically ordered")
        runtime_rows = [{**row, "sha256": row["sha256"].removeprefix("sha256:")} for row in rows]
        if (type(value["bytes"]) is not int or value["bytes"] != total
                or type(value["file_count"]) is not int or value["file_count"] != len(rows)
                or value["digest"] != _sha256(_canonical(runtime_rows))):
            raise NucleiPolicyError("Nuclei tree summary does not reconcile to its inventory")
        if value["source_origin_kind"] == "absent" and (rows or total or value["file_count"]):
            raise NucleiPolicyError("an absent Nuclei tree origin cannot have inventory rows")
        return {row["path"]: row for row in rows}

    corpus_rows = _tree(document["corpus"], private=False)
    config_rows = _tree(document["config"], private=True)
    ignore = document["ignore"]
    if (type(ignore) is not dict
            or set(ignore) != {"path", "sha256", "tags", "files", "resolved_files"}
            or ignore["path"] != ".nuclei-ignore"
            or config_rows.get(ignore["path"], {}).get("sha256") != ignore["sha256"]):
        raise NucleiPolicyError("Nuclei ignore identity is inconsistent with the config snapshot")
    for name in ("tags", "files", "resolved_files"):
        values = ignore.get(name)
        if (type(values) is not list or any(type(value) is not str or not value for value in values)
                or values != sorted(set(values), key=lambda item: item.encode("utf-8"))):
            raise NucleiPolicyError(f"Nuclei ignore {name} are not canonical")
    if (any(Path(value).is_absolute() or ".." in Path(value).parts or value in {"", "."}
            for value in ignore["files"])):
        raise NucleiPolicyError("Nuclei ignore file selector is unsafe")
    if any(corpus_rows.get(value, {}).get("kind") != "file" for value in ignore["resolved_files"]):
        raise NucleiPolicyError("Nuclei resolved ignore path is absent from the corpus")
    expected_resolved = _resolve_ignore_files(ignore, list(corpus_rows.values()))["resolved_files"]
    if ignore["resolved_files"] != expected_resolved:
        raise NucleiPolicyError("Nuclei resolved ignore paths do not match their frozen selectors")
    flags_config = document["flags_config"]
    if (type(flags_config) is not dict
            or set(flags_config) != {"path", "sha256", "active_settings"}
            or flags_config["path"] != "config.yaml" or flags_config["active_settings"] is not False
            or config_rows.get(flags_config["path"], {}).get("sha256") != flags_config["sha256"]):
        raise NucleiPolicyError("Nuclei flags-config identity is inconsistent or active")
    helpers = document["helpers"]
    if type(helpers) is not list or any(type(row) is not dict or corpus_rows.get(row.get("path")) != row
                                       for row in helpers):
        raise NucleiPolicyError("Nuclei helper inventory is not a subset of the corpus")
    if [row["path"] for row in helpers] != sorted({row["path"] for row in helpers}):
        raise NucleiPolicyError("Nuclei helper inventory is duplicated or out of order")
    template_inventory = document["template_inventory"]
    template_keys = {
        "id", "path", "bytes", "sha256", "severity", "tags", "signature_state",
        "signature_marker_digest", "load_state", "required_capabilities", "semantic_class",
        "semantic_reasons", "helper_paths",
    }
    if type(template_inventory) is not list:
        raise NucleiPolicyError("Nuclei template inventory is not a list")
    expected_template_paths = sorted(
        path for path, row in corpus_rows.items()
        if row["kind"] == "file" and _engine_template_path(path)
    )
    if [row.get("path") for row in template_inventory] != expected_template_paths:
        raise NucleiPolicyError("Nuclei template inventory does not cover the engine-visible corpus")
    for row in template_inventory:
        if type(row) is not dict or set(row) != template_keys:
            raise NucleiPolicyError("Nuclei template inventory row has unknown or missing fields")
        if (type(row["id"]) is not str or not row["id"]
                or type(row["path"]) is not str or not row["path"]
                or corpus_rows.get(row["path"], {}).get("sha256") != row["sha256"]
                or corpus_rows.get(row["path"], {}).get("bytes") != row["bytes"]
                or type(row["severity"]) is not str or not row["severity"]
                or type(row["tags"]) is not list
                or any(type(tag) is not str or not tag or tag != tag.strip().lower()
                       for tag in row["tags"])
                or row["tags"] != sorted(set(row["tags"]))
                or row["signature_state"] not in {
                    "digest-marker-present-unverified", "unsigned",
                }
                or ((row["signature_marker_digest"] is None)
                    != (row["signature_state"] == "unsigned"))
                or (row["signature_marker_digest"] is not None
                    and not _DIGEST_RE.fullmatch(row["signature_marker_digest"]))
                or row["load_state"] not in {"loaded", "load-excluded", "metadata-rejected"}
                or type(row["required_capabilities"]) is not list
                or any(type(name) is not str or name not in _LOAD_BLOCKING_CAPABILITIES
                       for name in row["required_capabilities"])
                or row["required_capabilities"] != [
                    name for name in _LOAD_BLOCKING_CAPABILITIES
                    if name in row["required_capabilities"]
                ]
                or row["semantic_class"] not in _semantic_classes
                or type(row["semantic_reasons"]) is not list
                or any(type(reason) is not str or not reason for reason in row["semantic_reasons"])
                or row["semantic_reasons"] != sorted(set(row["semantic_reasons"]))
                or type(row["helper_paths"]) is not list
                or any(type(path) is not str or not path for path in row["helper_paths"])
                or row["helper_paths"] != sorted(set(row["helper_paths"]))
                or any(corpus_rows.get(path, {}).get("kind") != "file"
                       for path in row["helper_paths"])):
            raise NucleiPolicyError("Nuclei template inventory row is inconsistent")
        if ((row["load_state"] == "load-excluded") != bool(row["required_capabilities"])
                or (row["load_state"] == "loaded" and row["required_capabilities"])):
            raise NucleiPolicyError("Nuclei template load exclusion is contradictory")
        if row["load_state"] == "metadata-rejected" and (
                row["id"] != row["path"] or row["severity"] != "unknown" or row["tags"]
                or row["required_capabilities"] or row["helper_paths"]
                or row["semantic_class"] != "unknown"
                or row["semantic_reasons"] != ["metadata-rejected"]):
            raise NucleiPolicyError("Nuclei rejected-template inventory is contradictory")
    classifier = document["semantic_classifier"]
    if (type(classifier) is not dict or set(classifier) != {"id", "effect", "classes"}
            or classifier["id"] != _semantic_classifier
            or classifier["effect"] != "telemetry-only-never-filters-selection"
            or classifier["classes"] != list(_semantic_classes)):
        raise NucleiPolicyError("Nuclei semantic classifier identity is unsupported")
    if type(document["owners"]) is not list or [row.get("owner") for row in document["owners"]] != list(OWNERS):
        raise NucleiPolicyError("Nuclei policy owner roster is incomplete or out of order")
    for owner in document["owners"]:
        required = {"owner", "description", "flags", "flags_digest", "selected_count",
                    "selected_templates", "selection_digest", "semantic_inventory", "private_config",
                    "oob_enabled", "oob_backend", "oob_config_identity", "channel_digest"}
        if type(owner) is not dict or set(owner) != required:
            raise NucleiPolicyError("Nuclei owner policy has unknown or missing fields")
        if owner["selected_count"] != len(owner["selected_templates"]):
            raise NucleiPolicyError("Nuclei selected-template count is inconsistent")
        if owner["private_config"] not in {None, "interactsh-token"}:
            raise NucleiPolicyError("Nuclei owner private-config declaration is unsupported")
        if type(owner["oob_enabled"]) is not bool:
            raise NucleiPolicyError("Nuclei owner OOB enabled state is not boolean")
        expected_channel = _channel_row(
            owner["owner"], enabled=owner["oob_enabled"], backend=owner["oob_backend"],
            config_identity=owner["oob_config_identity"],
        )
        if owner["channel_digest"] != expected_channel["channel_digest"]:
            raise NucleiPolicyError("Nuclei owner OOB channel is not digest-bound")
        if owner["flags_digest"] != _sha256(_canonical(
                {"flags": owner["flags"], "private_config": owner["private_config"]})):
            raise NucleiPolicyError("Nuclei owner flags are not digest-bound")
        if owner["selection_digest"] != _sha256(_canonical(owner["selected_templates"])):
            raise NucleiPolicyError("Nuclei owner selection is not digest-bound")
        selected_paths = []
        for selected in owner["selected_templates"]:
            selected_keys = set(_selected_template_fields)
            if type(selected) is not dict or set(selected) != selected_keys:
                raise NucleiPolicyError("Nuclei selected-template row is malformed")
            if (type(selected["id"]) is not str or not selected["id"]
                    or type(selected["path"]) is not str or not selected["path"]
                    or corpus_rows.get(selected["path"], {}).get("sha256") != selected["sha256"]
                    or type(selected["tags"]) is not list
                    or any(type(tag) is not str or not tag for tag in selected["tags"])
                    or selected["tags"] != sorted(set(selected["tags"]))
                    or selected["signature_state"] not in {
                        "digest-marker-present-unverified", "unsigned",
                    }
                    or ((selected["signature_marker_digest"] is None)
                        != (selected["signature_state"] == "unsigned"))
                    or selected["semantic_class"] not in _semantic_classes
                    or type(selected["semantic_reasons"]) is not list
                    or any(type(reason) is not str or not reason
                           for reason in selected["semantic_reasons"])
                    or selected["semantic_reasons"] != sorted(set(selected["semantic_reasons"]))):
                raise NucleiPolicyError("Nuclei selected-template row is inconsistent")
            if selected["signature_marker_digest"] is not None and not _DIGEST_RE.fullmatch(
                    selected["signature_marker_digest"]):
                raise NucleiPolicyError("Nuclei template signature marker digest is malformed")
            selected_paths.append(selected["path"])
        if selected_paths != sorted(set(selected_paths), key=lambda item: item.encode("utf-8")):
            raise NucleiPolicyError("Nuclei selected-template inventory is duplicated or out of order")
        semantic = owner["semantic_inventory"]
        if (type(semantic) is not dict
                or set(semantic) != {"classifier", "counts", "potentially_state_changing", "unknown"}
                or semantic["classifier"] != _semantic_classifier
                or type(semantic["counts"]) is not dict
                or set(semantic["counts"]) != set(_semantic_classes)):
            raise NucleiPolicyError("Nuclei semantic inventory is malformed")
        expected_counts = {
            name: sum(row["semantic_class"] == name for row in owner["selected_templates"])
            for name in _semantic_classes
        }
        expected_risk = [
            {"id": row["id"], "path": row["path"]} for row in owner["selected_templates"]
            if row["semantic_class"] == "potentially_state_changing"
        ]
        expected_unknown = [
            {"id": row["id"], "path": row["path"]} for row in owner["selected_templates"]
            if row["semantic_class"] == "unknown"
        ]
        if (semantic["counts"] != expected_counts
                or semantic["potentially_state_changing"] != expected_risk
                or semantic["unknown"] != expected_unknown):
            raise NucleiPolicyError("Nuclei semantic inventory does not reconcile to selection")
        expected_selection = [
            _selected_template_row(row)
            for row in _selection(owner["owner"], template_inventory, ignore)
        ]
        if owner["selected_templates"] != expected_selection:
            raise NucleiPolicyError("Nuclei selected inventory is not the complete accepted selection")
    modes = document["modes"]
    if (type(modes) is not dict or set(modes) != {
            "oob_enabled", "oob_backend", "oob_server", "oob_auth", "oob_auth_identity",
            "oob_config_identity", "block_private_targets",
            }
            or type(modes["oob_enabled"]) is not bool or type(modes["block_private_targets"]) is not bool
            or modes["oob_backend"] not in {"off", "public-interactsh", "self-hosted"}
            or modes["oob_auth"] not in {"none", "private-config"}
            or (modes["oob_enabled"] is False) != (modes["oob_backend"] == "off")
            or (modes["oob_backend"] == "off" and modes["oob_server"] is not None)
            or (modes["oob_backend"] == "public-interactsh"
                and modes["oob_server"] != "projectdiscovery-public-default")
            or (modes["oob_backend"] == "self-hosted"
                and (type(modes["oob_server"]) is not str or not modes["oob_server"]))
            or (modes["oob_auth"] == "private-config"
                and modes["oob_backend"] != "self-hosted")
            or ((modes["oob_auth_identity"] is None) != (modes["oob_auth"] == "none"))
            or (modes["oob_auth_identity"] is not None
                and (type(modes["oob_auth_identity"]) is not str
                     or not _DIGEST_RE.fullmatch(modes["oob_auth_identity"])))
            or type(modes["oob_config_identity"]) is not str
            or not _DIGEST_RE.fullmatch(modes["oob_config_identity"])):
        raise NucleiPolicyError("Nuclei mode policy is contradictory")
    if modes["oob_backend"] == "self-hosted":
        try:
            canonical_server = _freeze_oob_config(
                {"callback_server": modes["oob_server"]},
            )["callback_server"]
        except NucleiPolicyError as exc:
            raise NucleiPolicyError("Nuclei mode policy has a non-canonical OOB origin") from exc
        if modes["oob_server"] != canonical_server:
            raise NucleiPolicyError("Nuclei mode policy has a non-canonical OOB origin")
    expected_config_identity = _oob_config_identity(
        enabled=modes["oob_enabled"], backend=modes["oob_backend"],
        server=modes["oob_server"], auth_identity=modes["oob_auth_identity"],
    )
    if modes["oob_config_identity"] != expected_config_identity:
        raise NucleiPolicyError("Nuclei OOB configuration identity does not reconcile")
    expected_private = "interactsh-token" if modes["oob_auth"] == "private-config" else None
    if any(owner["private_config"] != expected_private for owner in document["owners"]):
        raise NucleiPolicyError("Nuclei owner credential transport contradicts the OOB policy")
    if any(owner["oob_enabled"] != modes["oob_enabled"]
           or owner["oob_backend"] != modes["oob_backend"]
           or owner["oob_config_identity"] != (
               modes["oob_config_identity"] if modes["oob_enabled"] else None)
           for owner in document["owners"]):
        raise NucleiPolicyError("Nuclei owner OOB backend contradicts the run policy")
    channels = document["channels"]
    if (type(channels) is not list
            or [row.get("owner") for row in channels if isinstance(row, dict)] != list(OOB_CHANNELS)
            or len(channels) != len(OOB_CHANNELS)):
        raise NucleiPolicyError("Nuclei policy OOB channel roster is incomplete or out of order")
    for row in channels:
        if (type(row) is not dict
                or set(row) != {"owner", "enabled", "oob_backend", "config_identity",
                                "channel_digest"}
                or type(row["enabled"]) is not bool
                or row["oob_backend"] not in {
                    "off", "public-interactsh", "self-hosted", "local-only",
                }
                or (row["config_identity"] is not None
                    and (type(row["config_identity"]) is not str
                         or not _DIGEST_RE.fullmatch(row["config_identity"])))
                or row["channel_digest"] != _channel_row(
                    row["owner"], enabled=row["enabled"], backend=row["oob_backend"],
                    config_identity=row["config_identity"],
                )["channel_digest"]):
            raise NucleiPolicyError("Nuclei policy OOB channel is malformed or unbound")
        if row["owner"] == "quarry.oob_import":
            expected = (True, "local-only", None)
        elif row["owner"] in {"params.oob_probe", "quarry.oob_poll"}:
            expected = (
                modes["oob_enabled"], modes["oob_backend"],
                modes["oob_config_identity"] if modes["oob_enabled"] else None,
            )
        else:
            if row["enabled"] and not modes["oob_enabled"]:
                raise NucleiPolicyError("Dalfox OOB cannot be enabled by a disabled run policy")
            expected = ((True, modes["oob_backend"], modes["oob_config_identity"])
                        if row["enabled"] else (False, "off", None))
        if (row["enabled"], row["oob_backend"], row["config_identity"]) != expected:
            raise NucleiPolicyError("Nuclei policy OOB channel contradicts the frozen run policy")
    for owner in document["owners"]:
        _validate_accepted_flags(owner, modes)
        for selected in owner["selected_templates"]:
            ignored = (selected["path"] in set(ignore["resolved_files"])
                       or bool(set(selected["tags"]) & set(ignore["tags"])))
            eligible = (
                selected["severity"] in _MAIN_SEVERITIES
                and not set(selected["tags"]) & set(_MAIN_EXCLUDED_TAGS)
                if owner["owner"] == "params.nuclei_scan" else
                "takeover" in selected["tags"]
                if owner["owner"] == "params.nuclei_takeover" else
                "waf" in selected["tags"]
            )
            if ignored or not eligible:
                raise NucleiPolicyError("Nuclei selected inventory contradicts accepted policy")
    selected_paths = {
        row["path"] for owner in document["owners"] for row in owner["selected_templates"]
    }
    expected_helpers = sorted({
        path for row in template_inventory if row["path"] in selected_paths
        for path in row["helper_paths"]
    })
    if [row["path"] for row in helpers] != expected_helpers:
        raise NucleiPolicyError("Nuclei helper inventory is not the exact selected-template closure")
    if document["owners"][0]["selected_templates"] != document["owners"][1]["selected_templates"]:
        raise NucleiPolicyError("the two Nuclei WAF owners do not share exact coverage")


def _manifest_summary(document: dict, artifact_digest: str) -> dict:
    """Project every durable manifest field from the one validated policy document."""
    return {
        "policy_id": document["policy_id"],
        "policy_digest": document["policy_digest"],
        "artifact": _POLICY_ARTIFACT,
        "artifact_digest": artifact_digest,
        "corpus_digest": document["corpus"]["digest"],
        "corpus_source_origin_kind": document["corpus"]["source_origin_kind"],
        "config_digest": document["config"]["digest"],
        "config_source_origin_kind": document["config"]["source_origin_kind"],
        "ignore_digest": document["ignore"]["sha256"],
        "corpus_trust": document["corpus"]["trust"],
        "modes": dict(document["modes"]),
        "owners": [
            {"owner": row["owner"], "selected_count": row["selected_count"],
             "selection_digest": row["selection_digest"], "flags_digest": row["flags_digest"],
             "oob_enabled": row["oob_enabled"], "oob_backend": row["oob_backend"],
             "oob_config_identity": row["oob_config_identity"],
             "channel_digest": row["channel_digest"],
             "semantic_counts": dict(row["semantic_inventory"]["counts"]),
             "potentially_state_changing": list(
                 row["semantic_inventory"]["potentially_state_changing"]),
             "unknown": list(row["semantic_inventory"]["unknown"])}
            for row in document["owners"]
        ],
        "channels": [dict(row) for row in document["channels"]],
    }


@dataclass
class Authority:
    document: dict
    path: Path
    artifact_bytes: bytes
    template_path: Path
    config_path: Path
    template_check: dict
    config_check: dict
    engine_identity: dict
    oob_config: dict = field(default_factory=dict, repr=False)
    _active_private_config: Path | None = field(default=None, init=False, repr=False)

    @property
    def digest(self) -> str:
        return self.document["policy_digest"]

    @property
    def artifact_digest(self) -> str:
        return _sha256(self.artifact_bytes)

    def owner(self, owner: str) -> dict:
        try:
            return next(row for row in self.document["owners"] if row["owner"] == owner)
        except StopIteration as exc:
            raise NucleiPolicyError(f"Nuclei owner is absent from the policy: {owner}") from exc

    def channel(self, owner: str) -> dict:
        if owner in OWNERS:
            row = self.owner(owner)
            return {
                "owner": owner, "enabled": row["oob_enabled"],
                "oob_backend": row["oob_backend"],
                "config_identity": row["oob_config_identity"],
                "channel_digest": row["channel_digest"],
            }
        try:
            return next(row for row in self.document["channels"] if row["owner"] == owner)
        except StopIteration as exc:
            raise NucleiPolicyError(f"OOB channel is absent from the policy: {owner}") from exc

    def channel_work_config(self, owner: str) -> dict:
        row = self.channel(owner)
        return {
            "policy_digest": self.digest, "channel_digest": row["channel_digest"],
            "oob_enabled": row["enabled"], "oob_backend": row["oob_backend"],
            "oob_config_identity": row["config_identity"],
        }

    def channel_oob_config(self, owner: str) -> dict:
        """Return private bytes only for the already-frozen network channel named by the policy."""
        row = self.channel(owner)
        if not row["enabled"] or row["oob_backend"] in {"off", "local-only"}:
            return {}
        if row["config_identity"] != self.document["modes"]["oob_config_identity"]:
            raise NucleiPolicyError(f"OOB channel configuration identity changed: {owner}")
        if row["oob_backend"] == "public-interactsh":
            return {}
        frozen = _freeze_oob_config(self.oob_config)
        modes = self.document["modes"]
        auth_identity = _oob_auth_identity(
            self.document["run_id"], str(frozen.get("callback_server") or ""),
            frozen.get("auth_token"),
        )
        if (frozen.get("callback_server") != modes["oob_server"]
                or auth_identity != modes["oob_auth_identity"]):
            raise NucleiPolicyError(f"private OOB configuration changed after publication: {owner}")
        return dict(frozen)

    def assert_ready(self) -> None:
        self.assert_artifact()
        for path, check, role in (
            (self.template_path, self.template_check, "nuclei-templates"),
            (self.config_path, self.config_check, "nuclei-config"),
        ):
            observed = runtime_identity._record_without_path(runtime_identity._dynamic_tree(path, role))
            expected = runtime_identity._record_without_path(check["expected"])
            observed.pop("role", None)
            expected.pop("role", None)
            if observed != expected:
                raise NucleiPolicyError(f"the detached {role} authority changed")
        current, _pin = _engine_identity()
        if current != self.engine_identity:
            raise NucleiPolicyError("the Nuclei engine identity changed after policy publication")

    def assert_artifact(self) -> None:
        """Authenticate the durable policy without requiring the live launch snapshots."""
        try:
            artifact, _identity = _regular_bytes(
                self.path, byte_bound=len(self.artifact_bytes),
            )
        except (OSError, NucleiPolicyError) as exc:
            raise NucleiPolicyError("Nuclei policy artifact is missing, aliased, or oversized") from exc
        if artifact != self.artifact_bytes:
            raise NucleiPolicyError("Nuclei policy artifact changed after publication")
        validate_document(json.loads(self.artifact_bytes))

    def work_config(self, owner: str) -> dict:
        row = self.owner(owner)
        return {"policy_digest": self.digest, "selection_digest": row["selection_digest"],
                "flags_digest": row["flags_digest"], "channel_digest": row["channel_digest"],
                "oob_enabled": row["oob_enabled"], "oob_backend": row["oob_backend"],
                "oob_config_identity": row["oob_config_identity"]}

    def manifest_summary(self) -> dict:
        return _manifest_summary(self.document, self.artifact_digest)

    def prepare(self, owner: str, command: list[str], *, input_total: int, work_unit: str) -> None:
        self.assert_ready()
        row = self.owner(owner)
        _assert_command(
            row, command, oob_enabled=self.document["modes"]["oob_enabled"],
            expected_private_config=self._active_private_config,
        )
        events.emit("nuclei_policy_start", owner, policy_digest=self.digest,
                    policy_ref=str(self.path), selection_digest=row["selection_digest"],
                    selected_count=row["selected_count"], flags_digest=row["flags_digest"],
                    oob_enabled=row["oob_enabled"], oob_backend=row["oob_backend"],
                    oob_config_identity=row["oob_config_identity"],
                    channel_digest=row["channel_digest"], input_total=input_total,
                    work_unit=work_unit)

    def settle(self, owner: str, result, *, input_total: int, work_unit: str) -> None:
        # Reconcile the policy artifact, engine, corpus and private config again after execution.  The
        # runner's pre-spawn record proves what was admitted; this closes same-UID/tool mutation during
        # the child lifetime before a terminal policy event is accepted.
        row = self.owner(owner)
        self.assert_ready()
        meta = getattr(result, "meta", None)
        meta = meta if isinstance(meta, dict) else {}
        started = meta.get("started") is True or getattr(result, "started", False) is True
        identity = meta.get("runtime_identity")
        identity_ref = meta.get("runtime_identity_ref")
        if started:
            if (not isinstance(identity, dict) or identity.get("tool") != "nuclei"
                    or type(identity_ref) is not str or not identity_ref):
                raise NucleiPolicyError("a started Nuclei owner has no persisted runtime identity")
            identities = identity.get("identities")
            adapter = identities[0] if isinstance(identities, list) and identities else None
            if not isinstance(adapter, dict) or {k: v for k, v in adapter.items() if k != "role"} != self.engine_identity:
                raise NucleiPolicyError("the executed Nuclei engine differs from the accepted policy")
            closures = identity.get("dynamic_closure")
            corpus = next((row for row in closures or ()
                           if isinstance(row, dict) and row.get("role") == "nuclei-templates"), None)
            corpus_digest = corpus.get("sha256") if isinstance(corpus, dict) else None
            if (type(corpus_digest) is not str
                    or "sha256:" + corpus_digest != self.document["corpus"]["digest"]):
                raise NucleiPolicyError("the executed Nuclei corpus differs from the accepted policy")
            private_inputs = identity.get("private_inputs")
            configs = [item for item in private_inputs or ()
                       if isinstance(item, dict) and item.get("role") == "nuclei-config"]
            if len(configs) != 1:
                raise NucleiPolicyError("the executed Nuclei config closure is absent or ambiguous")
            config = configs[0]
            expected_config = {
                "kind": "tree", "role": "nuclei-config",
                "source_state": self.document["config"]["source_state"],
                "closure": {
                    "bytes": self.document["config"]["bytes"],
                    "files": self.document["config"]["file_count"],
                    "sha256": self.document["config"]["digest"].removeprefix("sha256:"),
                },
            }
            if config != expected_config:
                raise NucleiPolicyError("the executed Nuclei config differs from the accepted policy")
        events.emit("nuclei_policy_finish", owner, policy_digest=self.digest,
                    selection_digest=row["selection_digest"],
                    selected_count=row["selected_count"], flags_digest=row["flags_digest"],
                    input_total=input_total, work_unit=work_unit,
                    oob_enabled=row["oob_enabled"], oob_backend=row["oob_backend"],
                    oob_config_identity=row["oob_config_identity"],
                    channel_digest=row["channel_digest"],
                    status=getattr(getattr(result, "status", None), "value", None),
                    started=started, runtime_identity_ref=identity_ref)

    @contextlib.contextmanager
    def oob_flags(self):
        """Yield the frozen OOB transport selected when this policy was published."""
        modes = self.document["modes"]
        if not modes["oob_enabled"]:
            yield ("-ni",)
            return
        frozen = self.channel_oob_config("params.nuclei_scan")
        server = frozen.get("callback_server")
        token = frozen.get("auth_token")
        if not server:
            yield ()
            return
        base = ("-iserver", str(server))
        if not token:
            yield base
            return
        if self._active_private_config is not None:
            raise NucleiPolicyError("Nuclei OOB private-config authority is already active")
        with secrets.private_tool_config("nuclei-oob", {"interactsh-token": str(token)}) as config:
            self._active_private_config = Path(config)
            try:
                yield (*base, "-config", str(config))
            finally:
                self._active_private_config = None


def _assert_command(owner: dict, command: list[str], *, oob_enabled: bool,
                    expected_private_config: Path | None) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "nuclei":
        raise NucleiPolicyError("Nuclei policy received a non-Nuclei command")
    expected = list(owner["flags"])
    value_flags = {"-l", "-o", "-tags", "-etags", "-ept", "-s", "-si", "-c", "-bs", "-mhe",
                   "-rl", "-iserver", "-config"}

    def parse(items: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
        pairs, booleans, index = [], [], 0
        while index < len(items):
            flag = items[index]
            if not flag.startswith("-"):
                raise NucleiPolicyError("Nuclei command contains an unbound positional target")
            if flag in value_flags:
                if index + 1 >= len(items) or items[index + 1].startswith("-"):
                    raise NucleiPolicyError(f"Nuclei command flag has no value: {flag}")
                pairs.append((flag, items[index + 1]))
                index += 2
            else:
                booleans.append(flag)
                index += 1
        return pairs, booleans

    expected_pairs, expected_bools = parse(expected)
    actual_pairs, actual_bools = parse(command[1:])
    operational_pairs = [pair for pair in actual_pairs if pair[0] in {"-l", "-o"}]
    if (len(operational_pairs) != 2 or {pair[0] for pair in operational_pairs} != {"-l", "-o"}
            or any(not Path(value).is_absolute() for _flag, value in operational_pairs)):
        raise NucleiPolicyError("Nuclei command input/output authority is malformed")
    policy_pairs = [pair for pair in actual_pairs if pair[0] not in {"-l", "-o", "-config"}]
    if policy_pairs != expected_pairs:
        raise NucleiPolicyError("Nuclei command changes accepted-policy flag/value order")
    if actual_bools != ["-jsonl", *expected_bools]:
        raise NucleiPolicyError("Nuclei command adds, omits, or reorders accepted boolean flags")
    config_pairs = [pair for pair in actual_pairs if pair[0] == "-config"]
    if owner["private_config"] is None:
        if config_pairs:
            raise NucleiPolicyError("Nuclei command adds an unaccepted private config")
    elif (len(config_pairs) != 1 or expected_private_config is None
          or Path(config_pairs[0][1]) != expected_private_config):
        raise NucleiPolicyError("Nuclei command changes or omits its accepted private config")
    if oob_enabled and "-ni" in command:
        raise NucleiPolicyError("Nuclei OOB is enabled but the command disables Interactsh")
    if not oob_enabled and "-ni" not in command:
        raise NucleiPolicyError("Nuclei OOB is disabled but the command can contact Interactsh")


def policy_for(ctx) -> "Authority | None":
    authority = getattr(ctx, "nuclei_policy", None)
    if type(getattr(ctx, "run", None)) is store.Run and not isinstance(authority, Authority):
        raise NucleiPolicyError("a managed run has no run-scoped Nuclei policy authority")
    return authority if isinstance(authority, Authority) else None


def published_document(run, manifest_summary: dict) -> dict:
    """Read and authenticate the frozen policy named by a committed run manifest."""
    if type(manifest_summary) is not dict:
        raise NucleiPolicyError("the run manifest has no frozen Nuclei/OOB policy summary")
    if manifest_summary.get("artifact") != _POLICY_ARTIFACT:
        raise NucleiPolicyError("the manifest Nuclei/OOB policy artifact reference is not canonical")
    path = run.dir.joinpath(*_POLICY_ARTIFACT.split("/"))
    artifact, _identity = _regular_bytes(path, byte_bound=512 * 1024 * 1024)
    try:
        document = json.loads(artifact)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NucleiPolicyError("the published Nuclei/OOB policy is not canonical JSON") from exc
    if _canonical(document) != artifact:
        raise NucleiPolicyError("the published Nuclei/OOB policy bytes are not canonical")
    validate_document(document)
    expected_summary = _manifest_summary(document, _sha256(artifact))
    if document["run_id"] != run.run_id or manifest_summary != expected_summary:
        raise NucleiPolicyError("the manifest and published Nuclei/OOB policy disagree")
    return document


def authenticate_frozen_oob(document: dict, raw: dict | None) -> dict:
    """Authenticate current private bytes against, but never redefine, a published OOB identity."""
    modes = document["modes"]
    if modes["oob_backend"] != "self-hosted":
        return {}
    if modes["oob_auth"] == "none":
        return {"callback_server": modes["oob_server"]}
    frozen = _freeze_oob_config(raw)
    auth_identity = _oob_auth_identity(
        document["run_id"], str(frozen.get("callback_server") or ""),
        frozen.get("auth_token"),
    )
    if (frozen.get("callback_server") != modes["oob_server"]
            or auth_identity != modes["oob_auth_identity"]):
        raise NucleiPolicyError("current private OOB credentials do not authenticate the frozen channel")
    return frozen


def _plan_channels(profile, backend: str) -> list[dict]:
    enabled = bool(profile.oob_enabled)
    network_backend = backend if enabled else "off"
    blind_backend = network_backend if enabled and bool(getattr(profile, "blind_xss", False)) else "off"
    return [
        {"owner": "params.oob_probe", "enabled": enabled, "oob_backend": network_backend},
        {"owner": "quarry.oob_poll", "enabled": enabled, "oob_backend": network_backend},
        {"owner": "params.dalfox_blind_oob", "enabled": blind_backend != "off",
         "oob_backend": blind_backend},
        {"owner": "quarry.oob_import", "enabled": True, "oob_backend": "local-only"},
    ]


def channel_summary(profile, backend: str | None = None) -> list[dict]:
    if backend is None:
        if not profile.oob_enabled:
            backend = "off"
        else:
            frozen = _freeze_oob_config(secrets.oob())
            backend = "self-hosted" if frozen.get("callback_server") else "public-interactsh"
    return _plan_channels(profile, backend)


def default_plan_summary() -> dict:
    """Truthful defaults when `quarry plan` has no target profile or detached snapshot."""
    backend = "public-interactsh"
    return {
        "snapshot": "not-materialized-pass--target-for-exact-selection",
        "corpus_trust": "unverified-inventory-only-not-an-authorship-claim",
        "modes": {"oob_backend": backend, "oob_enabled": True,
                  "block_private_targets": False},
        "owners": [
            {"owner": owner, "oob_enabled": True, "oob_backend": backend, "selected_count": None,
             "semantic_counts": None, "potentially_state_changing": [], "unknown": []}
            for owner in OWNERS
        ],
        "channels": [
            {"owner": "params.oob_probe", "enabled": True, "oob_backend": backend},
            {"owner": "quarry.oob_poll", "enabled": True, "oob_backend": backend},
            {"owner": "params.dalfox_blind_oob", "enabled": False, "oob_backend": "off"},
            {"owner": "quarry.oob_import", "enabled": True, "oob_backend": "local-only"},
        ],
    }


def planning_summary(profile) -> dict:
    """Materialize a read-only detached planning snapshot and report exact owner/OOB evidence."""
    try:
        config_source, template_source = runtime_identity.nuclei_runtime_sources()
        engine_identity, engine_pin = _engine_identity()
    except runtime_identity.RuntimeIdentityError as exc:
        raise NucleiPolicyError(str(exc)) from exc
    oob_config = _freeze_oob_config(secrets.oob()) if profile.oob_enabled else {}
    with contextlib.ExitStack() as stack:
        stack.enter_context(runtime_identity.reusable_tree_snapshot(
            template_source, role="nuclei-templates",
        ))
        stack.enter_context(runtime_identity.reusable_tree_snapshot(
            config_source, role="nuclei-config", allow_absent=False, private=True,
        ))
        template = runtime_identity.materialize_reusable_tree_snapshot(
            template_source, role="nuclei-templates",
        )
        config = runtime_identity.materialize_reusable_tree_snapshot(
            config_source, role="nuclei-config",
        )
        document = build_document(
            run_id="quarry-plan", profile=profile,
            template_root=template["path"], config_root=config["path"],
            engine_identity=engine_identity, engine_pin=engine_pin,
            template_source_state=template["check"]["source_kind"],
            config_source_state=config["check"]["source_kind"],
            template_source_origin_kind=template["check"].get("source_origin_kind"),
            config_source_origin_kind=config["check"].get("source_origin_kind"),
            oob_config=oob_config,
        )
    modes = document["modes"]
    owners = []
    for row in document["owners"]:
        semantic = row["semantic_inventory"]
        owners.append({
            "owner": row["owner"], "oob_enabled": row["oob_enabled"],
            "oob_backend": row["oob_backend"],
            "selected_count": row["selected_count"],
            "semantic_counts": dict(semantic["counts"]),
            "potentially_state_changing": list(semantic["potentially_state_changing"]),
            "unknown": list(semantic["unknown"]),
        })
    return {
        "snapshot": "detached-tree",
        "corpus_trust": document["corpus"]["trust"],
        "modes": dict(modes), "owners": owners,
        "channels": [
            {"owner": row["owner"], "enabled": row["enabled"],
             "oob_backend": row["oob_backend"]}
            for row in document["channels"]
        ],
    }


@contextlib.contextmanager
def run_authority(ctx):
    """Materialize, publish, and hold one Nuclei policy/snapshot authority for the full phase loop."""
    try:
        config_source, template_source = runtime_identity.nuclei_runtime_sources()
    except runtime_identity.RuntimeIdentityError as exc:
        raise NucleiPolicyError(str(exc)) from exc
    engine_identity, engine_pin = _engine_identity()
    oob_config = _freeze_oob_config(secrets.oob()) if ctx.profile.oob_enabled else {}
    with contextlib.ExitStack() as stack:
        stack.enter_context(runtime_identity.reusable_tree_snapshot(
            template_source, role="nuclei-templates",
        ))
        stack.enter_context(runtime_identity.reusable_tree_snapshot(
            config_source, role="nuclei-config", allow_absent=False, private=True,
        ))
        template = runtime_identity.materialize_reusable_tree_snapshot(
            template_source, role="nuclei-templates",
        )
        config = runtime_identity.materialize_reusable_tree_snapshot(
            config_source, role="nuclei-config",
        )
        document = build_document(
            run_id=ctx.run.run_id, profile=ctx.profile,
            template_root=template["path"], config_root=config["path"],
            engine_identity=engine_identity, engine_pin=engine_pin,
            template_source_state=template["check"].get("source_kind", "detached-tree"),
            config_source_state=config["check"].get("source_kind", "detached-tree"),
            template_source_origin_kind=template["check"].get("source_origin_kind"),
            config_source_origin_kind=config["check"].get("source_origin_kind"),
            oob_config=oob_config,
        )
        artifact = _canonical(document)
        path = ctx.run.dir / "raw" / "nuclei-policy" / "policy.json"
        if not budget.publish_bytes(path, artifact, digest=hashlib.sha256(artifact).hexdigest()):
            raise NucleiPolicyError("the immutable Nuclei policy artifact could not be published")
        authority = Authority(
            document=document, path=path, artifact_bytes=artifact,
            template_path=template["path"], config_path=config["path"],
            template_check=template["check"], config_check=config["check"],
            engine_identity=engine_identity, oob_config=oob_config,
        )
        authority.assert_ready()
        stack.enter_context(runtime_identity.expected_tool_identity("nuclei", engine_identity))
        events.emit("nuclei_policy", "run", policy_digest=authority.digest,
                    policy_ref=str(path), policy_artifact_digest=authority.artifact_digest,
                    owners=list(OWNERS),
                    corpus_digest=document["corpus"]["digest"],
                    corpus_source_origin_kind=document["corpus"]["source_origin_kind"],
                    config_digest=document["config"]["digest"],
                    config_source_origin_kind=document["config"]["source_origin_kind"],
                    ignore_digest=document["ignore"]["sha256"],
                    owner_coverage=authority.manifest_summary()["owners"],
                    oob_channels=authority.manifest_summary()["channels"],
                    oob_enabled=document["modes"]["oob_enabled"],
                    oob_backend=document["modes"]["oob_backend"],
                    block_private_targets=document["modes"]["block_private_targets"])
        yield authority
