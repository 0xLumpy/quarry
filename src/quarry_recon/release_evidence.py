"""Canonical release-candidate identity and gate-evidence primitives.

This module is deliberately independent of Quarry's runtime repository.  Release
evidence describes the source candidate and the environment that tested it; it
must never be written into a recon run or inferred from one.

The first version provides three things:

* a deterministic identity for a clean Git candidate;
* strict readers for candidate-identity and gate-record documents; and
* canonical JSON bytes/digests shared by later collectors and aggregators.

It does *not* decide that a release gate passed.  In particular, collecting an
identity for the current development version is not the same as closing
``A-IDENTITY`` or ``RG00``.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath

try:
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.10 lane
    try:
        import tomli as _toml
    except ModuleNotFoundError:  # pragma: no cover - produces a typed runtime prerequisite refusal
        _toml = None

CANDIDATE_SCHEMA = "quarry.candidate-identity.v1"
GATE_SCHEMA = "quarry.release-gate.v1"
REGISTRY_SCHEMA = "quarry.release-schema-registry.v1"
SOURCE_TREE_ALGORITHM = "quarry.git-tree-sha256.v1"
RELEASE_SCOPE = "0.3.10"
MAX_RECORD_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER = (1 << 63) - 1

SCHEMA_VERSIONS = {
    "candidate_identity": CANDIDATE_SCHEMA,
    "gate_record": GATE_SCHEMA,
    "schema_registry": REGISTRY_SCHEMA,
}

REGISTRY_PATH = "release/evidence/registry-v1.json"
SCHEMA_PATHS = {
    "candidate_identity": "release/evidence/schemas/candidate-identity-v1.schema.json",
    "gate_record": "release/evidence/schemas/gate-record-v1.schema.json",
    "schema_registry": "release/evidence/schemas/schema-registry-v1.schema.json",
}

DEFAULT_IDENTITY_INPUTS = {
    "candidate-identity-schema": SCHEMA_PATHS["candidate_identity"],
    "gate-record-schema": SCHEMA_PATHS["gate_record"],
    "package-metadata": "pyproject.toml",
    "package-version": "src/quarry_recon/__init__.py",
    "release-evidence-validator": "src/quarry_recon/release_evidence.py",
    "release-gate-contract": "docs/releases/RELEASE-GATES.md",
    "release-schema-registry": REGISTRY_PATH,
    "release-schema-registry-schema": SCHEMA_PATHS["schema_registry"],
    "release-scope-ledger": "docs/releases/v0.3.10.md",
}

GATE_STATUSES = frozenset({"pass", "fail", "open", "blocked", "not_applicable"})
LANES = frozenset({
    "H0-hermetic",
    "H1-tool-integration",
    "C0-private-corpus",
    "P0-package-supply",
    "L0-authorized-live",
})

_HEX_OBJECT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_GATE_ID_RE = re.compile(r"^[A-E]-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
_RFC3339_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,6})?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
_SUBMODULE_STATUS_RE = re.compile(
    rb"^(.)([0-9a-f]{40}(?:[0-9a-f]{24})?) (.*?)(?: \([^\r\n]*\))?$"
)


class EvidenceError(ValueError):
    """A release-evidence document or candidate violates its contract."""


@dataclass(frozen=True)
class _TreeEntry:
    mode: bytes
    kind: bytes
    object_id: bytes
    path: bytes


def _parse_json_int(value: str) -> int:
    if len(value.lstrip("-")) > 19:
        raise EvidenceError("evidence JSON integer is outside the inclusive ±(2^63-1) contract")
    parsed = int(value)
    if not -MAX_JSON_INTEGER <= parsed <= MAX_JSON_INTEGER:
        raise EvidenceError("evidence JSON integer is outside the inclusive ±(2^63-1) contract")
    return parsed


def _check_json_shape(document: object) -> None:
    stack = [(document, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise EvidenceError(f"evidence JSON exceeds maximum nesting depth {MAX_JSON_DEPTH}")
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise EvidenceError("evidence JSON object member names must be exact strings")
            stack.extend((child, depth + 1) for child in value.values())
        elif type(value) is list:
            stack.extend((child, depth + 1) for child in value)
        elif type(value) is int:
            if not -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER:
                raise EvidenceError("evidence JSON integer is outside the inclusive ±(2^63-1) contract")
        elif type(value) not in {str, bool, type(None)}:
            raise EvidenceError(f"evidence JSON contains unsupported value type {type(value).__name__}")


def canonical_json_bytes(document: object) -> bytes:
    """Return the single UTF-8 JSON representation used for evidence digests.

    Arrays retain their semantic order.  Callers must sort set-like arrays
    before reaching this boundary; the validators enforce that for the record
    shapes defined here.
    """
    _check_json_shape(document)
    try:
        text = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return text.encode("utf-8")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise EvidenceError(f"document is not canonical JSON data: {exc}") from exc


def canonical_digest(document: object) -> str:
    """Return the domain-separated content identity of canonical evidence JSON."""
    hasher = hashlib.sha256()
    hasher.update(b"quarry.release-evidence.canonical-json.v1\0")
    hasher.update(canonical_json_bytes(document))
    return "sha256:" + hasher.hexdigest()


def _json_object_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_json_bytes(data: bytes) -> object:
    """Decode strict UTF-8 JSON, rejecting duplicate members and NaN values."""
    if len(data) > MAX_RECORD_BYTES:
        raise EvidenceError(f"evidence record exceeds {MAX_RECORD_BYTES} bytes")
    try:
        text = data.decode("utf-8", "strict")
        document = json.loads(
            text,
            object_pairs_hook=_json_object_no_duplicates,
            parse_int=_parse_json_int,
            parse_constant=lambda value: (_ for _ in ()).throw(
                EvidenceError(f"non-finite JSON number {value!r}")
            ),
        )
        canonical_json_bytes(document)
        return document
    except EvidenceError:
        raise
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceError(f"invalid UTF-8 JSON: {exc}") from exc


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TZ": "UTC",
    }


def _git(
    repository: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    executable: str | os.PathLike[str],
) -> bytes:
    """Run one read-only Git query with ambient configuration disabled."""
    git_text = _absolute_tool_path(os.fspath(executable), "Git executable")
    git_path = Path(git_text)
    if not git_path.is_absolute() or any(part in {".", ".."} for part in git_path.parts):
        raise EvidenceError("Git executable must be a normalized native absolute executable path")
    command = [
        os.fspath(git_path),
        "-C",
        os.fspath(repository),
        "-c",
        "core.checkStat=default",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.untrackedCache=false",
    ]
    if os.name == "posix":
        command.extend(("-c", "core.fileMode=true", "-c", "core.symlinks=true"))
    command.extend(arguments)
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            env=_git_environment(),
        )
    except OSError as exc:
        raise EvidenceError(f"cannot execute Git: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise EvidenceError(f"Git query failed ({' '.join(arguments)}): {detail or completed.returncode}")
    return completed.stdout


def _one_ascii_line(raw: bytes, name: str) -> str:
    try:
        value = raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"Git returned a non-ASCII {name}") from exc
    if not value or "\n" in value or "\r" in value:
        raise EvidenceError(f"Git returned an invalid {name}")
    return value


def _resolved_git_directory(
    repository: Path,
    *,
    git_executable: str | os.PathLike[str],
) -> Path:
    value = _one_ascii_line(
        _git(repository, "rev-parse", "--absolute-git-dir", executable=git_executable),
        "absolute Git directory",
    )
    try:
        path = Path(value).resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"cannot resolve absolute Git directory: {exc}") from exc
    if not path.is_dir():
        raise EvidenceError("absolute Git directory is not a directory")
    return path


def _valid_tree_shape(mode: bytes, kind: bytes, path: bytes) -> bool:
    valid_mode_and_kind = (
        (kind == b"blob" and mode in {b"100644", b"100755", b"120000"})
        or (kind == b"commit" and mode == b"160000")
    )
    path_parts = path.split(b"/")
    valid_path = (
        bool(path)
        and not path.startswith(b"/")
        and all(part not in {b"", b".", b".."} for part in path_parts)
    )
    return valid_mode_and_kind and valid_path and b"\0" not in path


def _tree_entries(
    repository: Path,
    commit: str,
    *,
    git_executable: str | os.PathLike[str],
) -> list[_TreeEntry]:
    raw = _git(
        repository,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        commit,
        executable=git_executable,
    )
    entries: list[_TreeEntry] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            metadata, path = item.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
        except ValueError as exc:
            raise EvidenceError("Git returned a malformed tree entry") from exc
        if not _valid_tree_shape(mode, kind, path):
            raise EvidenceError(f"unsupported Git tree entry {item!r}")
        try:
            oid_text = object_id.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise EvidenceError("Git returned a non-ASCII object id") from exc
        if not _HEX_OBJECT_RE.fullmatch(oid_text):
            raise EvidenceError(f"Git returned an invalid object id {oid_text!r}")
        entries.append(_TreeEntry(mode, kind, object_id, path))
    entries.sort(key=lambda entry: entry.path)
    if len({entry.path for entry in entries}) != len(entries):
        raise EvidenceError("Git tree contains duplicate paths")
    return entries


def _frame(hasher, value: bytes) -> None:
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _source_tree_digest(
    repository: Path,
    entries: Sequence[_TreeEntry],
    *,
    blob_reader: Callable[[str], bytes] | None = None,
    git_executable: str | os.PathLike[str] | None = None,
) -> str:
    """Hash path, mode, kind and exact blob bytes for every tracked entry.

    Gitlink entries contribute their exact commit object id.  The algorithm is
    independent of tar metadata, checkout mtimes, filesystem ordering and the
    repository's Git object format.
    """
    if blob_reader is None:
        def blob_reader(oid):
            if git_executable is None:
                raise EvidenceError("source-tree blob reads require an absolute Git executable")
            return _git(
                repository,
                "cat-file",
                "blob",
                oid,
                executable=git_executable,
            )
    hasher = hashlib.sha256()
    hasher.update(b"quarry.git-tree-sha256.v1\0")
    blob_cache: dict[str, bytes] = {}
    for entry in entries:
        _frame(hasher, entry.path)
        _frame(hasher, entry.mode)
        _frame(hasher, entry.kind)
        object_id = entry.object_id.decode("ascii")
        if entry.kind == b"blob":
            body = blob_cache.get(object_id)
            if body is None:
                body = blob_reader(object_id)
                blob_cache[object_id] = body
            _frame(hasher, body)
        else:
            _frame(hasher, entry.object_id)
    return "sha256:" + hasher.hexdigest()


def _submodule_identities(raw: bytes) -> list[dict]:
    records = []
    for index, line in enumerate(raw.splitlines()):
        if not line:
            continue
        match = _SUBMODULE_STATUS_RE.fullmatch(line)
        if match is None:
            raise EvidenceError(f"Git returned malformed submodule status at line {index + 1}")
        state, commit, path_bytes = match.groups()
        if state != b" ":
            labels = {b"-": "uninitialized", b"+": "checked out at another commit", b"U": "conflicted"}
            raise EvidenceError(f"submodule is {labels.get(state, 'not clean')}: {path_bytes!r}")
        try:
            path = path_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise EvidenceError("submodule path is not UTF-8 and cannot enter public evidence") from exc
        records.append({
            "git_commit": commit.decode("ascii"),
            "path": _safe_relative_path(path, "submodule path"),
        })
    records.sort(key=lambda record: record["path"])
    if len({record["path"] for record in records}) != len(records):
        raise EvidenceError("Git returned duplicate recursive submodule paths")
    return records


def _refuse_hidden_index_entries(raw: bytes) -> None:
    """Reject index flags/statuses that can hide worktree changes from Git status."""
    for item in raw.split(b"\0"):
        if not item:
            continue
        if len(item) < 3 or item[1:2] != b" ":
            raise EvidenceError("Git returned malformed index visibility data")
        if item[:1] != b"H":
            raise EvidenceError("candidate index contains a hidden or non-canonical visibility state")


def _index_entries(raw: bytes) -> list[_TreeEntry]:
    entries = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            metadata, path = item.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
        except ValueError as exc:
            raise EvidenceError("Git returned a malformed index entry") from exc
        kind = b"commit" if mode == b"160000" else b"blob"
        if stage != b"0" or not _valid_tree_shape(mode, kind, path):
            raise EvidenceError("candidate index contains an unmerged or unsupported entry")
        try:
            oid_text = object_id.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise EvidenceError("Git returned a non-ASCII index object id") from exc
        if not _HEX_OBJECT_RE.fullmatch(oid_text):
            raise EvidenceError("candidate index contains an invalid object id")
        entries.append(_TreeEntry(mode, kind, object_id, path))
    entries.sort(key=lambda entry: entry.path)
    if len({entry.path for entry in entries}) != len(entries):
        raise EvidenceError("candidate index contains duplicate paths")
    return entries


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _refuse_raw_worktree_mismatch(
    checkout: Path,
    entries: Sequence[_TreeEntry],
    *,
    blob_reader: Callable[[str], bytes],
    label: str,
) -> None:
    checked_directories = {checkout}
    for entry in entries:
        parts = [os.fsdecode(part) for part in entry.path.split(b"/")]
        relative = Path(*parts)
        for count in range(1, len(parts)):
            parent = checkout / Path(*parts[:count])
            if parent in checked_directories:
                continue
            try:
                parent_stat = os.lstat(parent)
            except OSError as exc:
                raise EvidenceError(f"dirty {label} worktree is missing a committed directory") from exc
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise EvidenceError(f"dirty {label} worktree has a non-directory committed parent")
            checked_directories.add(parent)

        path = checkout / relative
        try:
            before = os.lstat(path)
        except OSError as exc:
            raise EvidenceError(f"dirty {label} worktree is missing a committed entry") from exc

        if entry.kind == b"commit":
            if not stat.S_ISDIR(before.st_mode):
                raise EvidenceError(f"dirty {label} worktree gitlink is not a directory")
            continue

        expected = blob_reader(entry.object_id.decode("ascii"))
        if entry.mode == b"120000":
            if not stat.S_ISLNK(before.st_mode):
                raise EvidenceError(f"dirty {label} worktree symlink type does not match the committed tree")
            try:
                actual = os.fsencode(os.readlink(path))
                after = os.lstat(path)
            except OSError as exc:
                raise EvidenceError(f"cannot read {label} worktree symlink") from exc
            if actual != expected or _stat_signature(before) != _stat_signature(after):
                raise EvidenceError(f"dirty {label} worktree symlink does not match the committed tree")
            continue

        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"dirty {label} worktree file type does not match the committed tree")
        if os.name == "posix" and bool(before.st_mode & 0o111) != (entry.mode == b"100755"):
            raise EvidenceError(f"dirty {label} worktree executable mode does not match the committed tree")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise EvidenceError(f"cannot open {label} worktree file without following links") from exc
        try:
            opened = os.fstat(descriptor)
            offset = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                if expected[offset:offset + len(chunk)] != chunk:
                    raise EvidenceError(f"dirty {label} worktree bytes do not match the committed tree")
                offset += len(chunk)
            after = os.fstat(descriptor)
        except BaseException as primary:
            try:
                os.close(descriptor)
            except BaseException as close_fault:
                if type(primary) not in {KeyboardInterrupt, SystemExit} and type(close_fault) in {
                    KeyboardInterrupt,
                    SystemExit,
                }:
                    raise
            if isinstance(primary, OSError):
                raise EvidenceError(f"cannot read {label} worktree file exactly: {primary}") from primary
            raise
        else:
            try:
                os.close(descriptor)
            except BaseException as close_fault:
                if isinstance(close_fault, OSError):
                    raise EvidenceError(f"cannot close {label} worktree file exactly: {close_fault}") \
                        from close_fault
                raise
        if (
            offset != len(expected)
            or _stat_signature(before) != _stat_signature(opened)
            or _stat_signature(opened) != _stat_signature(after)
        ):
            raise EvidenceError(f"dirty {label} worktree file does not stably match the committed tree")


def _refuse_dirty_checkout(
    repository: Path,
    candidate_commit: str,
    submodules: Sequence[dict],
    *,
    git_executable: str | os.PathLike[str],
) -> tuple[list[_TreeEntry], dict[str, bytes]]:
    checkouts = [(repository, "candidate", candidate_commit)]
    for record in submodules:
        relative = PurePosixPath(record["path"])
        checkout = repository.joinpath(*relative.parts)
        try:
            resolved = checkout.resolve(strict=True)
        except OSError as exc:
            raise EvidenceError(f"cannot resolve initialized submodule checkout: {exc}") from exc
        if not resolved.is_relative_to(repository):
            raise EvidenceError("initialized submodule checkout escapes the candidate repository")
        checkouts.append((resolved, "submodule", record["git_commit"]))

    candidate_entries: list[_TreeEntry] = []
    candidate_blob_cache: dict[str, bytes] = {}
    for checkout, label, expected_commit in checkouts:
        try:
            reported_root = Path(
                _one_ascii_line(
                    _git(checkout, "rev-parse", "--show-toplevel", executable=git_executable),
                    f"{label} worktree root",
                )
            ).resolve(strict=True)
        except OSError as exc:
            raise EvidenceError(f"cannot resolve {label} Git worktree root: {exc}") from exc
        if reported_root != checkout:
            raise EvidenceError(f"{label} Git worktree root does not match the expected checkout")
        observed_commit = _one_ascii_line(
            _git(checkout, "rev-parse", "--verify", "HEAD^{commit}", executable=git_executable),
            f"{label} commit id",
        )
        if observed_commit != expected_commit:
            raise EvidenceError(f"{label} HEAD changed from its recorded commit")
        entries = _tree_entries(checkout, expected_commit, git_executable=git_executable)
        index_entries = _index_entries(
            _git(checkout, "ls-files", "--stage", "-z", executable=git_executable)
        )
        if index_entries != entries:
            raise EvidenceError(f"dirty {label} index does not match its committed tree")
        _refuse_hidden_index_entries(
            _git(checkout, "ls-files", "-v", "-z", executable=git_executable)
        )
        if _git(
            checkout,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            executable=git_executable,
        ):
            raise EvidenceError(f"dirty {label} worktree contains non-ignored untracked paths")
        blob_cache = candidate_blob_cache if label == "candidate" else {}

        def read_blob(
            object_id: str,
            *,
            _checkout: Path = checkout,
            _blob_cache: dict[str, bytes] = blob_cache,
        ) -> bytes:
            body = _blob_cache.get(object_id)
            if body is None:
                body = _git(_checkout, "cat-file", "blob", object_id, executable=git_executable)
                _blob_cache[object_id] = body
            return body

        _refuse_raw_worktree_mismatch(checkout, entries, blob_reader=read_blob, label=label)
        if label == "candidate":
            candidate_entries = entries

    return candidate_entries, candidate_blob_cache


def _safe_relative_path(value: str, name: str) -> str:
    if type(value) is not str or not value or any(ord(char) < 0x20 for char in value):
        raise EvidenceError(f"{name} must be a non-empty relative path")
    path = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        path.is_absolute()
        or bool(windows.drive or windows.root)
        or "\\" in value
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise EvidenceError(f"{name} must be a normalized repository-relative POSIX path")
    return value


def _absolute_tool_path(value: object, name: str) -> str:
    text = _nonempty_string(value, name)
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if not posix.is_absolute() and not windows.is_absolute():
        raise EvidenceError(f"{name} must be an absolute executable path")
    if posix.is_absolute():
        parts = posix.parts
        spellings = {posix.as_posix()}
    else:
        parts = windows.parts
        spellings = {str(windows), windows.as_posix()}
    if any(part in {".", ".."} for part in parts):
        raise EvidenceError(f"{name} must be a normalized absolute executable path")
    if text not in spellings:
        raise EvidenceError(f"{name} must be a normalized absolute executable path")
    return text


def _decode_tracked_text(body: bytes, path: str) -> str:
    try:
        return body.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"tracked input {path!r} is not strict UTF-8") from exc


def _project_version(pyproject: bytes) -> str:
    text = _decode_tracked_text(pyproject, "pyproject.toml")
    if _toml is None:
        raise EvidenceError("semantic TOML parsing requires tomli on Python 3.10")
    try:
        document = _toml.loads(text)
    except (RecursionError, TypeError, ValueError) as exc:
        raise EvidenceError(f"pyproject.toml is not valid TOML: {exc}") from exc
    project = document.get("project")
    if type(project) is not dict:
        raise EvidenceError("pyproject.toml must contain exactly one semantic [project] table")
    value = project.get("version")
    if type(value) is not str or not value or any(ord(char) < 0x20 for char in value):
        raise EvidenceError("pyproject.toml must declare one literal semantic [project].version")
    dynamic = project.get("dynamic", [])
    if type(dynamic) is not list or any(type(member) is not str for member in dynamic):
        raise EvidenceError("pyproject.toml project.dynamic must be an array of strings")
    if "version" in dynamic:
        raise EvidenceError("pyproject.toml cannot declare project.version as both literal and dynamic")
    return value


def _runtime_version(initializer: bytes) -> str:
    text = _decode_tracked_text(initializer, "src/quarry_recon/__init__.py")
    try:
        module = ast.parse(text, filename="src/quarry_recon/__init__.py", mode="exec")
    except (RecursionError, SyntaxError, ValueError) as exc:
        raise EvidenceError(f"quarry_recon.__init__ is not valid Python: {exc}") from exc
    statements = list(module.body)
    if statements and isinstance(statements[0], ast.Expr) and isinstance(
        statements[0].value, ast.Constant
    ) and type(statements[0].value.value) is str:
        statements.pop(0)
    if len(statements) != 1 or not isinstance(statements[0], ast.Assign):
        raise EvidenceError(
            "quarry_recon.__init__ may contain only a module docstring and one literal __version__ assignment"
        )
    declaration = statements[0]
    if (
        len(declaration.targets) != 1
        or not isinstance(declaration.targets[0], ast.Name)
        or declaration.targets[0].id != "__version__"
    ):
        raise EvidenceError("quarry_recon.__init__.__version__ must be one literal string assignment")
    value_node = declaration.value
    if not isinstance(value_node, ast.Constant) or type(value_node.value) is not str:
        raise EvidenceError("quarry_recon.__init__.__version__ must be one literal string assignment")
    return _nonempty_string(value_node.value, "quarry_recon.__init__.__version__")


def _validate_schema_registry(document: object) -> dict:
    registry = _object(
        document,
        "release schema registry",
        {"identity_inputs", "release", "schema_version", "schemas"},
    )
    if registry["schema_version"] != REGISTRY_SCHEMA:
        raise EvidenceError(f"unsupported release schema registry {registry['schema_version']!r}")
    if registry["release"] != RELEASE_SCOPE:
        raise EvidenceError(f"release schema registry must bind release {RELEASE_SCOPE!r}")

    schemas = _array(registry["schemas"], "release schema registry.schemas")
    normalized_schemas = []
    for index, record in enumerate(schemas):
        item = _object(record, f"release schema registry.schemas[{index}]", {"name", "path", "record_version"})
        name = _token(item["name"], f"release schema registry.schemas[{index}].name")
        path = _safe_relative_path(item["path"], f"release schema registry.schemas[{index}].path")
        version = _nonempty_string(
            item["record_version"], f"release schema registry.schemas[{index}].record_version"
        )
        normalized_schemas.append({"name": name, "path": path, "record_version": version})
    _ordered_unique(normalized_schemas, "name", "release schema registry.schemas")
    expected_schemas = [
        {"name": name, "path": SCHEMA_PATHS[name], "record_version": SCHEMA_VERSIONS[name]}
        for name in sorted(SCHEMA_VERSIONS)
    ]
    if normalized_schemas != expected_schemas:
        raise EvidenceError("release schema registry does not match the supported schema inventory")

    identity_inputs = _array(registry["identity_inputs"], "release schema registry.identity_inputs")
    normalized_inputs = []
    for index, record in enumerate(identity_inputs):
        item = _object(record, f"release schema registry.identity_inputs[{index}]", {"name", "path"})
        name = _token(item["name"], f"release schema registry.identity_inputs[{index}].name")
        path = _safe_relative_path(item["path"], f"release schema registry.identity_inputs[{index}].path")
        normalized_inputs.append({"name": name, "path": path})
    _ordered_unique(normalized_inputs, "name", "release schema registry.identity_inputs")
    expected_inputs = [{"name": name, "path": path} for name, path in sorted(DEFAULT_IDENTITY_INPUTS.items())]
    if normalized_inputs != expected_inputs:
        raise EvidenceError("release schema registry does not match the required identity inputs")
    _bounded_record(registry, "release schema registry")
    return registry


def _validate_registered_schema(document: object, *, name: str, record_version: str) -> dict:
    if type(document) is not dict:
        raise EvidenceError(f"registered {name} schema must be a JSON object")
    for key in ("$id", "$schema", "additionalProperties", "properties", "required", "type"):
        if key not in document:
            raise EvidenceError(f"registered {name} schema is missing {key!r}")
    if document["$schema"] != "https://json-schema.org/draft/2020-12/schema":
        raise EvidenceError(f"registered {name} schema does not use JSON Schema 2020-12")
    if document["type"] != "object" or document["additionalProperties"] is not False:
        raise EvidenceError(f"registered {name} schema must be an exact object")
    properties = document["properties"]
    if type(properties) is not dict or type(properties.get("schema_version")) is not dict:
        raise EvidenceError(f"registered {name} schema does not define schema_version")
    if properties["schema_version"].get("const") != record_version:
        raise EvidenceError(f"registered {name} schema version disagrees with the registry")
    required = document["required"]
    if (
        type(required) is not list
        or any(type(member) is not str for member in required)
        or len(set(required)) != len(required)
        or set(required) != set(properties)
    ):
        raise EvidenceError(f"registered {name} schema must require every declared member")
    _bounded_record(document, f"registered {name} schema")
    return document


def _entry_map(entries: Iterable[_TreeEntry]) -> dict[bytes, _TreeEntry]:
    return {entry.path: entry for entry in entries}


def _tracked_blob(
    repository: Path,
    entries: Mapping[bytes, _TreeEntry],
    path: str,
    *,
    blob_reader: Callable[[str], bytes] | None = None,
    git_executable: str | os.PathLike[str] | None = None,
) -> tuple[_TreeEntry, bytes]:
    encoded = path.encode("utf-8", "strict")
    entry = entries.get(encoded)
    if entry is None or entry.kind != b"blob" or entry.mode not in {b"100644", b"100755"}:
        raise EvidenceError(f"identity input {path!r} is not a regular tracked blob in the candidate")
    if blob_reader is None and git_executable is None:
        raise EvidenceError("tracked blob reads require an absolute Git executable")
    reader = blob_reader or (lambda oid: _git(
        repository,
        "cat-file",
        "blob",
        oid,
        executable=git_executable,
    ))
    return entry, reader(entry.object_id.decode("ascii"))


def collect_candidate_identity(
    repository: str | os.PathLike[str],
    release: str,
    *,
    git_executable: str | os.PathLike[str],
    inputs: Mapping[str, str] | None = None,
) -> dict:
    """Collect a deterministic identity for the clean candidate at ``HEAD``.

    Ignored paths are outside the candidate by definition.  Every tracked,
    staged, untracked (non-ignored), or dirty-submodule change observed inside
    the caller's quiescent candidate-only epoch refuses collection; the function
    never emits a ``dirty: true`` candidate record.  This process does not create
    that isolation epoch, so its output is not release-eligible when invoked on
    an ambient checkout that another writer can mutate concurrently.
    """
    if release != RELEASE_SCOPE:
        raise EvidenceError(f"candidate release must match the v1 scope {RELEASE_SCOPE!r}")
    repo_arg = Path(repository)
    requested_git_directory = _resolved_git_directory(
        repo_arg,
        git_executable=git_executable,
    )
    root = Path(_one_ascii_line(
        _git(repo_arg, "rev-parse", "--show-toplevel", executable=git_executable),
        "repository root",
    ))
    try:
        root = root.resolve(strict=True)
        requested_location = repo_arg.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"cannot resolve repository root: {exc}") from exc
    if not requested_location.is_relative_to(root):
        raise EvidenceError("Git worktree root does not contain the requested candidate location")
    if _resolved_git_directory(root, git_executable=git_executable) != requested_git_directory:
        raise EvidenceError("resolved candidate root belongs to a different Git directory")

    commit = _one_ascii_line(
        _git(root, "rev-parse", "--verify", "HEAD^{commit}", executable=git_executable),
        "commit id",
    )
    tree = _one_ascii_line(
        _git(root, "rev-parse", "--verify", f"{commit}^{{tree}}", executable=git_executable),
        "tree id",
    )
    if not _HEX_OBJECT_RE.fullmatch(commit) or not _HEX_OBJECT_RE.fullmatch(tree):
        raise EvidenceError("Git returned an unsupported object id")
    submodule_status = _git(root, "submodule", "status", "--recursive", executable=git_executable)
    submodules = _submodule_identities(submodule_status)
    entries, blob_cache = _refuse_dirty_checkout(
        root,
        commit,
        submodules,
        git_executable=git_executable,
    )
    by_path = _entry_map(entries)

    def read_blob(object_id: str) -> bytes:
        body = blob_cache.get(object_id)
        if body is None:
            body = _git(root, "cat-file", "blob", object_id, executable=git_executable)
            blob_cache[object_id] = body
        return body

    _, registry_body = _tracked_blob(root, by_path, REGISTRY_PATH, blob_reader=read_blob)
    registry = _validate_schema_registry(load_json_bytes(registry_body))
    for schema in registry["schemas"]:
        _, schema_body = _tracked_blob(root, by_path, schema["path"], blob_reader=read_blob)
        _validate_registered_schema(
            load_json_bytes(schema_body),
            name=schema["name"],
            record_version=schema["record_version"],
        )

    _, pyproject = _tracked_blob(root, by_path, "pyproject.toml", blob_reader=read_blob)
    _, initializer = _tracked_blob(root, by_path, "src/quarry_recon/__init__.py", blob_reader=read_blob)
    pyproject_version = _project_version(pyproject)
    runtime_version = _runtime_version(initializer)
    if pyproject_version != runtime_version:
        raise EvidenceError(
            f"package version disagreement: pyproject={pyproject_version!r}, runtime={runtime_version!r}"
        )

    if inputs is not None and not isinstance(inputs, Mapping):
        raise EvidenceError("identity inputs must be a name-to-path mapping")
    selected_inputs = dict(DEFAULT_IDENTITY_INPUTS)
    for name, path in (inputs or {}).items():
        if type(name) is not str or not _TOKEN_RE.fullmatch(name):
            raise EvidenceError(f"invalid identity input name {name!r}")
        if name in selected_inputs and selected_inputs[name] != path:
            raise EvidenceError(f"identity input {name!r} conflicts with the required path")
        selected_inputs[name] = _safe_relative_path(path, f"input {name!r}")

    input_records = []
    for name, path in sorted(selected_inputs.items()):
        normalized = _safe_relative_path(path, f"input {name!r}")
        _, body = _tracked_blob(root, by_path, normalized, blob_reader=read_blob)
        input_records.append({
            "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "name": name,
            "path": normalized,
        })

    package_sources = []
    for path, value, body in (
        ("pyproject.toml", pyproject_version, pyproject),
        ("src/quarry_recon/__init__.py", runtime_version, initializer),
    ):
        package_sources.append({
            "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "path": path,
            "value": value,
        })

    direct_gitlinks = {}
    for entry in entries:
        if entry.kind == b"commit":
            try:
                direct_gitlinks[entry.path.decode("utf-8", "strict")] = entry.object_id.decode("ascii")
            except UnicodeDecodeError as exc:
                raise EvidenceError("submodule path is not UTF-8 and cannot enter public evidence") from exc
    observed = {record["path"]: record["git_commit"] for record in submodules}
    for path, commit_id in direct_gitlinks.items():
        if observed.get(path) != commit_id:
            raise EvidenceError(f"submodule {path!r} is not initialized at its candidate gitlink")

    document = {
        "dirty": False,
        "git_commit": commit,
        "git_tree": tree,
        "inputs": input_records,
        "package_version": pyproject_version,
        "package_version_sources": package_sources,
        "release": _nonempty_string(release, "release"),
        "schema_version": CANDIDATE_SCHEMA,
        "schema_versions": dict(SCHEMA_VERSIONS),
        "source_tree_digest": _source_tree_digest(root, entries, blob_reader=read_blob),
        "source_tree_digest_algorithm": SOURCE_TREE_ALGORITHM,
        "submodules": submodules,
    }
    if _one_ascii_line(
        _git(root, "rev-parse", "--verify", "HEAD^{commit}", executable=git_executable),
        "commit id",
    ) != commit:
        raise EvidenceError("candidate HEAD changed during identity collection")
    _refuse_dirty_checkout(root, commit, submodules, git_executable=git_executable)
    if _git(root, "submodule", "status", "--recursive", executable=git_executable) != submodule_status:
        raise EvidenceError("submodule identity changed during identity collection")
    validate_candidate_identity(document)
    return document


def _object(value: object, name: str, required: set[str]) -> dict:
    if type(value) is not dict:
        raise EvidenceError(f"{name} must be an object")
    if any(type(key) is not str for key in value):
        raise EvidenceError(f"{name} member names must be strings")
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        unknown = sorted(keys - required)
        details = []
        if missing:
            details.append(f"missing {missing}")
        if unknown:
            details.append(f"unknown {unknown}")
        raise EvidenceError(f"{name} has invalid members ({'; '.join(details)})")
    return value


def _array(value: object, name: str) -> list:
    if type(value) is not list:
        raise EvidenceError(f"{name} must be an array")
    return value


def _nonempty_string(value: object, name: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or any(ord(char) < 0x20 for char in value)
    ):
        raise EvidenceError(f"{name} must be a non-empty control-free string")
    return value


def _token(value: object, name: str) -> str:
    text = _nonempty_string(value, name)
    if not _TOKEN_RE.fullmatch(text):
        raise EvidenceError(f"{name} must be a stable token")
    return text


def _digest(value: object, name: str) -> str:
    if type(value) is not str or not _DIGEST_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a lowercase sha256: digest")
    return value


def _object_id(value: object, name: str) -> str:
    if type(value) is not str or not _HEX_OBJECT_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a full lowercase Git object id")
    return value


def _exact_nonnegative_int(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_JSON_INTEGER:
        raise EvidenceError(f"{name} must be an exact non-negative integer no larger than 2^63-1")
    return value


def _timestamp(value: object, name: str) -> datetime:
    text = _nonempty_string(value, name)
    match = _RFC3339_RE.fullmatch(text)
    if match is None:
        raise EvidenceError(f"{name} must be an RFC3339 timestamp")
    zone = match.group("zone")
    if zone != "Z":
        hour = int(zone[1:3])
        minute = int(zone[4:6])
        if hour > 23 or minute > 59 or zone == "-00:00":
            raise EvidenceError(f"{name} must use a known RFC3339 UTC offset")
    fraction = match.group("fraction")
    if fraction:
        fraction = "." + fraction[1:].ljust(6, "0")
    normalized = match.group("base") + (fraction or "")
    normalized += "+00:00" if zone == "Z" else zone
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EvidenceError(f"{name} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceError(f"{name} must include an RFC3339 timezone")
    return parsed


def _ordered_unique(records: list[dict], key: str, name: str) -> None:
    values = [record[key] for record in records]
    if values != sorted(values):
        raise EvidenceError(f"{name} must be sorted by {key}")
    if len(set(values)) != len(values):
        raise EvidenceError(f"{name} contains duplicate {key} values")


def _bounded_record(document: object, name: str) -> None:
    if len(canonical_json_bytes(document)) > MAX_RECORD_BYTES:
        raise EvidenceError(f"{name} exceeds {MAX_RECORD_BYTES} canonical bytes")


def validate_candidate_identity(document: object) -> dict:
    """Validate and return a v1 candidate-identity document."""
    required = {
        "dirty",
        "git_commit",
        "git_tree",
        "inputs",
        "package_version",
        "package_version_sources",
        "release",
        "schema_version",
        "schema_versions",
        "source_tree_digest",
        "source_tree_digest_algorithm",
        "submodules",
    }
    doc = _object(document, "candidate identity", required)
    if doc["schema_version"] != CANDIDATE_SCHEMA:
        raise EvidenceError(f"unsupported candidate schema {doc['schema_version']!r}")
    if doc["release"] != RELEASE_SCOPE:
        raise EvidenceError(f"candidate.release must match the v1 scope {RELEASE_SCOPE!r}")
    _object_id(doc["git_commit"], "candidate.git_commit")
    _object_id(doc["git_tree"], "candidate.git_tree")
    if doc["dirty"] is not False:
        raise EvidenceError("candidate.dirty must be exactly false")
    _digest(doc["source_tree_digest"], "candidate.source_tree_digest")
    if doc["source_tree_digest_algorithm"] != SOURCE_TREE_ALGORITHM:
        raise EvidenceError("unsupported source-tree digest algorithm")
    package_version = _nonempty_string(doc["package_version"], "candidate.package_version")

    versions = _object(doc["schema_versions"], "candidate.schema_versions", set(SCHEMA_VERSIONS))
    if versions != SCHEMA_VERSIONS:
        raise EvidenceError("candidate schema-version inventory does not match this reader")

    package_sources = _array(doc["package_version_sources"], "candidate.package_version_sources")
    if len(package_sources) != 2:
        raise EvidenceError("candidate must bind exactly the two package-version sources")
    normalized_sources = []
    for index, source in enumerate(package_sources):
        item = _object(source, f"candidate.package_version_sources[{index}]", {"digest", "path", "value"})
        path = _safe_relative_path(item["path"], f"candidate.package_version_sources[{index}].path")
        _digest(item["digest"], f"candidate.package_version_sources[{index}].digest")
        if item["value"] != package_version:
            raise EvidenceError("candidate package-version sources disagree")
        normalized_sources.append({**item, "path": path})
    _ordered_unique(normalized_sources, "path", "candidate.package_version_sources")
    if [source["path"] for source in normalized_sources] != [
        "pyproject.toml",
        "src/quarry_recon/__init__.py",
    ]:
        raise EvidenceError("candidate package-version sources are not the canonical pair")

    input_records = _array(doc["inputs"], "candidate.inputs")
    input_digests_by_path: dict[str, str] = {}
    for index, record in enumerate(input_records):
        item = _object(record, f"candidate.inputs[{index}]", {"digest", "name", "path"})
        _token(item["name"], f"candidate.inputs[{index}].name")
        path = _safe_relative_path(item["path"], f"candidate.inputs[{index}].path")
        digest = _digest(item["digest"], f"candidate.inputs[{index}].digest")
        prior_digest = input_digests_by_path.setdefault(path, digest)
        if prior_digest != digest:
            raise EvidenceError(f"candidate inputs disagree on the digest for {path!r}")
    _ordered_unique(input_records, "name", "candidate.inputs")
    declared_inputs = {record["name"]: record["path"] for record in input_records}
    for name, path in DEFAULT_IDENTITY_INPUTS.items():
        if declared_inputs.get(name) != path:
            raise EvidenceError(f"candidate inputs omit or redirect required input {name!r}")
    for source in normalized_sources:
        if input_digests_by_path.get(source["path"]) != source["digest"]:
            raise EvidenceError(
                f"candidate input and package-version source disagree for {source['path']!r}"
            )

    submodules = _array(doc["submodules"], "candidate.submodules")
    for index, record in enumerate(submodules):
        item = _object(record, f"candidate.submodules[{index}]", {"git_commit", "path"})
        _safe_relative_path(item["path"], f"candidate.submodules[{index}].path")
        _object_id(item["git_commit"], f"candidate.submodules[{index}].git_commit")
    _ordered_unique(submodules, "path", "candidate.submodules")
    _bounded_record(doc, "candidate identity")
    return doc


def candidate_summary(identity: object) -> dict:
    """Return the exact candidate binding embedded in every gate record."""
    doc = validate_candidate_identity(identity)
    return {
        "dirty": doc["dirty"],
        "git_commit": doc["git_commit"],
        "git_tree": doc["git_tree"],
        "identity_digest": canonical_digest(doc),
        "package_version": doc["package_version"],
        "source_tree_digest": doc["source_tree_digest"],
    }


def _validate_named_digests(value: object, name: str) -> list[dict]:
    records = _array(value, name)
    for index, record in enumerate(records):
        item = _object(record, f"{name}[{index}]", {"digest", "name"})
        _token(item["name"], f"{name}[{index}].name")
        _digest(item["digest"], f"{name}[{index}].digest")
    _ordered_unique(records, "name", name)
    return records


def validate_gate_record(document: object, *, identity: object) -> dict:
    """Validate and return a strict v1 release-gate record.

    Cryptographic signature verification and artifact opening are intentionally
    aggregator responsibilities.  This reader validates their identities and
    structural envelope without claiming either one was verified.
    """
    required = {
        "artifacts",
        "assertions",
        "candidate",
        "environment",
        "finished_at",
        "gate_id",
        "inputs",
        "lane",
        "not_applicable_rule",
        "reason",
        "release",
        "required",
        "schema_version",
        "selection",
        "signature",
        "started_at",
        "status",
        "toolchain",
    }
    doc = _object(document, "gate record", required)
    if doc["schema_version"] != GATE_SCHEMA:
        raise EvidenceError(f"unsupported gate schema {doc['schema_version']!r}")
    _nonempty_string(doc["release"], "gate.release")
    gate_id = _nonempty_string(doc["gate_id"], "gate.gate_id")
    if not _GATE_ID_RE.fullmatch(gate_id):
        raise EvidenceError("gate.gate_id is not a canonical gate id")
    if doc["lane"] not in LANES:
        raise EvidenceError(f"gate.lane is not a supported execution lane: {doc['lane']!r}")
    if type(doc["required"]) is not bool:
        raise EvidenceError("gate.required must be an exact boolean")
    if doc["status"] not in GATE_STATUSES:
        raise EvidenceError(f"gate.status is invalid: {doc['status']!r}")

    candidate = _object(doc["candidate"], "gate.candidate", {
        "dirty",
        "git_commit",
        "git_tree",
        "identity_digest",
        "package_version",
        "source_tree_digest",
    })
    if candidate["dirty"] is not False:
        raise EvidenceError("gate.candidate.dirty must be exactly false")
    _object_id(candidate["git_commit"], "gate.candidate.git_commit")
    _object_id(candidate["git_tree"], "gate.candidate.git_tree")
    _digest(candidate["identity_digest"], "gate.candidate.identity_digest")
    _nonempty_string(candidate["package_version"], "gate.candidate.package_version")
    _digest(candidate["source_tree_digest"], "gate.candidate.source_tree_digest")
    expected_identity = validate_candidate_identity(identity)
    expected = candidate_summary(expected_identity)
    if candidate != expected or doc["release"] != expected_identity["release"]:
        raise EvidenceError("gate record does not match the exact candidate identity")

    started = _timestamp(doc["started_at"], "gate.started_at")
    finished = _timestamp(doc["finished_at"], "gate.finished_at")
    if finished < started:
        raise EvidenceError("gate.finished_at precedes gate.started_at")

    environment = _object(doc["environment"], "gate.environment", {
        "architecture", "isolation_profile", "os", "python", "runner_image",
    })
    for key in ("architecture", "os", "python"):
        _nonempty_string(environment[key], f"gate.environment.{key}")
    _digest(environment["runner_image"], "gate.environment.runner_image")
    _digest(environment["isolation_profile"], "gate.environment.isolation_profile")

    _validate_named_digests(doc["inputs"], "gate.inputs")
    toolchain = _array(doc["toolchain"], "gate.toolchain")
    for index, record in enumerate(toolchain):
        item = _object(record, f"gate.toolchain[{index}]", {"digest", "name", "path", "version"})
        _token(item["name"], f"gate.toolchain[{index}].name")
        _absolute_tool_path(item["path"], f"gate.toolchain[{index}].path")
        _nonempty_string(item["version"], f"gate.toolchain[{index}].version")
        _digest(item["digest"], f"gate.toolchain[{index}].digest")
    _ordered_unique(toolchain, "name", "gate.toolchain")

    selection = _object(doc["selection"], "gate.selection", {
        "collected", "deselected", "failed", "passed", "selected", "skipped", "xfailed", "xpassed",
    })
    counts = {key: _exact_nonnegative_int(value, f"gate.selection.{key}")
              for key, value in selection.items()}
    if counts["collected"] != counts["selected"] + counts["deselected"]:
        raise EvidenceError("gate selection does not reconcile collected=selected+deselected")
    terminal = sum(counts[key] for key in ("passed", "failed", "skipped", "xfailed", "xpassed"))
    if counts["selected"] != terminal:
        raise EvidenceError("gate selection does not reconcile selected terminal outcomes")

    assertions = _array(doc["assertions"], "gate.assertions")
    for index, record in enumerate(assertions):
        item = _object(record, f"gate.assertions[{index}]", {"id", "reason", "status"})
        _token(item["id"], f"gate.assertions[{index}].id")
        if item["status"] not in GATE_STATUSES:
            raise EvidenceError(f"gate.assertions[{index}].status is invalid")
        if item["reason"] is not None:
            _nonempty_string(item["reason"], f"gate.assertions[{index}].reason")
    _ordered_unique(assertions, "id", "gate.assertions")

    artifacts = _array(doc["artifacts"], "gate.artifacts")
    for index, record in enumerate(artifacts):
        item = _object(record, f"gate.artifacts[{index}]", {"digest", "media_type", "name"})
        _token(item["name"], f"gate.artifacts[{index}].name")
        if type(item["media_type"]) is not str or not _MEDIA_TYPE_RE.fullmatch(item["media_type"]):
            raise EvidenceError(f"gate.artifacts[{index}].media_type is invalid")
        _digest(item["digest"], f"gate.artifacts[{index}].digest")
    _ordered_unique(artifacts, "name", "gate.artifacts")

    reason = doc["reason"]
    if reason is not None:
        _nonempty_string(reason, "gate.reason")
    rule = doc["not_applicable_rule"]
    if doc["status"] == "not_applicable":
        if reason is None or rule is None:
            raise EvidenceError("not_applicable gate needs a reason and pre-approved scope rule")
        rule_doc = _object(rule, "gate.not_applicable_rule", {"approved_at", "digest", "expires_at", "id"})
        _token(rule_doc["id"], "gate.not_applicable_rule.id")
        _digest(rule_doc["digest"], "gate.not_applicable_rule.digest")
        approved = _timestamp(rule_doc["approved_at"], "gate.not_applicable_rule.approved_at")
        if approved >= started:
            raise EvidenceError("not_applicable scope rule was not approved before execution")
        if rule_doc["expires_at"] is not None:
            expires = _timestamp(rule_doc["expires_at"], "gate.not_applicable_rule.expires_at")
            if expires <= approved:
                raise EvidenceError("not_applicable scope rule expires before it is approved")
            if expires <= finished:
                raise EvidenceError("not_applicable scope rule expired before gate completion")
    elif rule is not None:
        raise EvidenceError("only not_applicable gates may carry a scope rule")
    elif doc["status"] == "pass":
        if reason is not None:
            raise EvidenceError("passing gate must not carry a blocking reason")
        if any(counts[key] for key in ("failed", "skipped", "xfailed", "xpassed")):
            raise EvidenceError("passing gate contains a non-pass test-runner outcome")
        if any(assertion["status"] != "pass" for assertion in assertions):
            raise EvidenceError("passing gate contains a non-pass assertion")
        if counts["selected"] == 0 and not assertions and not artifacts:
            raise EvidenceError("passing gate contains no executed assertion or evidence artifact")
    elif reason is None:
        raise EvidenceError(f"{doc['status']} gate needs a reason")

    signature = doc["signature"]
    if signature is not None:
        signature_doc = _object(signature, "gate.signature", {"algorithm", "key_id", "value"})
        _token(signature_doc["algorithm"], "gate.signature.algorithm")
        _token(signature_doc["key_id"], "gate.signature.key_id")
        value = _nonempty_string(signature_doc["value"], "gate.signature.value")
        if not value.startswith("base64:"):
            raise EvidenceError("gate.signature.value must use the base64: encoding label")
        try:
            decoded = base64.b64decode(value[7:], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise EvidenceError("gate.signature.value is not valid canonical base64") from exc
        if not decoded or base64.b64encode(decoded).decode("ascii") != value[7:]:
            raise EvidenceError("gate.signature.value is not non-empty canonical base64")

    _bounded_record(doc, "gate record")
    return doc


def _parse_input_options(values: Sequence[str]) -> dict[str, str]:
    result = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise EvidenceError("--input must be NAME=REPOSITORY/PATH")
        if name in result:
            raise EvidenceError(f"duplicate --input name {name!r}")
        result[name] = path
    return result


def _load_path(path: str) -> object:
    try:
        if path == "-":
            body = sys.stdin.buffer.read(MAX_RECORD_BYTES + 1)
        else:
            with Path(path).open("rb") as stream:
                body = stream.read(MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise EvidenceError(f"cannot read evidence {path!r}: {exc}") from exc
    return load_json_bytes(body)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m quarry_recon.release_evidence")
    commands = parser.add_subparsers(dest="command", required=True)

    identity = commands.add_parser(
        "identity",
        help="emit a quiescent clean-candidate identity as canonical JSON",
    )
    identity.add_argument("--repository", default=".", help="candidate Git worktree (default: .)")
    identity.add_argument("--git", required=True, help="absolute path to the runner-attested Git executable")
    identity.add_argument("--release", required=True, help="intended release ledger version")
    identity.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="bind an additional tracked candidate input (repeatable)",
    )

    validate = commands.add_parser("validate", help="strictly validate and canonically digest a record")
    validate.add_argument("kind", choices=("candidate", "gate"))
    validate.add_argument("path", help="JSON file, or - for stdin")
    validate.add_argument("--identity", help="candidate JSON required for an exact gate binding check")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    options = parser.parse_args(argv)
    try:
        if options.command == "identity":
            document = collect_candidate_identity(
                options.repository,
                options.release,
                git_executable=options.git,
                inputs=_parse_input_options(options.input),
            )
            sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
            return 0
        document = _load_path(options.path)
        if options.kind == "candidate":
            validate_candidate_identity(document)
        else:
            if not options.identity:
                raise EvidenceError("gate validation requires --identity for exact candidate binding")
            validate_gate_record(document, identity=_load_path(options.identity))
        sys.stdout.write(canonical_digest(document) + "\n")
        return 0
    except EvidenceError as exc:
        parser.exit(2, f"release-evidence: {exc}\n")


if __name__ == "__main__":  # pragma: no cover - exercised through the public main() seam
    raise SystemExit(main())
