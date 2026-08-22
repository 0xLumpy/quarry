"""Phase-A release evidence starts with a deterministic, fail-closed candidate identity."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from quarry_recon import release_evidence as evidence

pytestmark = pytest.mark.offline


def _digest(byte: str = "0") -> str:
    return "sha256:" + byte * 64


def _registry() -> bytes:
    document = {
        "identity_inputs": [
            {"name": name, "path": path}
            for name, path in sorted(evidence.DEFAULT_IDENTITY_INPUTS.items())
        ],
        "release": evidence.RELEASE_SCOPE,
        "schema_version": evidence.REGISTRY_SCHEMA,
        "schemas": [
            {
                "name": name,
                "path": evidence.SCHEMA_PATHS[name],
                "record_version": evidence.SCHEMA_VERSIONS[name],
            }
            for name in sorted(evidence.SCHEMA_VERSIONS)
        ],
    }
    return evidence.canonical_json_bytes(document)


def _schema(name: str) -> bytes:
    version = evidence.SCHEMA_VERSIONS[name]
    return evidence.canonical_json_bytes({
        "$id": f"urn:test:{name}",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {"schema_version": {"const": version}},
        "required": ["schema_version"],
        "type": "object",
    })


def _tracked_bodies(*, pyproject_version: str = "0.3.10", runtime_version: str = "0.3.10") -> dict[str, bytes]:
    bodies = {
        "pyproject.toml": f'[project]\nname = "quarry-recon"\nversion = "{pyproject_version}"\n'.encode(),
        "src/quarry_recon/__init__.py": f'__version__ = "{runtime_version}"\n'.encode(),
        "src/quarry_recon/release_evidence.py": b"release evidence validator\n",
        "docs/releases/RELEASE-GATES.md": b"release gate contract\n",
        "docs/releases/v0.3.10.md": b"release ledger\n",
        evidence.REGISTRY_PATH: _registry(),
    }
    for name, path in evidence.SCHEMA_PATHS.items():
        bodies[path] = _schema(name)
    return bodies


class _FakeGit:
    COMMIT = "1" * 40
    TREE = "2" * 40

    def __init__(
        self,
        root: Path,
        bodies: dict[str, bytes],
        *,
        dirty_calls: set[int] | None = None,
        change_head_after: int | None = None,
        modes: dict[str, str] | None = None,
    ):
        self.root = root
        self.bodies = dict(bodies)
        self.dirty_calls = dirty_calls or set()
        self.change_head_after = change_head_after
        self.status_calls = 0
        self.head_calls = 0
        self.modes = modes or {}
        self.by_oid = {}
        entries = []
        index_entries = []
        for path, body in sorted(self.bodies.items()):
            oid = hashlib.sha1(body).hexdigest()
            self.by_oid[oid] = body
            mode = self.modes.get(path, "100644")
            entries.append(f"{mode} blob {oid}\t{path}".encode() + b"\0")
            index_entries.append(f"{mode} {oid} 0\t{path}".encode() + b"\0")
        self.tree = b"".join(entries)
        self.index = b"".join(index_entries)

    def __call__(self, repository, *arguments, input_bytes=None, executable=None):
        assert input_bytes is None
        assert Path(executable).is_absolute()
        if arguments == ("rev-parse", "--absolute-git-dir"):
            git_directory = self.root / ".git"
            git_directory.mkdir(exist_ok=True)
            return (str(git_directory) + "\n").encode()
        if arguments == ("rev-parse", "--show-toplevel"):
            return (str(self.root) + "\n").encode()
        if arguments == ("rev-parse", "--verify", "HEAD^{commit}"):
            self.head_calls += 1
            if self.change_head_after is not None and self.head_calls > self.change_head_after:
                return ("3" * 40 + "\n").encode()
            return (self.COMMIT + "\n").encode()
        if arguments == ("rev-parse", "--verify", f"{self.COMMIT}^{{tree}}"):
            return (self.TREE + "\n").encode()
        if arguments == ("ls-files", "-v", "-z"):
            return b"".join(b"H " + path.encode() + b"\0" for path in sorted(self.bodies))
        if arguments == ("ls-files", "--stage", "-z"):
            return self.index
        if arguments == ("ls-files", "--others", "--exclude-standard", "-z"):
            self.status_calls += 1
            return b"?? changed\0" if self.status_calls in self.dirty_calls else b""
        if arguments == ("submodule", "status", "--recursive"):
            return b""
        if arguments == ("ls-tree", "-r", "-z", "--full-tree", self.COMMIT):
            return self.tree
        if arguments[:2] == ("cat-file", "blob"):
            return self.by_oid[arguments[2]]
        raise AssertionError(f"unexpected Git query {arguments!r}")


def _collect(monkeypatch, tmp_path, **fake_options):
    bodies = fake_options.pop("bodies", _tracked_bodies())
    for relative, body in bodies.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    fake = _FakeGit(tmp_path, bodies, **fake_options)
    monkeypatch.setattr(evidence, "_git", fake)
    return evidence.collect_candidate_identity(
        tmp_path,
        "0.3.10",
        git_executable="/usr/bin/git",
    ), fake


def _gate(identity: dict, *, status="pass") -> dict:
    reason = None if status == "pass" else "gate is not green"
    return {
        "artifacts": [{"digest": _digest("a"), "media_type": "application/json", "name": "results"}],
        "assertions": [{"id": "contract", "reason": None, "status": "pass"}],
        "candidate": evidence.candidate_summary(identity),
        "environment": {
            "architecture": "x86_64",
            "isolation_profile": _digest("b"),
            "os": "linux",
            "python": "3.13.12",
            "runner_image": _digest("c"),
        },
        "finished_at": "2026-08-14T10:00:01Z",
        "gate_id": "A-IDENTITY",
        "inputs": [{"digest": _digest("d"), "name": "candidate"}],
        "lane": "H0-hermetic",
        "not_applicable_rule": None,
        "reason": reason,
        "release": identity["release"],
        "required": True,
        "schema_version": evidence.GATE_SCHEMA,
        "selection": {
            "collected": 1,
            "deselected": 0,
            "failed": 0,
            "passed": 1,
            "selected": 1,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        },
        "signature": None,
        "started_at": "2026-08-14T10:00:00Z",
        "status": status,
        "toolchain": [{
            "digest": _digest("e"),
            "name": "pytest",
            "path": "/runner/bin/pytest",
            "version": "8.4.1",
        }],
    }


class TestCanonicalJson:
    def test_v1_canonical_json_golden_vector(self):
        document = {"z": "Ω", "a": 1}
        assert evidence.canonical_json_bytes(document) == b'{"a":1,"z":"\xce\xa9"}'
        assert evidence.canonical_digest(document) == \
            "sha256:ac1b988e3a83ccc305cbe68d0614687d0e904f9ee8f68b47763da27675d063f3"

    def test_mapping_order_never_changes_bytes_or_digest(self):
        left = {"z": [3, 2, 1], "a": {"y": 2, "x": 1}}
        right = {"a": {"x": 1, "y": 2}, "z": [3, 2, 1]}
        assert evidence.canonical_json_bytes(left) == evidence.canonical_json_bytes(right)
        assert evidence.canonical_digest(left) == evidence.canonical_digest(right)
        assert evidence.canonical_digest(left) != "sha256:" + hashlib.sha256(
            evidence.canonical_json_bytes(left)
        ).hexdigest()

    @pytest.mark.parametrize(
        "document",
        [
            {1: "coerced-key"},
            ("tuple", "coerced-to-list"),
            1.5,
            -0.0,
            {"nested": {"not", "json"}},
        ],
    )
    def test_python_specific_values_cannot_collapse_to_a_json_identity(self, document):
        with pytest.raises(evidence.EvidenceError, match="JSON"):
            evidence.canonical_json_bytes(document)

    @pytest.mark.parametrize("body", [b"1.5", b"-0.0"])
    def test_reader_rejects_floating_point_numbers(self, body):
        with pytest.raises(evidence.EvidenceError, match="unsupported value type float"):
            evidence.load_json_bytes(body)

    @pytest.mark.parametrize(
        "body",
        [b'{"x":1,"x":2}', b'{"x":NaN}', b'"\xff"', b'"\\ud800"', b"1e999"],
    )
    def test_strict_reader_rejects_ambiguous_json(self, body):
        with pytest.raises(evidence.EvidenceError):
            evidence.load_json_bytes(body)

    def test_reader_bounds_the_record_before_parsing(self):
        with pytest.raises(evidence.EvidenceError, match="exceeds"):
            evidence.load_json_bytes(b" " * (evidence.MAX_RECORD_BYTES + 1))

    def test_path_reader_bounds_the_file_before_parsing(self, tmp_path):
        path = tmp_path / "oversize.json"
        path.write_bytes(b" " * (evidence.MAX_RECORD_BYTES + 2))
        with pytest.raises(evidence.EvidenceError, match="exceeds"):
            evidence._load_path(str(path))

    def test_reader_types_excessive_nesting_as_evidence_error(self):
        with pytest.raises(evidence.EvidenceError):
            evidence.load_json_bytes(b"[" * 2000 + b"0" + b"]" * 2000)

    def test_integer_range_is_explicit_and_cross_python(self):
        assert evidence.load_json_bytes(str(evidence.MAX_JSON_INTEGER).encode()) == evidence.MAX_JSON_INTEGER
        for value in (evidence.MAX_JSON_INTEGER + 1, -evidence.MAX_JSON_INTEGER - 1):
            with pytest.raises(evidence.EvidenceError, match=r"2\^63-1"):
                evidence.load_json_bytes(str(value).encode())
            with pytest.raises(evidence.EvidenceError, match=r"2\^63-1"):
                evidence.canonical_json_bytes(value)
        with pytest.raises(evidence.EvidenceError, match=r"2\^63-1"):
            evidence.load_json_bytes(b"9" * 5000)

    def test_committed_registry_and_schemas_are_strict_and_in_agreement(self):
        root = Path(__file__).resolve().parents[1]
        registry = evidence._validate_schema_registry(
            evidence.load_json_bytes((root / evidence.REGISTRY_PATH).read_bytes())
        )
        for record in registry["schemas"]:
            schema = evidence._validate_registered_schema(
                evidence.load_json_bytes((root / record["path"]).read_bytes()),
                name=record["name"],
                record_version=record["record_version"],
            )
            assert set(schema["required"]) == set(schema["properties"])

    def test_malformed_registered_schema_is_a_typed_refusal(self):
        malformed = json.loads(_schema("candidate_identity"))
        malformed["required"] = [{}]
        with pytest.raises(evidence.EvidenceError, match="require every"):
            evidence._validate_registered_schema(
                malformed,
                name="candidate_identity",
                record_version=evidence.CANDIDATE_SCHEMA,
            )


class TestCandidateCollection:
    def test_git_child_environment_does_not_inherit_credentials_or_loader_state(self, monkeypatch):
        monkeypatch.setenv("HOME", "/private/home")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/inject.so")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
        child = evidence._git_environment()
        assert set(child) == {
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_OPTIONAL_LOCKS",
            "LANG",
            "LC_ALL",
            "PATH",
            "TZ",
        }

    def test_git_lookup_can_never_fall_back_to_ambient_path(self, tmp_path):
        with pytest.raises(evidence.EvidenceError, match="absolute executable"):
            evidence._git(tmp_path, "status", executable="git")

    @pytest.mark.parametrize("path", ["/runner//bin/git", "/runner/bin/git/", r"C:\runner\\git.exe"])
    def test_absolute_tool_paths_must_have_one_normalized_spelling(self, path):
        with pytest.raises(evidence.EvidenceError, match="normalized"):
            evidence._absolute_tool_path(path, "tool")

    @pytest.mark.parametrize("path", ["/runner/bin/git", r"C:\runner\git.exe", "C:/runner/git.exe"])
    def test_absolute_tool_paths_allow_canonical_posix_and_windows_spellings(self, path):
        assert evidence._absolute_tool_path(path, "tool") == path

    def test_collector_refuses_a_release_outside_the_bound_v1_scope(self, tmp_path):
        with pytest.raises(evidence.EvidenceError, match="v1 scope"):
            evidence.collect_candidate_identity(
                tmp_path,
                "0.4.0",
                git_executable="/usr/bin/git",
            )

    @pytest.mark.skipif(os.name != "posix", reason="POSIX native-path boundary")
    @pytest.mark.parametrize("executable", [r"C:\fake-git.exe", "C:/fake-git.exe"])
    def test_windows_spelling_cannot_bypass_posix_native_git_path(self, tmp_path, executable):
        with pytest.raises(evidence.EvidenceError, match="native absolute executable"):
            evidence._git(tmp_path, "status", executable=executable)

    def test_v1_source_tree_golden_vectors(self, tmp_path):
        blob = evidence._TreeEntry(b"100644", b"blob", b"1" * 40, b"a.txt")
        gitlink = evidence._TreeEntry(b"160000", b"commit", b"2" * 40, b"vendor/tool")
        assert evidence._source_tree_digest(tmp_path, [blob], blob_reader=lambda oid: b"hello\n") == \
            "sha256:a72c1aac963ac0e3cc27cdc05e90c816952329817aa9096327ea3e0d409d33be"
        assert evidence._source_tree_digest(tmp_path, [gitlink]) == \
            "sha256:640bbe9d9bab9575a1857371cd85bfe451ca30a727561322b1e7fd15708bb18b"

    @pytest.mark.parametrize(
        "entry",
        [
            b"160000 blob " + b"1" * 40 + b"\tgitlink\0",
            b"100644 commit " + b"1" * 40 + b"\tfile\0",
            b"100664 blob " + b"1" * 40 + b"\tfile\0",
            b"garbage blob " + b"1" * 40 + b"\tfile\0",
            b"100644 blob " + b"1" * 40 + b"\t../escape\0",
            b"100644 blob " + b"1" * 40 + b"\t/absolute\0",
            b"100644 blob " + b"1" * 40 + b"\ta//b\0",
        ],
    )
    def test_tree_parser_refuses_invalid_mode_kind_and_path_shapes(self, monkeypatch, tmp_path, entry):
        monkeypatch.setattr(evidence, "_git", lambda *args, **kwargs: entry)
        with pytest.raises(evidence.EvidenceError, match="unsupported Git tree entry"):
            evidence._tree_entries(tmp_path, "1" * 40, git_executable="/usr/bin/git")

    def test_tree_parser_preserves_a_valid_non_utf8_raw_path(self, monkeypatch, tmp_path):
        entry = b"100644 blob " + b"1" * 40 + b"\t\xff\0"
        monkeypatch.setattr(evidence, "_git", lambda *args, **kwargs: entry)
        assert evidence._tree_entries(tmp_path, "1" * 40, git_executable="/usr/bin/git")[0].path == b"\xff"

    def test_clean_candidate_is_deterministic_and_contains_no_checkout_path(self, monkeypatch, tmp_path):
        first, fake = _collect(monkeypatch, tmp_path)
        second = evidence.collect_candidate_identity(tmp_path, "0.3.10", git_executable="/usr/bin/git")
        assert first == second
        assert evidence.canonical_json_bytes(first) == evidence.canonical_json_bytes(second)
        assert first["git_commit"] == fake.COMMIT
        assert first["git_tree"] == fake.TREE
        assert first["dirty"] is False
        assert first["package_version"] == "0.3.10"
        assert first["schema_versions"] == evidence.SCHEMA_VERSIONS
        assert first["submodules"] == []
        assert str(tmp_path).encode() not in evidence.canonical_json_bytes(first)

    @pytest.mark.parametrize("dirty_calls", [{1}, {2}])
    def test_initial_or_late_dirty_state_refuses_identity(self, monkeypatch, tmp_path, dirty_calls):
        with pytest.raises(evidence.EvidenceError, match="dirty"):
            _collect(monkeypatch, tmp_path, dirty_calls=dirty_calls)

    def test_head_change_during_collection_refuses_identity(self, monkeypatch, tmp_path):
        with pytest.raises(evidence.EvidenceError, match="HEAD changed"):
            _collect(monkeypatch, tmp_path, change_head_after=1)

    def test_package_sources_must_agree(self, monkeypatch, tmp_path):
        bodies = _tracked_bodies(runtime_version="0.3.8")
        with pytest.raises(evidence.EvidenceError, match="version disagreement"):
            _collect(monkeypatch, tmp_path, bodies=bodies)

    def test_inert_toml_text_cannot_forge_the_project_version(self, monkeypatch, tmp_path):
        bodies = _tracked_bodies()
        bodies["pyproject.toml"] = (
            b'payload = """\n[project]\nversion = "0.3.9"\n"""\n'
            b'[project]\ndynamic = ["version"]\n'
        )
        with pytest.raises(evidence.EvidenceError, match=r"semantic \[project\]\.version"):
            _collect(monkeypatch, tmp_path, bodies=bodies)

    def test_pathological_toml_nesting_is_a_typed_refusal(self):
        body = b"[project]\nversion=" + b"[" * 5000 + b'"0.3.9"' + b"]" * 5000
        with pytest.raises(evidence.EvidenceError, match="not valid TOML"):
            evidence._project_version(body)

    def test_inert_python_text_and_computed_assignment_cannot_forge_runtime_version(
        self, monkeypatch, tmp_path
    ):
        bodies = _tracked_bodies()
        bodies["src/quarry_recon/__init__.py"] = (
            b'"""__version__ = "0.3.9"""\n'
            b'__version__ = ".".join(("0", "3", "8"))\n'
        )
        with pytest.raises(evidence.EvidenceError, match="literal string assignment"):
            _collect(monkeypatch, tmp_path, bodies=bodies)

    def test_conditional_runtime_reassignment_is_not_an_exact_version_source(self):
        initializer = b'__version__ = "0.3.9"\nif enabled:\n    __version__ = "9.9.9"\n'
        with pytest.raises(evidence.EvidenceError, match="only a module docstring"):
            evidence._runtime_version(initializer)

    @pytest.mark.parametrize(
        "suffix",
        [
            "del __version__\n",
            'globals()["__version__"] = "9.9.9"\n',
            'raise RuntimeError("unimportable")\n',
        ],
    )
    def test_runtime_version_source_cannot_mutate_or_fail_after_the_literal(self, suffix):
        initializer = ('__version__ = "0.3.9"\n' + suffix).encode()
        with pytest.raises(evidence.EvidenceError, match="only a module docstring"):
            evidence._runtime_version(initializer)

    @pytest.mark.parametrize("seam", ["fstat", "read"])
    def test_raw_worktree_read_faults_are_typed_and_close_the_descriptor(
        self, monkeypatch, tmp_path, seam
    ):
        body = b"candidate bytes\n"
        (tmp_path / "tracked").write_bytes(body)
        entry = evidence._TreeEntry(b"100644", b"blob", b"1" * 40, b"tracked")
        real_close = os.close
        closed = []

        def close(descriptor):
            closed.append(descriptor)
            real_close(descriptor)

        def fault(*args, **kwargs):
            raise OSError("injected exact-read fault")

        monkeypatch.setattr(os, "close", close)
        monkeypatch.setattr(os, seam, fault)
        with pytest.raises(evidence.EvidenceError, match="cannot read"):
            evidence._refuse_raw_worktree_mismatch(
                tmp_path,
                [entry],
                blob_reader=lambda object_id: body,
                label="candidate",
            )
        assert len(closed) == 1

    def test_raw_worktree_exact_cancellation_preserves_identity_and_closes_descriptor(
        self, monkeypatch, tmp_path
    ):
        body = b"candidate bytes\n"
        (tmp_path / "tracked").write_bytes(body)
        entry = evidence._TreeEntry(b"100644", b"blob", b"1" * 40, b"tracked")
        signal = KeyboardInterrupt("exact")
        real_close = os.close
        closed = []

        def close(descriptor):
            closed.append(descriptor)
            real_close(descriptor)

        def cancel(*args, **kwargs):
            raise signal

        monkeypatch.setattr(os, "close", close)
        monkeypatch.setattr(os, "read", cancel)
        with pytest.raises(KeyboardInterrupt) as caught:
            evidence._refuse_raw_worktree_mismatch(
                tmp_path,
                [entry],
                blob_reader=lambda object_id: body,
                label="candidate",
            )
        assert caught.value is signal
        assert len(closed) == 1

    def test_every_declared_input_must_be_a_tracked_blob(self, monkeypatch, tmp_path):
        bodies = _tracked_bodies()
        bodies.pop("docs/releases/RELEASE-GATES.md")
        with pytest.raises(evidence.EvidenceError, match="not a regular tracked blob"):
            _collect(monkeypatch, tmp_path, bodies=bodies)

    def test_conflicting_required_input_is_refused(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        assert identity
        with pytest.raises(evidence.EvidenceError, match="conflicts"):
            evidence.collect_candidate_identity(
                tmp_path,
                "0.3.10",
                git_executable="/usr/bin/git",
                inputs={"package-metadata": "somewhere-else.toml"},
            )

    def test_content_mode_path_and_symlink_target_change_tree_digest(self, tmp_path):
        entry = evidence._TreeEntry(b"100644", b"blob", b"1" * 40, b"a")
        baseline = evidence._source_tree_digest(tmp_path, [entry], blob_reader=lambda oid: b"body")
        variants = [
            ([evidence._TreeEntry(b"100644", b"blob", b"2" * 40, b"a")], b"changed"),
            ([evidence._TreeEntry(b"100755", b"blob", b"1" * 40, b"a")], b"body"),
            ([evidence._TreeEntry(b"100644", b"blob", b"1" * 40, b"b")], b"body"),
            ([evidence._TreeEntry(b"120000", b"blob", b"3" * 40, b"a")], b"other-target"),
        ]
        for entries, body in variants:
            assert evidence._source_tree_digest(tmp_path, entries, blob_reader=lambda oid, body=body: body) != baseline

    def test_gitlink_identity_changes_tree_digest(self, tmp_path):
        left = [evidence._TreeEntry(b"160000", b"commit", b"1" * 40, b"vendor/tool")]
        right = [evidence._TreeEntry(b"160000", b"commit", b"2" * 40, b"vendor/tool")]
        assert evidence._source_tree_digest(tmp_path, left) != evidence._source_tree_digest(tmp_path, right)

    @pytest.mark.parametrize("prefix", [b"-", b"+", b"U"])
    def test_uninitialized_changed_or_conflicted_submodule_is_refused(self, prefix):
        with pytest.raises(evidence.EvidenceError, match="submodule is"):
            evidence._submodule_identities(prefix + b"1" * 40 + b" vendor/tool\n")

    def test_recursive_submodule_identities_are_sorted(self):
        raw = b" " + b"2" * 40 + b" vendor/z\n " + b"1" * 40 + b" vendor/a (heads/main)\n"
        assert evidence._submodule_identities(raw) == [
            {"git_commit": "1" * 40, "path": "vendor/a"},
            {"git_commit": "2" * 40, "path": "vendor/z"},
        ]

    @pytest.mark.parametrize("tag", [b"h", b"S", b"s", b"M"])
    def test_hidden_or_noncanonical_index_state_is_refused(self, tag):
        with pytest.raises(evidence.EvidenceError, match="visibility"):
            evidence._refuse_hidden_index_entries(tag + b" pyproject.toml\0")


class TestCandidateValidation:
    def test_collected_candidate_validates(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        assert evidence.validate_candidate_identity(identity) is identity

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("dirty", True, "dirty"),
            ("git_commit", "abc", "object id"),
            ("source_tree_digest", "sha256:no", "digest"),
            ("release", "0.4.0", "v1 scope"),
            ("schema_version", "future", "unsupported"),
            ("source_tree_digest_algorithm", "tar", "algorithm"),
        ],
    )
    def test_identity_rejects_wrong_scalar_contracts(self, monkeypatch, tmp_path, field, value, message):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity[field] = value
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.validate_candidate_identity(identity)

    def test_unknown_member_is_rejected(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["checkout_path"] = "/private/home"
        with pytest.raises(evidence.EvidenceError, match="unknown"):
            evidence.validate_candidate_identity(identity)

    def test_input_paths_cannot_escape_the_repository(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["inputs"][0]["path"] = "/home/operator/private"
        with pytest.raises(evidence.EvidenceError, match="relative"):
            evidence.validate_candidate_identity(identity)

    @pytest.mark.parametrize(
        "path",
        [r"C:\Users\operator\private.json", r"\\server\share\private.json", "C:private.json"],
    )
    def test_input_paths_refuse_windows_absolute_unc_and_drive_relative_spellings(
        self, monkeypatch, tmp_path, path
    ):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["inputs"][0]["path"] = path
        with pytest.raises(evidence.EvidenceError, match="relative"):
            evidence.validate_candidate_identity(identity)

    def test_input_paths_cannot_contain_control_characters(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["inputs"][0]["path"] = "docs/hidden\nname"
        with pytest.raises(evidence.EvidenceError, match="relative"):
            evidence.validate_candidate_identity(identity)

    def test_inputs_are_sorted_and_unique(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["inputs"] = list(reversed(identity["inputs"]))
        with pytest.raises(evidence.EvidenceError, match="sorted"):
            evidence.validate_candidate_identity(identity)

    def test_required_registry_inputs_cannot_be_omitted(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["inputs"] = []
        with pytest.raises(evidence.EvidenceError, match="required input"):
            evidence.validate_candidate_identity(identity)

    @pytest.mark.parametrize("name", ["package-metadata", "package-version"])
    def test_package_input_digest_must_match_its_version_source(self, monkeypatch, tmp_path, name):
        identity, _ = _collect(monkeypatch, tmp_path)
        record = next(item for item in identity["inputs"] if item["name"] == name)
        record["digest"] = _digest("f")
        with pytest.raises(evidence.EvidenceError, match="package-version source disagree"):
            evidence.validate_candidate_identity(identity)

    def test_two_input_names_cannot_disagree_about_one_path(self, monkeypatch, tmp_path):
        identity, _ = _collect(monkeypatch, tmp_path)
        identity["inputs"].append({
            "digest": _digest("f"),
            "name": "z-conflicting-alias",
            "path": "pyproject.toml",
        })
        with pytest.raises(evidence.EvidenceError, match="inputs disagree"):
            evidence.validate_candidate_identity(identity)


class TestGateValidation:
    @pytest.fixture
    def identity(self, monkeypatch, tmp_path):
        return _collect(monkeypatch, tmp_path)[0]

    def test_gate_binds_the_exact_candidate(self, identity):
        gate = _gate(identity)
        assert evidence.validate_gate_record(gate, identity=identity) is gate

    def test_wrong_candidate_is_refused(self, identity):
        gate = _gate(identity)
        gate["candidate"]["git_commit"] = "9" * 40
        with pytest.raises(evidence.EvidenceError, match="exact candidate"):
            evidence.validate_gate_record(gate, identity=identity)

    @pytest.mark.parametrize(
        ("mutate", "message"),
        [
            (lambda gate: gate.update(extra=True), "unknown"),
            (lambda gate: gate.update(required=1), "boolean"),
            (lambda gate: gate.update(status="green"), "status"),
            (lambda gate: gate.update(lane="ambient"), "lane"),
            (lambda gate: gate.update(started_at="2026-08-14 10:00:00"), "RFC3339"),
            (lambda gate: gate["selection"].update(selected=True), "integer"),
            (lambda gate: gate["selection"].update(skipped=1), "selected terminal"),
            (lambda gate: gate["assertions"][0].update(status="open"), "non-pass assertion"),
            (lambda gate: gate["toolchain"][0].update(path="bin/pytest"), "absolute executable"),
        ],
    )
    def test_malformed_or_nonpassing_pass_record_is_refused(self, identity, mutate, message):
        gate = _gate(identity)
        mutate(gate)
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.validate_gate_record(gate, identity=identity)

    @pytest.mark.parametrize(
        "timestamp",
        [
            "2026-08-14T10:00:00+00:60",
            "2026-08-14T10:00:00+01:60",
            "2026-08-14T10:00:00+24:00",
            "2026-08-14T10:00:00-00:00",
        ],
    )
    def test_timestamps_require_a_known_valid_rfc3339_offset(self, identity, timestamp):
        gate = _gate(identity)
        gate["started_at"] = timestamp
        with pytest.raises(evidence.EvidenceError, match="RFC3339"):
            evidence.validate_gate_record(gate, identity=identity)

    def test_blocking_status_requires_a_reason(self, identity):
        gate = _gate(identity, status="open")
        gate["reason"] = None
        with pytest.raises(evidence.EvidenceError, match="needs a reason"):
            evidence.validate_gate_record(gate, identity=identity)

    def test_blocking_status_reason_cannot_be_whitespace_only(self, identity):
        gate = _gate(identity, status="open")
        gate["reason"] = "   "
        with pytest.raises(evidence.EvidenceError, match="non-empty"):
            evidence.validate_gate_record(gate, identity=identity)

    def test_not_applicable_requires_a_preapproved_rule(self, identity):
        gate = _gate(identity, status="not_applicable")
        with pytest.raises(evidence.EvidenceError, match="pre-approved"):
            evidence.validate_gate_record(gate, identity=identity)
        gate["not_applicable_rule"] = {
            "approved_at": "2026-08-01T00:00:00Z",
            "digest": _digest("f"),
            "expires_at": "2026-09-01T00:00:00Z",
            "id": "no-live-range",
        }
        assert evidence.validate_gate_record(gate, identity=identity) is gate

    def test_scope_rule_expiry_must_follow_approval(self, identity):
        gate = _gate(identity, status="not_applicable")
        gate["not_applicable_rule"] = {
            "approved_at": "2026-08-14T00:00:00Z",
            "digest": _digest("f"),
            "expires_at": "2026-08-13T00:00:00Z",
            "id": "expired",
        }
        with pytest.raises(evidence.EvidenceError, match="expires"):
            evidence.validate_gate_record(gate, identity=identity)

    def test_scope_rule_must_precede_execution_and_cover_completion(self, identity):
        gate = _gate(identity, status="not_applicable")
        gate["not_applicable_rule"] = {
            "approved_at": "2026-08-14T10:00:00.5Z",
            "digest": _digest("f"),
            "expires_at": None,
            "id": "late",
        }
        with pytest.raises(evidence.EvidenceError, match="before execution"):
            evidence.validate_gate_record(gate, identity=identity)
        gate["not_applicable_rule"].update({
            "approved_at": "2026-08-14T09:00:00Z",
            "expires_at": "2026-08-14T10:00:00.5Z",
        })
        with pytest.raises(evidence.EvidenceError, match="completion"):
            evidence.validate_gate_record(gate, identity=identity)

    def test_empty_required_pass_is_not_evidence(self, identity):
        gate = _gate(identity)
        gate["selection"] = {key: 0 for key in gate["selection"]}
        gate["assertions"] = []
        gate["artifacts"] = []
        gate["inputs"] = []
        gate["toolchain"] = []
        with pytest.raises(evidence.EvidenceError, match="no executed assertion"):
            evidence.validate_gate_record(gate, identity=identity)

    @pytest.mark.parametrize("value", ["not-labelled", "base64:", "base64:***", "base64:YQ"])
    def test_signature_bytes_have_one_canonical_encoding(self, identity, value):
        gate = _gate(identity)
        gate["signature"] = {"algorithm": "ed25519", "key_id": "release", "value": value}
        with pytest.raises(evidence.EvidenceError, match="base64"):
            evidence.validate_gate_record(gate, identity=identity)

    def test_valid_signature_envelope_is_structural_not_a_verification_claim(self, identity):
        gate = _gate(identity)
        gate["signature"] = {"algorithm": "ed25519", "key_id": "release", "value": "base64:YQ=="}
        assert evidence.validate_gate_record(gate, identity=identity) is gate

    def test_gate_mapping_order_does_not_change_its_digest(self, identity):
        gate = _gate(identity)
        reordered = dict(reversed(list(gate.items())))
        assert evidence.canonical_digest(gate) == evidence.canonical_digest(reordered)
