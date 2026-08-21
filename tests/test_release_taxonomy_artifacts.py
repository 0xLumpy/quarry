"""Strict standalone contracts for taxonomy and verification-job artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import signal
from itertools import product
from pathlib import Path

import conftest as taxonomy_collector
import pytest
import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

from quarry_recon import release_evidence as evidence

pytestmark = pytest.mark.offline

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ".github/workflows/ci.yml"


def _taxonomy_bytes() -> bytes:
    rows = [
        ("tests/a.py::test_a", "offline", (), True),
        ("tests/a.py::test_z", "offline", (), False),
        ("tests/b.py::test_git", "integration", ("git", "sh"), False),
        ("tests/p.py::test_wheel", "packaging", ("wheel",), False),
    ]
    return taxonomy_collector._taxonomy_manifest_bytes(
        rows,
        ["tests/a.py::test_a", "tests/a.py::test_z"],
        mark_expression="offline",
        keyword_expression="",
    )


def _taxonomy_document() -> dict:
    return evidence.read_pytest_taxonomy(_taxonomy_bytes())


def _workflow_body() -> bytes:
    return (ROOT / WORKFLOW_PATH).read_bytes()


def _job_map_body() -> bytes:
    return (ROOT / evidence.VERIFICATION_JOB_MAP_PATH).read_bytes()


def _job_map_document() -> dict:
    return evidence.read_verification_job_map(
        _job_map_body(),
        workflow_bodies={WORKFLOW_PATH: _workflow_body()},
    )


def _write_test_workflow(root: Path, body: bytes = b"name: test\n") -> Path:
    target = root / WORKFLOW_PATH
    target.parent.mkdir(parents=True)
    target.write_bytes(body)
    return target


def _direct_workflow_paths(root: Path) -> list[str]:
    directory = root / ".github" / "workflows"
    return sorted({
        path.relative_to(root).as_posix()
        for pattern in ("*.yml", "*.yaml")
        for path in directory.glob(pattern)
    })


def _assert_exact_workflow_inventory(document: dict, root: Path) -> list[str]:
    mapped = [record["path"] for record in document["workflows"]]
    observed = _direct_workflow_paths(root)
    assert mapped == observed
    return observed


def _configured_matrix_rows(job: dict) -> set[tuple[tuple[str, str], ...]]:
    matrix = (job.get("strategy") or {}).get("matrix")
    if matrix is None:
        return {()}
    assert type(matrix) is dict
    assert "include" not in matrix and "exclude" not in matrix
    names = sorted(matrix)
    axes = []
    for name in names:
        values = matrix[name]
        assert type(name) is str
        assert type(values) is list and values
        assert all(type(value) is str for value in values)
        axes.append(values)
    return {
        tuple(zip(names, values))
        for values in product(*axes)
    }


class _UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys instead of taking the last."""


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueSafeLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


class TestStandaloneSchemaInventory:
    def test_future_runner_inputs_do_not_mutate_v1_candidate_identity(self):
        assert evidence.SCHEMA_VERSIONS == {
            "candidate_identity": evidence.CANDIDATE_SCHEMA,
            "gate_record": evidence.GATE_SCHEMA,
            "schema_registry": evidence.REGISTRY_SCHEMA,
        }
        assert set(evidence.FUTURE_RUNNER_INPUTS).isdisjoint(evidence.DEFAULT_IDENTITY_INPUTS)
        assert evidence.PYTEST_TAXONOMY_SCHEMA_PATH not in evidence.SCHEMA_PATHS.values()
        assert evidence.VERIFICATION_JOB_MAP_SCHEMA_PATH not in evidence.SCHEMA_PATHS.values()
        assert evidence.VERIFICATION_JOB_MAP_PATH not in evidence.DEFAULT_IDENTITY_INPUTS.values()
        assert taxonomy_collector._TAXONOMY_SCHEMA == evidence.PYTEST_TAXONOMY_SCHEMA
        assert taxonomy_collector._PRIMARY_LANES == evidence.PYTEST_PRIMARY_LANES

    @pytest.mark.parametrize(
        ("path", "name", "version"),
        [
            (
                evidence.PYTEST_TAXONOMY_SCHEMA_PATH,
                "pytest-taxonomy",
                evidence.PYTEST_TAXONOMY_SCHEMA,
            ),
            (
                evidence.VERIFICATION_JOB_MAP_SCHEMA_PATH,
                "verification-job-map",
                evidence.VERIFICATION_JOB_MAP_SCHEMA,
            ),
        ],
    )
    def test_standalone_schemas_are_exact_draft_2020_12_objects(self, path, name, version):
        schema = evidence.load_json_bytes((ROOT / path).read_bytes())
        validated = evidence._validate_registered_schema(
            schema,
            name=name,
            record_version=version,
        )
        assert set(validated["required"]) == set(validated["properties"])


class TestPytestTaxonomyReader:
    def test_existing_emitter_round_trips_without_byte_changes(self):
        body = _taxonomy_bytes()
        document = evidence.read_pytest_taxonomy(body)
        assert body == evidence.canonical_json_bytes(document)
        assert document["schema_version"] == "quarry.pytest-taxonomy.v1"
        assert [record["lane"] for record in document["lanes"]] == [
            lane for _marker, lane in evidence.PYTEST_PRIMARY_LANES
        ]

    @pytest.mark.parametrize(
        "body_mutation",
        [
            lambda body: body + b"\n",
            lambda body: b" " + body,
            lambda body: json.dumps(json.loads(body), indent=2, sort_keys=True).encode(),
        ],
    )
    def test_bytes_reader_accepts_only_the_exact_canonical_representation(self, body_mutation):
        with pytest.raises(evidence.EvidenceError, match="canonical"):
            evidence.read_pytest_taxonomy(body_mutation(_taxonomy_bytes()))

    def test_exact_object_keys_and_integer_types_are_enforced(self):
        document = _taxonomy_document()
        document["collector"]["ambient_path"] = "/private"
        with pytest.raises(evidence.EvidenceError, match="unknown"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        document["selection"]["selected"] = True
        with pytest.raises(evidence.EvidenceError, match="exact non-negative integer"):
            evidence.validate_pytest_taxonomy(document)

    def test_lane_order_node_order_uniqueness_and_disjointness_are_enforced(self):
        document = _taxonomy_document()
        document["lanes"][0], document["lanes"][1] = document["lanes"][1], document["lanes"][0]
        with pytest.raises(evidence.EvidenceError, match="canonical marker/lane order"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        document["lanes"][0]["nodes"].reverse()
        with pytest.raises(evidence.EvidenceError, match="sorted by UTF-8"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        document["lanes"][1]["nodes"] = [document["lanes"][0]["nodes"][0]]
        with pytest.raises(evidence.EvidenceError, match="disjoint"):
            evidence.validate_pytest_taxonomy(document)

    def test_lone_surrogate_node_ids_are_typed_as_evidence_errors(self):
        document = _taxonomy_document()
        document["lanes"][0]["nodes"][0] = "tests/a.py::test_\ud800"
        with pytest.raises(evidence.EvidenceError, match="valid Unicode"):
            evidence.validate_pytest_taxonomy(document)

    def test_collected_selected_and_per_lane_counts_reconcile(self):
        document = _taxonomy_document()
        document["selection"]["collected"] += 1
        with pytest.raises(evidence.EvidenceError, match="lane-node union"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        document["selection"]["deselected"] += 1
        with pytest.raises(evidence.EvidenceError, match=r"collected=selected\+deselected"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        document["selection"]["selected_by_lane"][0]["selected"] -= 1
        with pytest.raises(evidence.EvidenceError, match="selected_by_lane"):
            evidence.validate_pytest_taxonomy(document)

    def test_capabilities_are_sorted_named_and_limited_to_h1_or_p0(self):
        document = _taxonomy_document()
        document["capabilities"].reverse()
        with pytest.raises(evidence.EvidenceError, match="sorted by name"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        document["capabilities"][0]["nodes"] = [document["lanes"][0]["nodes"][0]]
        with pytest.raises(evidence.EvidenceError, match="H1/P0"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        h1_node = document["lanes"][1]["nodes"][0]
        for capability in document["capabilities"]:
            capability["nodes"] = [node for node in capability["nodes"] if node != h1_node]
        document["capabilities"] = [record for record in document["capabilities"] if record["nodes"]]
        with pytest.raises(evidence.EvidenceError, match="every H1"):
            evidence.validate_pytest_taxonomy(document)

    def test_synthetic_process_nodes_are_sorted_unique_h0_members(self):
        document = _taxonomy_document()
        document["synthetic_process_nodes"] = [document["lanes"][1]["nodes"][0]]
        with pytest.raises(evidence.EvidenceError, match="only for H0"):
            evidence.validate_pytest_taxonomy(document)

        document = _taxonomy_document()
        node = document["synthetic_process_nodes"][0]
        document["synthetic_process_nodes"] = [node, node]
        with pytest.raises(evidence.EvidenceError, match="duplicate"):
            evidence.validate_pytest_taxonomy(document)


class TestVerificationJobMapReader:
    def test_committed_map_is_one_canonical_json_line_and_binds_raw_workflow(self):
        body = _job_map_body()
        document = _job_map_document()
        assert body == evidence.canonical_json_bytes(document) + b"\n"
        assert document["workflows"] == [{
            "digest": "sha256:" + hashlib.sha256(_workflow_body()).hexdigest(),
            "path": WORKFLOW_PATH,
        }]

    def test_any_raw_workflow_byte_drift_is_rejected(self):
        with pytest.raises(evidence.EvidenceError, match="raw bytes drifted"):
            evidence.read_verification_job_map(
                _job_map_body(),
                workflow_bodies={WORKFLOW_PATH: _workflow_body() + b"# drift\n"},
            )

    def test_exact_keys_and_lowercase_sha256_digest_types_are_enforced(self):
        document = _job_map_document()
        document["jobs"][0]["ambient"] = True
        with pytest.raises(evidence.EvidenceError, match="unknown"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

        document = _job_map_document()
        document["workflows"][0]["digest"] = "SHA256:" + "A" * 64
        with pytest.raises(evidence.EvidenceError, match="lowercase sha256"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

    @pytest.mark.parametrize(
        "body",
        [
            lambda: _job_map_body()[:-1],
            lambda: _job_map_body() + b"\n",
            lambda: json.dumps(_job_map_document(), indent=2, sort_keys=True).encode() + b"\n",
        ],
    )
    def test_tracked_map_requires_exact_canonical_json_line_bytes(self, body):
        with pytest.raises(evidence.EvidenceError, match="canonical|exactly one LF"):
            evidence.read_verification_job_map(
                body(),
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

    def test_declared_and_supplied_workflow_paths_must_match_exactly(self):
        document = _job_map_document()
        with pytest.raises(evidence.EvidenceError, match="exactly match"):
            evidence.validate_verification_job_map(document, workflow_bodies={})
        with pytest.raises(evidence.EvidenceError, match="exactly match"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body(), "extra.yml": b""},
            )

    def test_paths_refs_and_instance_ids_are_closed_over_declared_workflows(self):
        document = _job_map_document()
        document["workflows"][0]["path"] = "../ci.yml"
        with pytest.raises(evidence.EvidenceError, match="relative"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={"../ci.yml": _workflow_body()},
            )

        document = _job_map_document()
        document["workflows"][0]["path"] = ".github/workflows/nested/ci.yml"
        with pytest.raises(evidence.EvidenceError, match="directly name"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={".github/workflows/nested/ci.yml": _workflow_body()},
            )

        document = _job_map_document()
        document["workflows"][0]["path"] = ".github/workflows/.yml"
        with pytest.raises(evidence.EvidenceError, match="directly name"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={".github/workflows/.yml": _workflow_body()},
            )

        document = _job_map_document()
        document["jobs"][0]["ref"] = ".github/workflows/other.yml#jobs.offline"
        with pytest.raises(evidence.EvidenceError, match="undeclared workflow"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

        document = _job_map_document()
        document["jobs"][0]["instances"][0]["id"] += "-forged"
        with pytest.raises(evidence.EvidenceError, match="does not match"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

    def test_instance_matrix_order_and_identity_are_canonical(self):
        document = _job_map_document()
        offline = next(job for job in document["jobs"] if job["lane"] == "H0-hermetic")
        matrix = offline["instances"][0]["matrix"]
        matrix.extend([
            {"name": "z-axis", "value": "a"},
            {"name": "a-axis", "value": "b"},
        ])
        with pytest.raises(evidence.EvidenceError, match="sorted by name"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

        document = _job_map_document()
        offline = next(job for job in document["jobs"] if job["lane"] == "H0-hermetic")
        offline["instances"].reverse()
        with pytest.raises(evidence.EvidenceError, match="sorted by id"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

    def test_lane_selection_and_capability_semantics_fail_closed(self):
        document = _job_map_document()
        offline = next(job for job in document["jobs"] if job["lane"] == "H0-hermetic")
        offline["selection"]["mark_expression"] = "integration"
        with pytest.raises(evidence.EvidenceError, match="primary lane marker"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

        document = _job_map_document()
        offline = next(job for job in document["jobs"] if job["lane"] == "H0-hermetic")
        offline["capabilities"] = ["git"]
        with pytest.raises(evidence.EvidenceError, match="only for H1/P0"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )

        document = _job_map_document()
        offline = next(job for job in document["jobs"] if job["lane"] == "H0-hermetic")
        offline["lane"] = "H1-tool-integration"
        offline["selection"]["mark_expression"] = "integration"
        with pytest.raises(evidence.EvidenceError, match="every H1"):
            evidence.validate_verification_job_map(
                document,
                workflow_bodies={WORKFLOW_PATH: _workflow_body()},
            )


class TestRepositoryWorkflowReads:
    def test_regular_workflow_is_read_exactly(self, tmp_path):
        body = b"name: exact\n"
        _write_test_workflow(tmp_path, body)
        assert evidence._repository_workflow_bodies(
            tmp_path, [{"path": WORKFLOW_PATH}]
        ) == {WORKFLOW_PATH: body}

    def test_missing_workflow_is_a_typed_io_refusal(self, tmp_path):
        tmp_path.joinpath(".github", "workflows").mkdir(parents=True)
        with pytest.raises(evidence.EvidenceError, match="cannot read verification workflow"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

    @pytest.mark.parametrize("linked_ancestor", [".github", "workflows"])
    def test_ancestor_symlinks_are_refused(self, tmp_path, linked_ancestor):
        outside = tmp_path / "outside"
        if linked_ancestor == ".github":
            _write_test_workflow(outside)
            (tmp_path / ".github").symlink_to(
                outside / ".github",
                target_is_directory=True,
            )
        else:
            (tmp_path / ".github").mkdir()
            outside.mkdir()
            (outside / "ci.yml").write_bytes(b"name: linked\n")
            (tmp_path / ".github" / "workflows").symlink_to(
                outside,
                target_is_directory=True,
            )
        with pytest.raises(evidence.EvidenceError, match="without following links"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

    def test_final_symlink_is_refused(self, tmp_path):
        target = tmp_path / WORKFLOW_PATH
        target.parent.mkdir(parents=True)
        actual = tmp_path / "actual.yml"
        actual.write_bytes(b"name: linked\n")
        target.symlink_to(actual)
        with pytest.raises(evidence.EvidenceError, match="without following links"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

    def test_directory_and_oversize_final_inputs_are_refused(self, tmp_path):
        target = tmp_path / WORKFLOW_PATH
        target.mkdir(parents=True)
        with pytest.raises(evidence.EvidenceError, match="regular file"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

        target.rmdir()
        target.write_bytes(b"x" * (evidence.MAX_RECORD_BYTES + 1))
        with pytest.raises(evidence.EvidenceError, match="exceeds"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo") or not hasattr(signal, "setitimer"),
        reason="POSIX FIFO nonblocking boundary",
    )
    def test_fifo_is_refused_without_waiting_for_a_writer(self, tmp_path):
        target = tmp_path / WORKFLOW_PATH
        target.parent.mkdir(parents=True)
        os.mkfifo(target)

        def timeout(*_args):
            raise AssertionError("workflow FIFO open blocked")

        prior_handler = signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, 2.0)
        try:
            with pytest.raises(evidence.EvidenceError, match="regular file"):
                evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prior_handler)

    def test_ordinary_read_and_close_faults_are_typed(self, tmp_path, monkeypatch):
        _write_test_workflow(tmp_path)

        def read_fault(*_args):
            raise OSError("read fault")

        monkeypatch.setattr(evidence.os, "read", read_fault)
        with pytest.raises(evidence.EvidenceError, match="read fault"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

        monkeypatch.undo()
        real_close = evidence.os.close

        def close_fault(descriptor):
            real_close(descriptor)
            raise OSError("close fault")

        monkeypatch.setattr(evidence.os, "close", close_fault)
        with pytest.raises(evidence.EvidenceError, match="close fault"):
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])

    @pytest.mark.parametrize(
        "cancellation",
        [KeyboardInterrupt("read cancellation"), SystemExit("read cancellation")],
        ids=["keyboard-interrupt", "system-exit"],
    )
    def test_primary_cancellation_survives_ordinary_close_fault(
        self,
        tmp_path,
        monkeypatch,
        cancellation,
    ):
        _write_test_workflow(tmp_path)
        real_close = evidence.os.close

        def cancel_read(*_args):
            raise cancellation

        def close_fault(descriptor):
            real_close(descriptor)
            raise OSError("secondary close fault")

        monkeypatch.setattr(evidence.os, "read", cancel_read)
        monkeypatch.setattr(evidence.os, "close", close_fault)
        with pytest.raises(type(cancellation)) as caught:
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])
        assert caught.value is cancellation

    @pytest.mark.parametrize(
        "cancellation",
        [KeyboardInterrupt("close cancellation"), SystemExit("close cancellation")],
        ids=["keyboard-interrupt", "system-exit"],
    )
    def test_close_cancellation_wins_over_ordinary_primary_fault(
        self,
        tmp_path,
        monkeypatch,
        cancellation,
    ):
        _write_test_workflow(tmp_path)
        real_close = evidence.os.close
        raised = False

        def read_fault(*_args):
            raise OSError("ordinary primary")

        def cancel_close(descriptor):
            nonlocal raised
            real_close(descriptor)
            if not raised:
                raised = True
                raise cancellation

        monkeypatch.setattr(evidence.os, "read", read_fault)
        monkeypatch.setattr(evidence.os, "close", cancel_close)
        with pytest.raises(type(cancellation)) as caught:
            evidence._repository_workflow_bodies(tmp_path, [{"path": WORKFLOW_PATH}])
        assert caught.value is cancellation


class TestCommittedWorkflowParity:
    def test_yaml_loader_itself_refuses_duplicate_mapping_keys(self):
        with pytest.raises(ConstructorError, match="duplicate key"):
            yaml.load("jobs:\n  offline: {}\n  offline: {}\n", Loader=_UniqueSafeLoader)

    def test_a_second_direct_workflow_is_caught_before_job_parity(self, tmp_path):
        _write_test_workflow(tmp_path)
        (tmp_path / ".github" / "workflows" / "second.yaml").write_bytes(b"jobs: {}\n")
        document = evidence.load_json_bytes(_job_map_body()[:-1])
        with pytest.raises(AssertionError):
            _assert_exact_workflow_inventory(document, tmp_path)

    def test_job_map_covers_each_current_job_matrix_instance_and_lane(self):
        # Production deliberately binds raw bytes only. This static parity
        # boundary owns YAML interpretation and rejects duplicate YAML keys.
        provisional = evidence.load_json_bytes(_job_map_body()[:-1])
        workflow_paths = _assert_exact_workflow_inventory(provisional, ROOT)
        workflow_bodies = {path: (ROOT / path).read_bytes() for path in workflow_paths}
        document = evidence.read_verification_job_map(
            _job_map_body(),
            workflow_bodies=workflow_bodies,
        )
        parsed_workflows = {
            path: yaml.load(body, Loader=_UniqueSafeLoader)
            for path, body in workflow_bodies.items()
        }
        for workflow_path, workflow in parsed_workflows.items():
            prefix = workflow_path + "#jobs."
            mapped_jobs = {
                record["ref"][len(prefix):]: record
                for record in document["jobs"]
                if record["ref"].startswith(prefix)
            }
            assert set(mapped_jobs) == set(workflow["jobs"])
            for job_id, configured in workflow["jobs"].items():
                mapped = mapped_jobs[job_id]
                assert mapped["lane"] == configured["env"]["QUARRY_PRIMARY_LANE"]
                mapped_matrix = {
                    tuple(
                        (parameter["name"], parameter["value"])
                        for parameter in instance["matrix"]
                    )
                    for instance in mapped["instances"]
                }
                assert mapped_matrix == _configured_matrix_rows(configured)

                pytest_selections = []
                for step in configured["steps"]:
                    if "run" not in step:
                        continue
                    tokens = shlex.split(step["run"])
                    for index, token in enumerate(tokens):
                        if token != "pytest":
                            continue
                        arguments = tokens[index + 1:]
                        if "-m" not in arguments:
                            continue
                        marker = arguments[arguments.index("-m") + 1]
                        keyword = (arguments[arguments.index("-k") + 1]
                                   if "-k" in arguments else "")
                        pytest_selections.append((marker, keyword))
                assert pytest_selections
                assert set(pytest_selections) == {(
                    mapped["selection"]["mark_expression"],
                    mapped["selection"]["keyword_expression"],
                )}

        offline = parsed_workflows[WORKFLOW_PATH]["jobs"]["offline"]
        mapped_offline = next(
            record for record in document["jobs"]
            if record["ref"] == WORKFLOW_PATH + "#jobs.offline"
        )
        assert mapped_offline["lane"] == "H0-hermetic"
        assert mapped_offline["capabilities"] == []
        assert offline["strategy"]["matrix"]["python-version"] == ["3.10", "3.12"]
        assert offline["strategy"]["matrix"]["shard"] == ["0", "1", "2", "3", "4", "5"]
        setup = next(
            step for step in offline["steps"]
            if str(step.get("uses", "")).startswith("actions/setup-python@")
        )
        assert setup["uses"] == \
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
        assert setup["with"]["python-version"] == "${{ matrix.python-version }}"
        for workflow in parsed_workflows.values():
            for configured in workflow["jobs"].values():
                for step in configured["steps"]:
                    uses = str(step.get("uses", ""))
                    if uses.startswith("actions/checkout@"):
                        assert uses == \
                            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
                    if uses.startswith("actions/setup-python@"):
                        assert uses == \
                            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
        test_steps = [
            step for step in offline["steps"]
            if step.get("name") == "H0 tests (deny guard)"
        ]
        assert len(test_steps) == 1
        test_step = test_steps[0]
        arguments = shlex.split(test_step["run"])
        pytest_arguments = [
            arguments[index + 1:] for index, token in enumerate(arguments)
            if token == "pytest"
        ]
        assert len(pytest_arguments) == 2
        assert all(
            values[values.index("-m") + 1] == mapped_offline["selection"]["mark_expression"]
            for values in pytest_arguments
        )
        assert "--quarry-shard-count 6" in test_step["run"]
        assert '--quarry-shard-index "${{ matrix.shard }}"' in test_step["run"]
        assert '${{ matrix.shard }}' in test_step["run"]
        expected_report = (
            "$RUNNER_TEMP/h0-shard-${{ matrix.python-version }}-"
            "${{ matrix.shard }}.json"
        )
        assert [
            arguments[index + 1] for index, token in enumerate(arguments)
            if token == "--quarry-taxonomy-manifest"
        ] == ["$RUNNER_TEMP/quarry-taxonomy.json"] * 2
        assert [
            arguments[index + 1] for index, token in enumerate(arguments)
            if token == "--quarry-h0-shard-report"
        ] == [expected_report] * 2
        assert test_step["env"]["QUARRY_OFFLINE_CI"] == "1"

        determinism_steps = [
            step for step in offline["steps"]
            if step.get("name") == "Determinism paired artifact-tree diff (existing Python 3.12 shard 0)"
        ]
        assert len(determinism_steps) == 1
        determinism = determinism_steps[0]
        assert determinism["if"] == "${{ matrix.python-version == '3.12' && matrix.shard == '0' }}"
        assert shlex.split(determinism["run"]) == [
            "python", "scripts/emit_determinism.py", "--fixture",
            "release/evidence/determinism-fixture-v1.json", "--h0-fragment",
            "$RUNNER_TEMP/h0-shard-3.12-0.json", "--job-instance-id",
            ".github/workflows/ci.yml#jobs.offline[python-version=3.12,shard=0]",
            "--output", "$RUNNER_TEMP/artifact-tree-diff-fragment.json",
        ]

        upload_steps = [
            step for step in offline["steps"]
            if step.get("name") == "Upload H0 shard outcome"
        ]
        assert len(upload_steps) == 1
        upload = upload_steps[0]
        assert upload["if"] == "${{ always() }}"
        assert upload["uses"] == \
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        assert upload["with"] == {
            "name": "h0-shard-outcome-${{ matrix.python-version }}-${{ matrix.shard }}",
            "path": (
                "${{ runner.temp }}/h0-shard-${{ matrix.python-version }}-"
                "${{ matrix.shard }}.json\n"
                "${{ runner.temp }}/quarry-taxonomy.json\n"
                "${{ runner.temp }}/quarry-coverage-3.12-${{ matrix.shard }}*\n"
                "${{ runner.temp }}/coverage-shard-${{ matrix.shard }}.json\n"
                "${{ runner.temp }}/security-scan-fragment.json\n"
                "${{ runner.temp }}/artifact-tree-diff-fragment.json\n"
            ),
            "if-no-files-found": "error",
        }
