"""Fail-closed checks for the pytest lane taxonomy and its diagnostic manifest."""

from __future__ import annotations

import json
import os
import platform
import shlex
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import conftest as taxonomy
import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.10 CI job
    import tomli as tomllib


pytestmark = pytest.mark.offline

_ROOT = Path(__file__).resolve().parents[1]


class _Item:
    nodeid = "tests/example.py::test_case"

    def __init__(self, **markers):
        self._markers = markers

    def iter_markers(self, name):
        return iter(self._markers.get(name, ()))


def _mark(*args, **kwargs):
    return SimpleNamespace(args=args, kwargs=kwargs)


@pytest.mark.parametrize(
    ("primary", "secondary", "expected_tools"),
    [
        ("offline", {}, ()),
        ("integration", {"requires_tool": (_mark("git"),)}, ("git",)),
        ("corpus", {}, ()),
        ("packaging", {}, ()),
        ("live", {}, ()),
    ],
)
def test_each_primary_lane_classifies_exactly(primary, secondary, expected_tools):
    item = _Item(**{primary: (_mark(),), **secondary})
    assert taxonomy._classify_test_item(item) == (primary, expected_tools, False)


def test_ci_shard_assignment_is_stable_complete_and_balanced():
    nodeids = [f"tests/example.py::test_case_{index}" for index in range(6000)]
    first = [taxonomy._test_shard(nodeid, 6) for nodeid in nodeids]
    assert first == [taxonomy._test_shard(nodeid, 6) for nodeid in nodeids]
    assert set(first) == set(range(6))
    counts = [first.count(index) for index in range(6)]
    assert max(counts) - min(counts) < 100


@pytest.mark.parametrize(
    ("markers", "message"),
    [
        ({}, "unmarked"),
        ({"offline": (_mark(),), "integration": (_mark(),)}, "multiple primary lanes"),
        ({"offline": (_mark("argument"),)}, "takes no arguments"),
        ({"offline": (_mark(), _mark())}, "duplicate primary marker"),
    ],
)
def test_missing_conflicting_or_parameterized_primary_is_rejected(markers, message):
    with pytest.raises(pytest.UsageError, match=message):
        taxonomy._classify_test_item(_Item(**markers))


@pytest.mark.parametrize(
    "bad_mark",
    [
        _mark(),
        _mark(""),
        _mark("git path"),
        _mark(3),
        _mark("git", "bwrap"),
        _mark(name="git"),
    ],
)
def test_requires_tool_demands_one_stable_name(bad_mark):
    item = _Item(integration=(_mark(),), requires_tool=(bad_mark,))
    with pytest.raises(pytest.UsageError, match="exactly one stable tool name"):
        taxonomy._classify_test_item(item)


def test_requires_tool_is_a_capability_not_a_primary_lane():
    unmarked = _Item(requires_tool=(_mark("git"),))
    with pytest.raises(pytest.UsageError, match="unmarked"):
        taxonomy._classify_test_item(unmarked)

    h0 = _Item(offline=(_mark(),), requires_tool=(_mark("git"),))
    with pytest.raises(pytest.UsageError, match="reviewed H1/P0 lane"):
        taxonomy._classify_test_item(h0)


def test_h1_requires_a_named_tool_and_duplicate_capabilities_are_rejected():
    with pytest.raises(pytest.UsageError, match="does not name its real tool"):
        taxonomy._classify_test_item(_Item(integration=(_mark(),)))

    duplicate = _Item(
        integration=(_mark(),),
        requires_tool=(_mark("git"), _mark("git")),
    )
    with pytest.raises(pytest.UsageError, match="duplicate requires_tool"):
        taxonomy._classify_test_item(duplicate)


def test_synthetic_process_is_secondary_and_h0_only():
    valid = _Item(offline=(_mark(),), synthetic_process=(_mark(),))
    assert taxonomy._classify_test_item(valid) == ("offline", (), True)

    wrong_lane = _Item(
        integration=(_mark(),),
        requires_tool=(_mark("git"),),
        synthetic_process=(_mark(),),
    )
    with pytest.raises(pytest.UsageError, match="only in the offline/H0 lane"):
        taxonomy._classify_test_item(wrong_lane)

    for bad in ((_mark("argument"),), (_mark(), _mark())):
        with pytest.raises(pytest.UsageError, match="synthetic_process"):
            taxonomy._classify_test_item(_Item(offline=(_mark(),), synthetic_process=bad))


def _ordinary_child(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    argv = [taxonomy._SYNTHETIC_INTERPRETER, "-c", "raise SystemExit(0)"]
    kwargs = {
        "cwd": os.fspath(_ROOT),
        "env": {
            "HOME": os.fspath(home),
            "PATH": "",
        },
        "shell": False,
    }
    return argv, kwargs


def test_synthetic_child_accepts_only_the_current_interpreter_and_minimal_env(tmp_path):
    argv, kwargs = _ordinary_child(tmp_path)
    taxonomy._validate_synthetic_spawn(argv, (), kwargs, home_root=tmp_path)

    bad_cases = [
        (["python", *argv[1:]], kwargs),
        (argv, {**kwargs, "shell": True}),
        (argv, {**kwargs, "executable": sys.executable}),
        (argv, {**kwargs, "preexec_fn": lambda: None}),
        (argv, {**kwargs, "close_fds": False}),
        (argv, {**kwargs, "close_fds": 0}),
        (argv, {**kwargs, "close_fds": None}),
        (argv, {**kwargs, "pass_fds": (7,)}),
        (argv, {**kwargs, "pass_fds": []}),
        (argv, {**kwargs, "startupinfo": object()}),
        (argv, {**kwargs, "user": "nobody"}),
        (argv, {**kwargs, "group": 7}),
        (argv, {**kwargs, "extra_groups": ()}),
        (argv, {**kwargs, "creationflags": 1}),
        (argv, {**kwargs, "umask": 0}),
        (argv, {**kwargs, "process_group": 0}),
        (argv, {**kwargs, "stdin": 7}),
        (argv, {**kwargs, "stdout": 8}),
        (argv, {**kwargs, "stderr": 9}),
        (argv, {**kwargs, "cwd": "relative"}),
        (argv, {**kwargs, "cwd": os.fspath(tmp_path.parent)}),
        (argv, {**kwargs, "env": {**kwargs["env"], "TOKEN": "ambient"}}),
        (argv, {**kwargs, "env": {**kwargs["env"], "PATH": "/usr/bin"}}),
        (argv, {**kwargs, "env": {"PATH": kwargs["env"]["PATH"]}}),
    ]
    for bad_argv, bad_kwargs in bad_cases:
        with pytest.raises(taxonomy.NetworkDenied):
            taxonomy._validate_synthetic_spawn(
                bad_argv, (), bad_kwargs, home_root=tmp_path,
            )

    with pytest.raises(taxonomy.NetworkDenied, match="argv list/tuple"):
        taxonomy._validate_synthetic_spawn(argv, ("positional",), kwargs, home_root=tmp_path)


def test_synthetic_child_home_must_resolve_below_pytest_temp_root(tmp_path):
    argv, kwargs = _ordinary_child(tmp_path)
    kwargs["env"]["HOME"] = os.fspath(tmp_path.parent)
    with pytest.raises(taxonomy.NetworkDenied, match="outside the pytest temporary root"):
        taxonomy._validate_synthetic_spawn(argv, (), kwargs, home_root=tmp_path)


def test_mutating_shared_sys_executable_cannot_replace_the_pinned_interpreter(
    tmp_path, monkeypatch,
):
    _argv, kwargs = _ordinary_child(tmp_path)
    monkeypatch.setattr(taxonomy.sys, "executable", "/bin/sh")
    with pytest.raises(taxonomy.NetworkDenied, match="absolute current interpreter"):
        taxonomy._validate_synthetic_spawn(
            [taxonomy.sys.executable, "-c", "exit 0"],
            (),
            kwargs,
            home_root=tmp_path,
        )
    assert taxonomy._SYNTHETIC_INTERPRETER != taxonomy.sys.executable


def test_runner_worker_has_an_exact_specialized_shape():
    argv = [taxonomy._SYNTHETIC_INTERPRETER, "-I", "-m", "quarry_recon.runner_worker"]
    kwargs = {
        "cwd": "/",
        "env": {
            "QUARRY_RUNNER_EXPECTED_PARENT_PID": "123",
            "QUARRY_RUNNER_PREPARED_ABORT": "1",
        },
        "shell": False,
    }
    taxonomy._validate_synthetic_spawn(argv, (), kwargs, home_root=None)

    execution_kwargs = {
        **kwargs,
        "env": {
            "QUARRY_RUNNER_EXPECTED_PARENT_PID": "123",
            "QUARRY_RUNNER_EXECUTION": "1",
            "QUARRY_RUNNER_STDOUT_FD": "7",
            "QUARRY_RUNNER_STDERR_FD": "9",
        },
        "pass_fds": (9, 7),
    }
    taxonomy._validate_synthetic_spawn(argv, (), execution_kwargs, home_root=None)

    invalid = [
        (argv + ["extra"], kwargs),
        (argv, {**kwargs, "cwd": os.fspath(_ROOT)}),
        (argv, {**kwargs, "env": {**kwargs["env"], "PATH": "/usr/bin"}}),
        (argv, {**kwargs, "env": {**kwargs["env"], "QUARRY_RUNNER_EXECUTION": "1"}}),
        (
            argv,
            {
                **kwargs,
                "env": {
                    "QUARRY_RUNNER_EXPECTED_PARENT_PID": "123",
                    "QUARRY_RUNNER_EXECUTION": "1",
                    "QUARRY_RUNNER_PREPARED_ABORT": "garbage",
                },
            },
        ),
        (argv, {**kwargs, "env": {**kwargs["env"], "QUARRY_RUNNER_STDOUT_FD": "fd"}}),
        (
            argv,
            {
                **kwargs,
                "env": {**kwargs["env"], "QUARRY_RUNNER_STDOUT_FD": "0"},
                "pass_fds": (0,),
            },
        ),
        (
            argv,
            {
                **kwargs,
                "env": {**kwargs["env"], "QUARRY_RUNNER_STDOUT_FD": "7"},
                "pass_fds": (7,),
            },
        ),
        (argv, {**execution_kwargs, "pass_fds": (7,)}),
        (argv, {**execution_kwargs, "pass_fds": (7, 9, 11)}),
        (argv, {**execution_kwargs, "pass_fds": (7, 7, 9)}),
        (argv, {**execution_kwargs, "pass_fds": [7, 9]}),
        (
            argv,
            {
                **execution_kwargs,
                "env": {
                    **execution_kwargs["env"],
                    "QUARRY_RUNNER_STDERR_FD": "7",
                },
                "pass_fds": (7,),
            },
        ),
    ]
    for bad_argv, bad_kwargs in invalid:
        with pytest.raises(taxonomy.NetworkDenied):
            taxonomy._validate_synthetic_spawn(
                bad_argv, (), bad_kwargs, home_root=None,
            )


def test_guarded_popen_preserves_keyword_args_but_still_denies_h0():
    with pytest.raises(taxonomy.NetworkDenied, match="denied subprocess"):
        taxonomy._GuardedPopen(
            args=[sys.executable, "-c", "raise SystemExit(0)"],
            cwd=os.fspath(_ROOT),
            env={},
            shell=False,
        )


def test_synthetic_guard_never_claims_to_be_child_containment():
    assert "tracked-test tripwires, not child containment" in taxonomy.__doc__
    assert "OS-isolated H0 evidence boundary therefore\nremains open" in taxonomy.__doc__


def test_manifest_is_canonical_and_reconciles_pre_and_post_selection():
    rows = [
        ("tests/z.py::test_z", "integration", ("git",), False),
        ("tests/a.py::test_a", "offline", (), True),
        ("tests/m.py::test_m", "packaging", ("build",), False),
    ]
    expected = taxonomy._taxonomy_manifest_bytes(
        rows,
        ["tests/z.py::test_z", "tests/a.py::test_a"],
        mark_expression="offline or integration",
        keyword_expression="test_",
    )
    reversed_input = taxonomy._taxonomy_manifest_bytes(
        list(reversed(rows)),
        ["tests/a.py::test_a", "tests/z.py::test_z"],
        mark_expression="offline or integration",
        keyword_expression="test_",
    )
    assert reversed_input == expected
    assert len(expected) < taxonomy._MAX_TAXONOMY_MANIFEST_BYTES

    manifest = json.loads(expected)
    assert manifest["schema_version"] == "quarry.pytest-taxonomy.v1"
    assert manifest["collector"] == {
        "name": "pytest",
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "version": pytest.__version__,
    }
    assert manifest["selection"] == {
        "collected": 3,
        "deselected": 1,
        "keyword_expression": "test_",
        "mark_expression": "offline or integration",
        "selected": 2,
        "selected_by_lane": [
            {"lane": "H0-hermetic", "selected": 1},
            {"lane": "H1-tool-integration", "selected": 1},
            {"lane": "C0-private-corpus", "selected": 0},
            {"lane": "P0-package-supply", "selected": 0},
            {"lane": "L0-authorized-live", "selected": 0},
        ],
    }
    assert manifest["capabilities"] == [
        {"name": "build", "nodes": ["tests/m.py::test_m"]},
        {"name": "git", "nodes": ["tests/z.py::test_z"]},
    ]


def test_collection_manifest_accounts_for_every_node(pytestconfig):
    manifest = json.loads(pytestconfig.stash[taxonomy.TAXONOMY_MANIFEST_KEY])
    lane_nodes = [node for lane in manifest["lanes"] for node in lane["nodes"]]
    selection = manifest["selection"]
    assert len(lane_nodes) == len(set(lane_nodes)) == selection["collected"]
    assert selection["selected"] + selection["deselected"] == selection["collected"]
    assert sum(row["selected"] for row in selection["selected_by_lane"]) == selection["selected"]
    for lane in manifest["lanes"]:
        assert lane["nodes"] == sorted(
            lane["nodes"], key=lambda value: value.encode("utf-8"),
        )
    module_lanes = {
        lane["marker"]
        for lane in manifest["lanes"]
        for node in lane["nodes"]
        if node.startswith("tests/test_taxonomy_enforcement.py::")
    }
    assert module_lanes == {"offline"}


def test_manifest_writer_is_private_and_never_overwrites(tmp_path):
    target = tmp_path / "taxonomy.json"
    taxonomy._write_new_private(target, b"first")
    assert target.read_bytes() == b"first"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(pytest.UsageError, match="cannot create taxonomy manifest"):
        taxonomy._write_new_private(target, b"replacement")
    assert target.read_bytes() == b"first"


def test_collection_hook_wraps_marker_deselection_from_the_outside():
    implementation = taxonomy.pytest_collection_modifyitems.pytest_impl
    assert implementation["wrapper"] is True
    assert implementation["tryfirst"] is True
    assert implementation["trylast"] is False


def test_pyproject_has_only_explicit_primary_lane_policy():
    with (_ROOT / "pyproject.toml").open("rb") as stream:
        pytest_config = tomllib.load(stream)["tool"]["pytest"]["ini_options"]
    declared = {
        entry.partition(":")[0].partition("(")[0]
        for entry in pytest_config["markers"]
    }
    assert set(taxonomy._PRIMARY_LANE_MARKERS) <= declared
    assert "default_offline" not in declared
    arguments = shlex.split(pytest_config["addopts"])
    assert arguments[arguments.index("-m") + 1] == "offline"


def test_every_ci_job_declares_one_primary_lane_and_h0_selects_positively():
    workflows = sorted((_ROOT / ".github" / "workflows").glob("*.y*ml"))
    assert workflows
    known_lanes = {lane for _marker, lane in taxonomy._PRIMARY_LANES}
    pytest_commands = []
    for path in workflows:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        for job_name, job in document["jobs"].items():
            lane = job.get("env", {}).get("QUARRY_PRIMARY_LANE")
            assert lane in known_lanes, (path, job_name, lane)
            for step in job.get("steps", ()):
                command = step.get("run", "")
                if "pytest" in command:
                    pytest_commands.append((lane, shlex.split(command)))
    assert pytest_commands
    for lane, arguments in pytest_commands:
        if lane == "H0-hermetic":
            assert arguments[arguments.index("-m") + 1] == "offline"
            assert "--quarry-taxonomy-manifest" in arguments
