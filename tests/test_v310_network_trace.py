from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from pathlib import Path

import pytest

from quarry_recon import network_trace
from quarry_recon.network_broker import NetworkBrokerRefused, NetworkEffectFence


pytestmark = pytest.mark.offline

_LIMITS = {
    "max_rows": 256,
    "max_bytes": 256 * 1024,
    "max_row_bytes": 1024,
}
_INVOCATION_ID = "1" * 32
_ARTIFACT_RELPATH = "raw/network/invocation-1/network-trace.jsonl"


@pytest.fixture
def trace_directory(tmp_path):
    tmp_path.chmod(0o700)
    descriptor = os.open(
        tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        yield tmp_path, descriptor
    finally:
        os.close(descriptor)


def _create(directory_fd, **overrides):
    values = {**_LIMITS, **overrides}
    if "effect_fence" not in values:
        values["effect_fence"] = NetworkEffectFence(
            values.get("cancellation_event"),
        )
    return network_trace.NetworkTraceArtifact.create(
        directory_fd, _INVOCATION_ID, _ARTIFACT_RELPATH, **values,
    )


def _replay(directory_fd, **overrides):
    values = {**_LIMITS, **overrides}
    return network_trace.replay_network_trace(
        directory_fd, _INVOCATION_ID, _ARTIFACT_RELPATH, **values,
    )


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text("ascii").splitlines()]


def _rechain(rows: list[dict]) -> bytes:
    digest = hashlib.sha256()
    output = bytearray()
    for sequence, row in enumerate(rows):
        row["sequence"] = sequence
        row["previous_sha256"] = digest.hexdigest()
        line = (json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ) + "\n").encode("ascii")
        output.extend(line)
        digest.update(line)
    return bytes(output)


def _one_pair(directory_fd, *, component="broker.standard"):
    artifact = _create(directory_fd)
    token = artifact.plan(
        component, "connect",
        {"host": "example.test", "peer": "192.0.2.10", "port": 443},
    )
    artifact.settle(token, "allowed", {"bytes": 7})
    return artifact


def test_creation_is_private_preallocated_and_logically_empty(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    path = root / network_trace.ARTIFACT_NAME
    observed = path.stat()
    assert stat.S_ISREG(observed.st_mode)
    assert stat.S_IMODE(observed.st_mode) == 0o600
    assert observed.st_uid == os.geteuid()
    assert observed.st_nlink == 1
    # KEEP_SIZE allocation reserves blocks without manufacturing a padded
    # suffix; only the durable invocation header contributes logical bytes.
    assert observed.st_size > 0
    assert observed.st_blocks * 512 >= _LIMITS["max_bytes"]
    artifact.close()


def test_creation_orders_preallocation_file_fsync_and_parent_fsync(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    calls = []
    real_preallocate = network_trace._preallocate_keep_size
    real_fsync = network_trace.os.fsync

    def preallocate(descriptor, length):
        calls.append(("preallocate", stat.S_ISREG(os.fstat(descriptor).st_mode)))
        return real_preallocate(descriptor, length)

    def fsync(descriptor):
        calls.append((
            "fsync",
            "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file",
        ))
        return real_fsync(descriptor)

    monkeypatch.setattr(network_trace, "_preallocate_keep_size", preallocate)
    monkeypatch.setattr(network_trace.os, "fsync", fsync)
    artifact = _create(directory_fd)
    assert calls[:3] == [
        ("preallocate", True), ("fsync", "file"), ("fsync", "directory"),
    ]
    artifact.close()


def test_parent_must_be_dedicated_private_authority(tmp_path):
    for name, prepare in (
        ("writable", lambda path: path.chmod(0o777)),
        ("preexisting", lambda path: (path / "other").write_text("x")),
        ("symlink", lambda path: (path / network_trace.ARTIFACT_NAME).symlink_to("missing")),
    ):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        prepare(root)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with pytest.raises(network_trace.NetworkTraceRefused):
                _create(descriptor)
        finally:
            os.close(descriptor)


def test_structurally_compatible_fake_effect_fence_is_refused(trace_directory):
    root, directory_fd = trace_directory

    class FakeFence:
        def __init__(self):
            self.event = threading.Event()
            self.cancel_calls = 0

        def cancel(self):
            self.cancel_calls += 1

        def is_set(self):
            return False

        def __enter__(self):
            return self

        def __exit__(self, _kind, _value, _traceback):
            return False

    fake = FakeFence()
    with pytest.raises(
        network_trace.NetworkTraceRefused, match="effect_fence_invalid",
    ):
        _create(directory_fd, effect_fence=fake)
    assert fake.cancel_calls == 0
    assert list(root.iterdir()) == []


def test_one_shared_writer_sequences_two_brokers_proxy_and_cdp_concurrently(
        trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(
        directory_fd, max_rows=2048, max_bytes=2 * 1024 * 1024,
    )
    components = (
        "broker.browser", "broker.controller", "proxy", "cdp",
    )
    barrier = threading.Barrier(len(components))
    failures = []

    def worker(component):
        try:
            barrier.wait()
            operation = {
                "proxy": "peer_connect", "cdp": "controller_connection",
            }.get(component, "connect")
            observation_operation = {
                "proxy": "request", "cdp": "message",
            }.get(component, "notification")
            for index in range(40):
                artifact.observe(
                    component, observation_operation, "allowed",
                    {"worker_index": index},
                )
                token = artifact.plan(
                    component, operation, {"worker_index": index},
                    reserve_rows=2,
                )
                artifact.event(token, "admitted", {"worker_index": index})
                artifact.settle(token, "allowed", {"worker_index": index})
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(value,)) for value in components]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures

    settlement = artifact.finalize("allow", "complete")
    artifact.close()
    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert [row["sequence"] for row in rows] == list(range(642))
    assert settlement["rows"] == 642
    assert settlement["open_plans"] == 0
    assert settlement["complete"] is True
    for component in components:
        assert settlement["components"][component] == {
            "sha256": settlement["components"][component]["sha256"],
            "rows": 160,
            "plans": 40,
            "events": 40,
            "terminals": 40,
            "observations": 40,
            "open_plans": 0,
            "complete": True,
        }


def test_observation_is_typed_effect_free_and_replay_bound(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.observe(
        "broker.standard", "notification", "denied",
        {"syscall": 999},
    )
    artifact.observe(
        "proxy", "request", "allowed", {"authority": "example.test"},
    )
    artifact.observe(
        "cdp", "message", "completed", {"method": "Fetch.enable"},
    )
    settlement = artifact.finalize("allow", "complete")
    artifact.close()

    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert [row["kind"] for row in rows] == [
        "header", "observation", "observation", "observation", "seal",
    ]
    assert all("plan_id" not in row for row in rows[1:4])
    assert settlement["open_plans"] == 0
    assert settlement["components"]["broker.standard"]["observations"] == 1
    assert settlement["components"]["proxy"]["observations"] == 1
    assert settlement["components"]["cdp"]["observations"] == 1
    replayed = _replay(directory_fd, expected_settlement=settlement)
    assert replayed == settlement


def test_n_plus_one_observation_records_fatal_and_cancels(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd, max_rows=4, max_bytes=8192)
    artifact.observe(
        "broker.standard", "notification", "denied", {"number": 1},
    )
    with pytest.raises(
        network_trace.NetworkTraceCapacityError,
        match="network_trace_capacity_exhausted",
    ):
        artifact.observe(
            "broker.controller", "notification", "denied", {"number": 2},
        )

    assert artifact.cancellation_event.is_set()
    settlement = artifact.finalize("deny", "capacity_exhausted")
    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert [row["kind"] for row in rows] == [
        "header", "observation", "fatal", "seal",
    ]
    assert settlement["components"]["broker.standard"]["observations"] == 1
    assert settlement["components"]["broker.controller"]["observations"] == 0
    assert settlement["fatal"] == "network_trace_capacity_exhausted"
    assert settlement["dropped_rows"] == 1
    assert settlement["complete"] is False
    artifact.close()


@pytest.mark.parametrize("fault", ("write", "fsync"))
def test_observation_append_fault_cancels_shared_fence(
        trace_directory, monkeypatch, fault):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    if fault == "write":
        monkeypatch.setattr(
            network_trace.os, "pwrite",
            lambda *_args: (_ for _ in ()).throw(OSError("fixture write fault")),
        )
    else:
        real_fsync = network_trace.os.fsync

        def fail_file_fsync(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("fixture fsync fault")
            return real_fsync(descriptor)

        monkeypatch.setattr(network_trace.os, "fsync", fail_file_fsync)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError,
        match="network_trace_durable_append_failed",
    ):
        artifact.observe("proxy", "request", "denied")
    assert fence.is_set() and artifact.cancellation_event.is_set()
    artifact.close()


def test_observation_is_forbidden_after_fatal_and_seal(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    with pytest.raises(
        network_trace.NetworkTraceRefused,
        match="network_trace_observation_invalid",
    ):
        artifact.observe("broker.standard", "unknown", "denied")
    with pytest.raises(network_trace.NetworkTraceRefused):
        artifact.observe("broker.standard", "notification", "denied")
    settlement = artifact.finalize("deny", "invalid_observation")
    sealed_size = (root / network_trace.ARTIFACT_NAME).stat().st_size
    with pytest.raises(network_trace.NetworkTraceRefused, match="sealed"):
        artifact.observe("broker.standard", "notification", "denied")
    assert (root / network_trace.ARTIFACT_NAME).stat().st_size == sealed_size
    assert settlement["fatal"] == "network_trace_observation_invalid"
    artifact.close()


def test_deny_finalize_drains_live_effect_epoch_before_return(trace_directory):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    artifact.plan("proxy", "relay")
    entered = threading.Event()
    release = threading.Event()
    effect_finished = threading.Event()
    results = []

    def live_effect():
        with fence:
            entered.set()
            release.wait()
        effect_finished.set()

    def finalize():
        results.append(artifact.finalize("deny", "external_cancellation"))

    effect_thread = threading.Thread(target=live_effect)
    effect_thread.start()
    assert entered.wait(2)
    finalizer = threading.Thread(target=finalize)
    finalizer.start()
    assert fence.event.wait(2)
    finalizer.join(0.05)
    assert finalizer.is_alive() and not effect_finished.is_set()
    release.set()
    effect_thread.join(2)
    finalizer.join(2)
    assert effect_finished.is_set() and not finalizer.is_alive()
    assert results[0]["decision"] == "deny"
    assert results[0]["open_plans"] == 1
    assert results[0]["complete"] is False
    with pytest.raises(NetworkBrokerRefused):
        with fence:
            pytest.fail("cancelled fence admitted a post-settlement effect")
    artifact.close()


def test_close_drains_live_epoch_and_preserves_unsealed_open_truth(
        trace_directory):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    artifact.plan("proxy", "relay")
    entered = threading.Event()
    release = threading.Event()

    def live_effect():
        with fence:
            entered.set()
            release.wait()

    effect_thread = threading.Thread(target=live_effect)
    effect_thread.start()
    assert entered.wait(2)
    close_errors = []

    def close_artifact():
        try:
            artifact.close()
        except BaseException as exc:  # pragma: no cover - asserted below
            close_errors.append(exc)

    closer = threading.Thread(target=close_artifact)
    closer.start()
    assert fence.event.wait(2)
    closer.join(0.05)
    assert closer.is_alive()
    release.set()
    effect_thread.join(2)
    closer.join(2)
    assert (not effect_thread.is_alive() and not closer.is_alive()
            and not close_errors)
    with pytest.raises(NetworkBrokerRefused):
        with fence:
            pytest.fail("closed trace left the network fence open")
    replayed = _replay(directory_fd)
    assert replayed["decision"] is None
    assert replayed["open_plans"] == 1
    assert replayed["complete"] is False


def test_native_dns_is_its_own_resolver_effect_not_an_http_answer(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    token = artifact.plan(
        "native.dns", "resolver_query",
        {
            "qname": "www.example.test", "qtype": "aaaa",
            "resolver_peer": "192.0.2.53", "resolver_port": 53,
            "transport": "udp", "transaction": 17,
        },
    )
    artifact.settle(token, "allowed", {"answers": ["2001:db8::10"]})
    settlement = artifact.finalize("allow", "complete")
    assert settlement["components"]["native.dns"]["plans"] == 1
    row = _rows(root / network_trace.ARTIFACT_NAME)[1]
    assert row["component"] == "native.dns"
    assert row["data"]["qname"] == "www.example.test"
    assert "host" not in row["data"] and "approved" not in row["data"]
    artifact.close()


def test_compact_settlement_binds_exact_bytes_and_contains_no_invocation_secret_or_path(
        trace_directory):
    root, directory_fd = trace_directory
    secret = "secret-request-token-do-not-copy"
    artifact = _create(directory_fd)
    token = artifact.plan("proxy", "peer_connect", {"label": secret})
    artifact.settle(token, "denied", {"reason": "policy"})
    settlement = artifact.finalize("allow", "complete")
    body = (root / network_trace.ARTIFACT_NAME).read_bytes()
    compact = (json.dumps(
        settlement, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ) + "\n").encode("ascii")
    assert len(compact) <= network_trace.NETWORK_TRACE_MAX_SETTLEMENT_BYTES
    assert settlement["sha256"] == hashlib.sha256(body).hexdigest()
    assert settlement["bytes"] == len(body)
    assert secret.encode() not in compact
    assert _INVOCATION_ID.encode() not in compact
    assert str(root).encode() not in compact
    assert set(settlement) == {
        "schema_version", "artifact", "sha256", "bytes", "rows",
        "open_plans", "dropped_rows", "fatal", "components", "complete",
        "invocation_sha256", "decision", "reason",
        "artifact_relpath", "certified",
    }
    artifact.close()


def test_crash_immediately_after_create_is_bound_but_unsealed(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.close()
    settlement = _replay(directory_fd)
    assert settlement["rows"] == 1
    assert settlement["decision"] is None
    assert settlement["reason"] is None
    assert settlement["complete"] is False
    assert settlement["invocation_sha256"] == hashlib.sha256(
        _INVOCATION_ID.encode("ascii"),
    ).hexdigest()


def test_other_invocation_artifact_is_refused(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    with pytest.raises(network_trace.NetworkTraceIntegrityError, match="header"):
        network_trace.replay_network_trace(
            directory_fd, "2" * 32, _ARTIFACT_RELPATH, **_LIMITS,
        )


def test_other_invocation_relative_path_is_refused(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    with pytest.raises(network_trace.NetworkTraceIntegrityError, match="header"):
        network_trace.replay_network_trace(
            directory_fd, _INVOCATION_ID,
            "raw/network/different/network-trace.jsonl", **_LIMITS,
        )


@pytest.mark.parametrize(
    "value",
    (
        "/absolute/network-trace.jsonl",
        "../escape/network-trace.jsonl",
        "network-trace.jsonl",
        "raw/network/other.jsonl",
    ),
)
def test_artifact_relative_path_is_canonical_and_bounded(
        trace_directory, value):
    root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    with pytest.raises(network_trace.NetworkTraceRefused, match="relpath"):
        network_trace.NetworkTraceArtifact.create(
            directory_fd, _INVOCATION_ID, value,
            effect_fence=fence, **_LIMITS,
        )
    assert fence.is_set() and list(root.iterdir()) == []
    with pytest.raises(NetworkBrokerRefused):
        with fence:
            pytest.fail("construction refusal left the network fence open")


@pytest.mark.parametrize(
    "override",
    (
        {"max_rows": network_trace.NETWORK_TRACE_MAX_ROWS + 1},
        {"max_bytes": network_trace.NETWORK_TRACE_MAX_BYTES + 1},
        {"max_row_bytes": network_trace.NETWORK_TRACE_MAX_ROW_BYTES + 1},
        {"max_depth": network_trace.NETWORK_TRACE_MAX_JSON_DEPTH + 1},
        {
            "max_integer":
            network_trace.NETWORK_TRACE_MAX_INTEGER_MAGNITUDE + 1,
        },
    ),
    ids=("rows", "bytes", "row-bytes", "depth", "integer"),
)
def test_advertised_limit_ceilings_refuse_before_filesystem_effect(
        trace_directory, monkeypatch, override):
    root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    monkeypatch.setattr(
        network_trace.os, "dup",
        lambda *_args: pytest.fail("invalid limits reached directory dup"),
    )
    with pytest.raises(network_trace.NetworkTraceRefused, match="limits_invalid"):
        network_trace.NetworkTraceArtifact.create(
            directory_fd, _INVOCATION_ID, _ARTIFACT_RELPATH,
            effect_fence=fence, **{**_LIMITS, **override},
        )
    assert fence.is_set() and list(root.iterdir()) == []


def test_invalid_components_cancel_valid_fence_before_filesystem_effect(
        trace_directory, monkeypatch):
    root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    monkeypatch.setattr(
        network_trace.os, "dup",
        lambda *_args: pytest.fail("invalid components reached directory dup"),
    )
    with pytest.raises(
        network_trace.NetworkTraceRefused, match="components_invalid",
    ):
        network_trace.NetworkTraceArtifact.create(
            directory_fd, _INVOCATION_ID, _ARTIFACT_RELPATH,
            effect_fence=fence, components=("unknown",), **_LIMITS,
        )
    assert fence.is_set() and list(root.iterdir()) == []


def test_cross_invocation_file_substitution_is_refused(tmp_path):
    roots = [tmp_path / "one", tmp_path / "two"]
    ids = ("1" * 32, "2" * 32)
    descriptors = []
    try:
        for root, invocation_id in zip(roots, ids):
            root.mkdir(mode=0o700)
            descriptor = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            descriptors.append(descriptor)
            artifact = network_trace.NetworkTraceArtifact.create(
                descriptor, invocation_id,
                f"raw/network/invocation-{invocation_id[0]}/network-trace.jsonl",
                effect_fence=NetworkEffectFence(), **_LIMITS,
            )
            artifact.finalize("allow", "complete")
            artifact.close()
        (roots[0] / network_trace.ARTIFACT_NAME).unlink()
        os.replace(
            roots[1] / network_trace.ARTIFACT_NAME,
            roots[0] / network_trace.ARTIFACT_NAME,
        )
        with pytest.raises(network_trace.NetworkTraceIntegrityError, match="header"):
            network_trace.replay_network_trace(
                descriptors[0], ids[0],
                "raw/network/invocation-1/network-trace.jsonl", **_LIMITS,
            )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_n_plus_one_plan_records_durable_fatal_and_refuses_before_effect(
        trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd, max_rows=5, max_bytes=8192)
    effects = []

    first = artifact.plan("broker.standard", "connect", {"number": 1})
    effects.append(1)
    artifact.settle(first, "allowed")
    with pytest.raises(
        network_trace.NetworkTraceCapacityError,
        match="network_trace_capacity_exhausted",
    ):
        artifact.plan("broker.browser", "connect", {"number": 2})
        effects.append(2)

    assert effects == [1]
    assert artifact.cancellation_event.is_set()
    settlement = artifact.finalize("deny", "capacity_exhausted")
    assert settlement["complete"] is False
    assert settlement["fatal"] == "network_trace_capacity_exhausted"
    assert settlement["dropped_rows"] == 1
    assert [row["kind"] for row in _rows(root / network_trace.ARTIFACT_NAME)] == [
        "header", "plan", "terminal", "fatal", "seal",
    ]
    artifact.close()


def test_fatal_capacity_still_allows_every_existing_plan_to_settle(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd, max_rows=5, max_bytes=8192)
    token = artifact.plan("broker.standard", "connect")
    with pytest.raises(network_trace.NetworkTraceCapacityError):
        artifact.plan("proxy", "peer_connect", reserve_rows=2)
    artifact.settle(token, "cancelled", {"code": "fence_closed"})
    settlement = artifact.finalize("deny", "capacity_exhausted")
    assert settlement["open_plans"] == 0
    assert settlement["components"]["broker.standard"]["complete"] is False
    assert settlement["fatal"] == "network_trace_capacity_exhausted"
    artifact.close()


def test_external_cancellation_is_durable_and_precedes_effect(trace_directory):
    root, directory_fd = trace_directory
    cancelled = threading.Event()
    artifact = _create(directory_fd, cancellation_event=cancelled)
    effects = []
    cancelled.set()
    with pytest.raises(network_trace.NetworkTraceRefused, match="cancelled"):
        artifact.plan("native.http", "request", {"host": "example.test"})
        effects.append("contact")
    assert effects == []
    assert _rows(root / network_trace.ARTIFACT_NAME)[1]["code"] == (
        "network_trace_cancelled"
    )
    artifact.close()


def test_cancellation_between_plan_and_effect_fence_entry_prevents_contact(
        trace_directory):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    planned = threading.Event()
    continue_to_effect = threading.Event()
    effects = []
    failures = []

    def worker():
        try:
            token = artifact.plan("native.http", "request")
            planned.set()
            continue_to_effect.wait()
            try:
                with fence:
                    effects.append("contact")
            except NetworkBrokerRefused:
                artifact.settle(token, "cancelled", {"code": "fence_closed"})
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    assert planned.wait(2)
    fence.cancel()
    continue_to_effect.set()
    thread.join(2)
    assert not thread.is_alive() and not failures
    assert effects == []
    settlement = artifact.finalize("deny", "external_cancellation")
    assert settlement["open_plans"] == 0
    artifact.close()


def test_trace_write_fault_synchronously_waits_for_effect_fence_drain(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    entered = threading.Event()
    release = threading.Event()
    holder_done = threading.Event()

    def hold_one_short_epoch():
        with fence:
            entered.set()
            release.wait()
        holder_done.set()

    holder = threading.Thread(target=hold_one_short_epoch)
    holder.start()
    assert entered.wait(2)
    monkeypatch.setattr(
        network_trace.os, "pwrite",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture write fault")),
    )
    result = []

    def plan():
        try:
            artifact.plan("native.http", "request")
        except BaseException as exc:
            result.append(exc)

    planner = threading.Thread(target=plan)
    planner.start()
    assert fence.event.wait(2)
    assert planner.is_alive() and not holder_done.is_set()
    release.set()
    holder.join(2)
    planner.join(2)
    assert holder_done.is_set() and not planner.is_alive()
    assert len(result) == 1 and isinstance(
        result[0], network_trace.NetworkTraceIntegrityError,
    )
    artifact.close()


def test_unexpected_row_encoder_failure_always_cancels_shared_fence(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    monkeypatch.setattr(
        network_trace, "_canonical_line",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("fixture encoder failure"),
        ),
    )
    with pytest.raises(RuntimeError, match="fixture encoder failure"):
        artifact.plan("native.http", "request")
    assert fence.is_set() and artifact.cancellation_event.is_set()
    with pytest.raises(NetworkBrokerRefused):
        with fence:
            pytest.fail("trace failure left the network fence open")
    artifact.close()


def test_invalid_terminal_gets_bounded_terminal_then_fatal(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    token = artifact.plan("proxy", "peer_connect")
    with pytest.raises(network_trace.NetworkTraceRefused, match="json_type"):
        artifact.settle(token, "allowed", {"invalid": object()})
    settlement = artifact.finalize("deny", "terminal_invalid")
    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert [row["kind"] for row in rows] == [
        "header", "plan", "terminal", "fatal", "seal",
    ]
    assert rows[2]["outcome"] == "error"
    assert settlement["open_plans"] == 0
    assert settlement["fatal"] == "network_trace_terminal_invalid"
    artifact.close()


def test_duplicate_terminal_is_a_durable_fatal_not_a_second_terminal(
        trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    token = artifact.plan("cdp", "controller_connection")
    artifact.settle(token, "allowed")
    with pytest.raises(network_trace.NetworkTraceRefused, match="plan_missing"):
        artifact.settle(token, "allowed")
    settlement = artifact.finalize("deny", "duplicate_terminal")
    assert [row["kind"] for row in _rows(root / network_trace.ARTIFACT_NAME)] == [
        "header", "plan", "terminal", "fatal", "seal",
    ]
    assert settlement["fatal"] == "network_trace_terminal_unmatched"
    artifact.close()


def test_crash_replay_exposes_open_plan_without_inventing_terminal(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.plan("broker.browser", "connect", {"peer": "192.0.2.2"})
    artifact.close()  # Model process death: no finalizer gets to manufacture truth.
    settlement = _replay(directory_fd)
    assert settlement["rows"] == 2
    assert settlement["open_plans"] == 1
    assert settlement["fatal"] is None
    assert settlement["complete"] is False


def test_abort_open_writes_one_terminal_for_each_plan(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    for component, operation in (
        ("broker.standard", "connect"),
        ("proxy", "peer_connect"),
        ("cdp", "controller_connection"),
    ):
        artifact.plan(component, operation)
    artifact.abort_open(code="external_cancellation")
    settlement = artifact.finalize("allow", "complete")
    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert sum(row["kind"] == "plan" for row in rows) == 3
    assert sum(row["kind"] == "terminal" for row in rows) == 3
    assert {row.get("outcome") for row in rows if row["kind"] == "terminal"} == {
        "cancelled",
    }
    assert settlement["complete"] is True
    artifact.close()


def test_finalize_is_one_locked_idempotent_transition(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    barrier = threading.Barrier(8)
    results = []

    def finalize():
        barrier.wait()
        results.append(artifact.finalize("allow", "complete"))

    threads = [threading.Thread(target=finalize) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 8 and all(value == results[0] for value in results)
    results[0]["fatal"] = "caller_mutation"
    assert artifact.finalize("allow", "complete")["fatal"] is None
    with pytest.raises(
        network_trace.NetworkTraceRefused, match="finalization_conflict",
    ):
        artifact.finalize("deny", "conflict")
    with pytest.raises(network_trace.NetworkTraceRefused, match="sealed"):
        artifact.plan("proxy", "peer_connect")
    artifact.close()


def test_read_back_requires_exact_compact_settlement_parity(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    settlement = artifact.finalize("allow", "complete")
    artifact.close()
    assert _replay(directory_fd, expected_settlement=settlement) == settlement
    changed = json.loads(json.dumps(settlement))
    changed["rows"] += 1
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError,
        match="settlement_parity",
    ):
        _replay(directory_fd, expected_settlement=changed)


@pytest.mark.parametrize(
    ("field", "value"),
    (("complete", 1), ("rows", True), ("bytes", 1.0)),
)
def test_expected_settlement_refuses_python_numeric_type_confusion(
        trace_directory, field, value):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    settlement = artifact.finalize("allow", "complete")
    artifact.close()
    confused = json.loads(json.dumps(settlement))
    confused[field] = value
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError, match="settlement_parity",
    ):
        _replay(directory_fd, expected_settlement=confused)


def test_expected_settlement_refuses_deep_or_huge_values_before_serialization(
        trace_directory):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    settlement = artifact.finalize("allow", "complete")
    artifact.close()
    deep = []
    for _ in range(1000):
        deep = [deep]
    hostile = dict(settlement)
    hostile["components"] = deep
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError, match="settlement_parity",
    ):
        _replay(directory_fd, expected_settlement=hostile)
    huge = dict(settlement)
    huge["reason"] = "x" * (network_trace.NETWORK_TRACE_MAX_SETTLEMENT_BYTES * 4)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError, match="settlement_parity",
    ):
        _replay(directory_fd, expected_settlement=huge)


def test_append_path_is_streaming_and_never_rereads_prior_rows(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd, max_rows=1024, max_bytes=1024 * 1024)
    real_pread = network_trace.os.pread
    monkeypatch.setattr(
        network_trace.os, "pread",
        lambda *_args, **_kwargs: pytest.fail("append path reread prior bytes"),
    )
    for index in range(200):
        token = artifact.plan("native.http", "request", {"index": index})
        artifact.settle(token, "denied", {"index": index})
    monkeypatch.setattr(network_trace.os, "pread", real_pread)
    assert artifact.finalize("allow", "complete")["rows"] == 402
    artifact.close()


@pytest.mark.parametrize(
    "failure", ["open", "preallocate", "file_fsync", "parent_fsync"],
)
def test_construction_faults_leave_no_usable_artifact(
        trace_directory, monkeypatch, failure):
    root, directory_fd = trace_directory
    real_open = network_trace.os.open
    real_fsync = network_trace.os.fsync

    if failure == "open":
        def fail_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == network_trace.ARTIFACT_NAME:
                raise OSError("fixture open fault")
            return real_open(path, flags, mode, dir_fd=dir_fd)
        monkeypatch.setattr(network_trace.os, "open", fail_open)
    elif failure == "preallocate":
        monkeypatch.setattr(
            network_trace, "_preallocate_keep_size",
            lambda *_args: (_ for _ in ()).throw(OSError("fixture allocation fault")),
        )
    elif failure == "file_fsync":
        def fail_file_fsync(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("fixture file fsync fault")
            return real_fsync(descriptor)
        monkeypatch.setattr(network_trace.os, "fsync", fail_file_fsync)
    else:
        def fail_parent_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("fixture parent fsync fault")
            return real_fsync(descriptor)
        monkeypatch.setattr(network_trace.os, "fsync", fail_parent_fsync)

    with pytest.raises(OSError):
        _create(directory_fd)
    assert not (root / network_trace.ARTIFACT_NAME).exists()


def test_preallocation_fault_cancels_shared_fence_before_create_returns(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    monkeypatch.setattr(
        network_trace, "_preallocate_keep_size",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture allocation fault")),
    )
    with pytest.raises(OSError):
        _create(directory_fd, effect_fence=fence)
    assert fence.is_set()


@pytest.mark.parametrize("fault", ["header_write", "preallocation"])
def test_construction_close_fault_cannot_skip_effect_fence_drain(
        trace_directory, monkeypatch, fault):
    root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    real_close = network_trace.os.close
    real_pwrite = network_trace.os.pwrite
    if fault == "header_write":
        monkeypatch.setattr(
            network_trace.os, "pwrite",
            lambda *_args: (_ for _ in ()).throw(OSError("header write fault")),
        )
    else:
        monkeypatch.setattr(
            network_trace, "_preallocate_keep_size",
            lambda *_args: (_ for _ in ()).throw(OSError("allocation fault")),
        )

    def close_then_fault(descriptor):
        real_close(descriptor)
        raise OSError("close fault after close")

    monkeypatch.setattr(network_trace.os, "close", close_then_fault)
    expected = (
        network_trace.NetworkTraceIntegrityError
        if fault == "header_write" else OSError
    )
    pattern = (
        "durable_append_failed" if fault == "header_write" else "allocation fault"
    )
    try:
        with pytest.raises(expected, match=pattern):
            network_trace.NetworkTraceArtifact.create(
                directory_fd, _INVOCATION_ID, _ARTIFACT_RELPATH,
                effect_fence=fence, **_LIMITS,
            )
    finally:
        monkeypatch.setattr(network_trace.os, "close", real_close)
        monkeypatch.setattr(network_trace.os, "pwrite", real_pwrite)
    assert fence.is_set()
    assert not (root / network_trace.ARTIFACT_NAME).exists()


@pytest.mark.parametrize("fault", ["write", "fsync", "partial_write"])
def test_plan_append_fault_cancels_before_effect(
        trace_directory, monkeypatch, fault):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    real_pwrite = network_trace.os.pwrite
    real_fsync = network_trace.os.fsync
    effects = []

    if fault == "write":
        monkeypatch.setattr(
            network_trace.os, "pwrite",
            lambda *_args: (_ for _ in ()).throw(OSError("fixture write fault")),
        )
    elif fault == "fsync":
        monkeypatch.setattr(
            network_trace.os, "fsync",
            lambda descriptor: (
                (_ for _ in ()).throw(OSError("fixture fsync fault"))
                if stat.S_ISREG(os.fstat(descriptor).st_mode)
                else real_fsync(descriptor)
            ),
        )
    else:
        state = {"called": False}

        def partial(descriptor, body, offset):
            if not state["called"]:
                state["called"] = True
                return real_pwrite(descriptor, body[: max(1, len(body) // 2)], offset)
            raise OSError("fixture torn write")

        monkeypatch.setattr(network_trace.os, "pwrite", partial)

    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        artifact.plan("native.http", "request")
        effects.append("contact")
    assert effects == []
    assert artifact.cancellation_event.is_set()
    artifact.close()


def test_terminal_write_fault_cancels_and_replay_never_claims_complete(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    token = artifact.plan("proxy", "peer_connect")
    real_pwrite = network_trace.os.pwrite
    monkeypatch.setattr(
        network_trace.os, "pwrite",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture terminal fault")),
    )
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        artifact.settle(token, "allowed")
    assert artifact.cancellation_event.is_set()
    monkeypatch.setattr(network_trace.os, "pwrite", real_pwrite)
    artifact.close()
    assert _replay(directory_fd)["complete"] is False


def test_seal_fsync_fault_cannot_launder_visible_allow_as_certified_complete(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    real_fsync = network_trace.os.fsync
    calls = {"value": 0}

    def sync_then_fault(descriptor):
        calls["value"] += 1
        real_fsync(descriptor)
        if calls["value"] == 2:
            raise OSError("post-sync fixture fault")

    monkeypatch.setattr(network_trace.os, "fsync", sync_then_fault)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError, match="seal_commit_failed",
    ):
        artifact.finalize("allow", "complete")
    monkeypatch.setattr(network_trace.os, "fsync", real_fsync)
    artifact.close()
    reopened = _replay(directory_fd)
    assert reopened["decision"] == "allow"
    assert reopened["certified"] is False
    assert reopened["complete"] is False
    assert all(
        value["complete"] is False
        for value in reopened["components"].values()
    )


def test_finalize_has_no_fallible_operation_after_durable_allow_commit(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    real_ftruncate = network_trace.os.ftruncate
    real_pwrite = network_trace.os.pwrite
    calls = []

    def ftruncate(descriptor, length):
        calls.append("truncate")
        return real_ftruncate(descriptor, length)

    def pwrite(descriptor, body, offset):
        if b'"kind":"seal"' in body:
            calls.append("seal")
        return real_pwrite(descriptor, body, offset)

    monkeypatch.setattr(network_trace.os, "ftruncate", ftruncate)
    monkeypatch.setattr(network_trace.os, "pwrite", pwrite)
    settlement = artifact.finalize("allow", "complete")
    assert settlement["certified"] is True
    assert settlement["complete"] is True
    assert calls[-1] == "seal"
    assert calls.count("seal") == 1
    artifact.close()


@pytest.mark.parametrize("fault", ["release", "release_fsync"])
def test_precommit_release_fault_writes_no_seal_and_cancels(
        trace_directory, monkeypatch, fault):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    real_fsync = network_trace.os.fsync
    if fault == "release":
        monkeypatch.setattr(
            network_trace, "_release_preallocation_tail",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("fixture release fault"),
            ),
        )
    else:
        monkeypatch.setattr(
            network_trace.os, "fsync",
            lambda *_args: (_ for _ in ()).throw(
                OSError("fixture release fsync fault"),
            ),
        )
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError,
        match="precommit_release_failed",
    ):
        artifact.finalize("allow", "complete")
    monkeypatch.setattr(network_trace.os, "fsync", real_fsync)
    artifact.close()
    reopened = _replay(directory_fd)
    assert reopened["decision"] is None
    assert reopened["certified"] is False
    assert reopened["complete"] is False


@pytest.mark.parametrize("fault", ["after_truncate", "after_reallocate"])
def test_mid_release_fault_preserves_canonical_unsealed_prefix(
        trace_directory, monkeypatch, fault):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    real_truncate = network_trace._truncate_retry
    real_fallocate = network_trace._fallocate
    if fault == "after_truncate":
        def truncate_then_fault(descriptor, length):
            real_truncate(descriptor, length)
            raise OSError("fixture post-truncate fault")
        monkeypatch.setattr(
            network_trace, "_truncate_retry", truncate_then_fault,
        )
    else:
        def reallocate_then_fault(descriptor, flags, offset, length):
            real_fallocate(descriptor, flags, offset, length)
            raise OSError("fixture post-reallocation fault")
        monkeypatch.setattr(network_trace, "_fallocate", reallocate_then_fault)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError,
        match="precommit_release_failed",
    ):
        artifact.finalize("allow", "complete")
    monkeypatch.setattr(network_trace, "_truncate_retry", real_truncate)
    monkeypatch.setattr(network_trace, "_fallocate", real_fallocate)
    artifact.close()
    reopened = _replay(directory_fd)
    assert reopened["decision"] is None
    assert reopened["rows"] == 3
    assert reopened["certified"] is False
    assert reopened["complete"] is False


def test_same_size_truncate_releases_tail_and_reserves_only_seal_range(
        trace_directory, monkeypatch):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    path = root / network_trace.ARTIFACT_NAME
    before_blocks = path.stat().st_blocks * 512
    before_size = path.stat().st_size
    real_fallocate = network_trace._fallocate
    calls = []

    def fallocate(descriptor, flags, offset, length):
        calls.append((flags, offset, length))
        return real_fallocate(descriptor, flags, offset, length)

    monkeypatch.setattr(network_trace, "_fallocate", fallocate)
    settlement = artifact.finalize("allow", "complete")
    granularity = os.fstatvfs(directory_fd).f_frsize
    assert calls == [(
        network_trace._FALLOC_FL_KEEP_SIZE,
        before_size, settlement["bytes"] - before_size,
    )]
    after_blocks = path.stat().st_blocks * 512
    assert after_blocks < before_blocks
    assert after_blocks <= (
        (settlement["bytes"] + granularity - 1) // granularity * granularity
        + granularity
    )
    artifact.close()


def test_tail_release_handles_non_aligned_envelope_and_zero_length_range(
        trace_directory, monkeypatch):
    root, directory_fd = trace_directory
    envelope = 256 * 1024 + 123
    artifact = _create(directory_fd, max_bytes=envelope)
    real_fallocate = network_trace._fallocate
    calls = []

    def fallocate(descriptor, flags, offset, length):
        calls.append((flags, offset, length))
        return real_fallocate(descriptor, flags, offset, length)

    monkeypatch.setattr(network_trace, "_fallocate", fallocate)
    settlement = artifact.finalize("allow", "complete")
    assert len(calls) == 1
    _flags, offset, length = calls[0]
    assert _flags == network_trace._FALLOC_FL_KEEP_SIZE
    assert offset + length == settlement["bytes"] <= envelope
    assert settlement["complete"] is True
    artifact.close()

    # Exercise the exact no-op arithmetic without allocating another artifact.
    scratch = root / "scratch"
    scratch.write_bytes(b"x" * 2500)
    descriptor = os.open(scratch, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fake = type("VFS", (), {"f_frsize": 4096})()
        monkeypatch.setattr(network_trace.os, "fstatvfs", lambda _fd: fake)
        monkeypatch.setattr(
            network_trace, "_fallocate",
            lambda *_args: pytest.fail("zero-length range called fallocate"),
        )
        assert network_trace._release_preallocation_tail(
            descriptor, current_eof=2500, future_eof=2500,
            envelope_bytes=3500,
        ) == (2500, 0)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda body: body[:-1],
        lambda body: body + b"garbage",
        lambda body: body + body.splitlines(keepends=True)[-1],
        lambda body: body.replace(b'"kind":"plan"', b'"kind": "plan"', 1),
        lambda body: b"".join(reversed(body.splitlines(keepends=True))),
        lambda body: body.replace(b'"sequence":1', b'"sequence":7', 1),
        lambda body: body.replace(b'"component":"broker.standard"',
                                  b'"component":"unknown"', 1),
    ],
    ids=("torn", "extra", "duplicate", "noncanonical", "reorder",
         "sequence-gap", "unknown-component"),
)
def test_replay_rejects_tampered_bytes(trace_directory, mutate):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    path.write_bytes(mutate(path.read_bytes()))
    path.chmod(0o600)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)


def test_replay_rejects_duplicate_json_member(trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    body = path.read_bytes().replace(
        b'{"component":', b'{"component":"proxy","component":', 1,
    )
    path.write_bytes(body)
    path.chmod(0o600)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError, match="member_duplicate",
    ):
        _replay(directory_fd)


def test_replay_rejects_mode_and_hardlink_alias(trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    path.chmod(0o644)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)
    path.chmod(0o600)
    os.link(path, root / "alias")
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)


def test_replay_opens_nonblocking_and_rejects_nonregular_replacement(
        trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    path.unlink()
    os.mkfifo(path, 0o600)
    with pytest.raises(network_trace.NetworkTraceIntegrityError, match="identity"):
        _replay(directory_fd)


def test_live_writer_rejects_named_inode_swap(trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    path = root / network_trace.ARTIFACT_NAME
    replacement = root / "replacement"
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, path)
    with pytest.raises(network_trace.NetworkTraceIntegrityError, match="identity"):
        artifact.finalize("allow", "complete")
    assert artifact.cancellation_event.is_set()
    artifact.close()


def test_live_writer_rejects_same_length_content_tamper(trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    path = root / network_trace.ARTIFACT_NAME
    body = path.read_bytes()
    changed = body.replace(b"example.test", b"changed.test", 1)
    assert len(changed) == len(body) and changed != body
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        assert os.pwrite(descriptor, changed, 0) == len(changed)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    with pytest.raises(network_trace.NetworkTraceError):
        artifact.finalize("allow", "complete")
    artifact.close()


def test_live_writer_detects_swap_and_restore_aba_via_parent_ctime(
        trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    path = root / network_trace.ARTIFACT_NAME
    held = root / "held"
    replacement = root / "replacement"
    discarded = root / "discarded"
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    os.replace(path, held)
    os.replace(replacement, path)
    os.replace(path, discarded)
    os.replace(held, path)
    with pytest.raises(network_trace.NetworkTraceIntegrityError, match="identity"):
        artifact.finalize("allow", "complete")
    artifact.close()


def test_replay_rejects_symlink_replacement_without_following_it(trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    target = root / "target"
    target.write_bytes(path.read_bytes())
    target.chmod(0o600)
    path.unlink()
    path.symlink_to(target.name)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)


def test_replay_rejects_truncate_after_clean_settlement(trace_directory):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    settlement = artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    path.chmod(0o600)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd, expected_settlement=settlement)


@pytest.mark.parametrize("mutation", ["reservation", "stage", "outcome"])
def test_replay_enforces_typed_vocabulary_and_durable_reservation(
        trace_directory, mutation):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    token = artifact.plan(
        "broker.standard", "connect", reserve_rows=2,
    )
    artifact.event(token, "admitted")
    artifact.settle(token, "allowed")
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    rows = _rows(path)
    if mutation == "reservation":
        rows[1]["reservation"]["rows"] = 1
    elif mutation == "stage":
        rows[2]["stage"] = "unknown_stage"
    else:
        rows[3]["outcome"] = "unknown_outcome"
    path.write_bytes(_rechain(rows))
    path.chmod(0o600)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)


@pytest.mark.parametrize("mutation", ("operation", "outcome", "plan_id"))
def test_replay_enforces_exact_observation_schema(
        trace_directory, mutation):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.observe("broker.standard", "notification", "denied")
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    rows = _rows(path)
    if mutation == "operation":
        rows[1]["operation"] = "unknown"
    elif mutation == "outcome":
        rows[1]["outcome"] = "unknown"
    else:
        rows[1]["plan_id"] = "0000000000000001"
    path.write_bytes(_rechain(rows))
    path.chmod(0o600)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)


def test_replay_rejects_observation_after_durable_fatal(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    with pytest.raises(network_trace.NetworkTraceRefused):
        artifact.plan("broker.standard", "unknown")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    rows = _rows(path)
    rows.append({
        "schema": network_trace.ROW_SCHEMA,
        "sequence": 0,
        "kind": "observation",
        "previous_sha256": "",
        "component": "broker.standard",
        "operation": "notification",
        "outcome": "denied",
        "data": {"syscall": 999},
    })
    path.write_bytes(_rechain(rows))
    path.chmod(0o600)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError,
        match="network_trace_observation_invalid",
    ):
        _replay(directory_fd)


def test_replay_rejects_canonical_prefix_reservation_overcommit(
        trace_directory):
    root, directory_fd = trace_directory
    limits = {"max_rows": 8, "max_bytes": 8192, "max_row_bytes": 1024}
    artifact = _create(directory_fd, **limits)
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    header = _rows(path)[0]
    rows = [
        header,
        {
            "schema": network_trace.ROW_SCHEMA,
            "sequence": 1,
            "kind": "plan",
            "previous_sha256": "",
            "component": "broker.standard",
            "operation": "connect",
            "plan_id": "0000000000000001",
            "data": {},
            "reservation": {"row_bytes": 1024, "rows": 4},
        },
        {
            "schema": network_trace.ROW_SCHEMA,
            "sequence": 2,
            "kind": "plan",
            "previous_sha256": "",
            "component": "proxy",
            "operation": "peer_connect",
            "plan_id": "0000000000000002",
            "data": {},
            "reservation": {"row_bytes": 1024, "rows": 1},
        },
    ]
    path.write_bytes(_rechain(rows))
    path.chmod(0o600)
    with pytest.raises(
        network_trace.NetworkTraceIntegrityError,
        match="reservation_overcommitted",
    ):
        _replay(directory_fd, **limits)


@pytest.mark.parametrize(
    "mutation",
    ("header_bool", "kind_list", "component_list", "decision_list"),
)
def test_hostile_canonical_types_are_integrity_errors_not_python_exceptions(
        trace_directory, mutation):
    root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    artifact.finalize("allow", "complete")
    artifact.close()
    path = root / network_trace.ARTIFACT_NAME
    rows = _rows(path)
    if mutation == "header_bool":
        rows[0]["preallocation"]["bytes"] = True
    elif mutation == "kind_list":
        rows[1]["kind"] = ["plan"]
    elif mutation == "component_list":
        rows[1]["component"] = ["broker.standard"]
    else:
        rows[-1]["decision"] = ["allow"]
    path.write_bytes(_rechain(rows))
    path.chmod(0o600)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        _replay(directory_fd)


def test_allow_refuses_open_plan_but_deny_seals_it_incomplete(trace_directory):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    artifact.plan("broker.controller", "connect")
    with pytest.raises(
        network_trace.NetworkTraceRefused, match="allow_incomplete",
    ):
        artifact.finalize("allow", "complete")
    settlement = artifact.finalize("deny", "open_plan")
    assert settlement["decision"] == "deny"
    assert settlement["open_plans"] == 1
    assert settlement["fatal"] == "network_trace_allow_incomplete"
    assert settlement["complete"] is False
    assert all(
        component["complete"] is False
        for component in settlement["components"].values()
    )
    artifact.close()


def test_mocked_wrong_owner_is_refused_while_live(
        trace_directory, monkeypatch):
    _root, directory_fd = trace_directory
    artifact = _one_pair(directory_fd)
    real_fstat = network_trace.os.fstat

    def wrong_owner(descriptor):
        value = real_fstat(descriptor)
        if stat.S_ISREG(value.st_mode):
            fields = list(value)
            fields[4] = value.st_uid + 1
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(network_trace.os, "fstat", wrong_owner)
    with pytest.raises(network_trace.NetworkTraceIntegrityError):
        artifact.finalize("allow", "complete")
    artifact.close()


@pytest.mark.parametrize(
    "data",
    [
        {"integer": 1 << 60},
        {"nested": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}},
        {"bad-key": "value"},
        {"float": 1.5},
    ],
    ids=("integer", "depth", "key", "float"),
)
def test_plan_rejects_unbounded_or_ambiguous_json_before_effect(
        trace_directory, data):
    _root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    effects = []
    with pytest.raises(network_trace.NetworkTraceRefused):
        artifact.plan("native.http", "request", data)
        effects.append("contact")
    assert effects == []
    assert artifact.cancellation_event.is_set()
    artifact.close()


@pytest.mark.parametrize(
    "data",
    (
        {"values": [""] * (_LIMITS["max_row_bytes"] + 1)},
        {"value": "x" * (_LIMITS["max_row_bytes"] * 1024)},
    ),
    ids=("wide-list", "huge-string"),
)
def test_payload_width_is_refused_before_json_serialization(
        trace_directory, monkeypatch, data):
    root, directory_fd = trace_directory
    fence = NetworkEffectFence()
    artifact = _create(directory_fd, effect_fence=fence)
    real_dumps = network_trace.json.dumps

    def guarded_dumps(value, *args, **kwargs):
        if type(value) is dict and value.get("kind") == "plan":
            pytest.fail("oversized plan reached json.dumps")
        return real_dumps(value, *args, **kwargs)

    monkeypatch.setattr(network_trace.json, "dumps", guarded_dumps)
    with pytest.raises(network_trace.NetworkTraceRefused, match="row_oversize"):
        artifact.plan("native.http", "request", data)
    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert [row["kind"] for row in rows] == ["header", "fatal"]
    assert rows[1]["code"] == "network_trace_plan_invalid"
    assert fence.is_set()
    artifact.close()


def test_plan_serializes_a_bounded_snapshot_not_mutable_caller_data(
        trace_directory, monkeypatch):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    data = {"value": "stable"}
    real_dumps = network_trace.json.dumps

    def mutate_before_dumps(value, *args, **kwargs):
        if type(value) is dict and value.get("kind") == "plan":
            assert value["data"] is not data
            data["value"] = "x" * (1024 * 1024)
        return real_dumps(value, *args, **kwargs)

    monkeypatch.setattr(network_trace.json, "dumps", mutate_before_dumps)
    token = artifact.plan("native.http", "request", data)
    artifact.settle(token, "allowed")
    assert _rows(root / network_trace.ARTIFACT_NAME)[1]["data"] == {
        "value": "stable",
    }
    artifact.close()


def test_oversize_plan_records_fatal_before_effect(trace_directory):
    root, directory_fd = trace_directory
    artifact = _create(directory_fd)
    with pytest.raises(network_trace.NetworkTraceRefused, match="row_oversize"):
        artifact.plan("native.http", "request", {"value": "x" * 1000})
    rows = _rows(root / network_trace.ARTIFACT_NAME)
    assert [row["kind"] for row in rows] == ["header", "fatal"]
    assert rows[1]["code"] == "network_trace_plan_invalid"
    artifact.close()
