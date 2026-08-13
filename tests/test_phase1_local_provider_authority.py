"""Phase 1: in-process provider evidence shares the repository seal authority."""
from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import cloud, privfs, store
from quarry_recon.phases import _local_raw, horizontal, vertical
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


class _Scope:
    passive_only = False

    @staticmethod
    def in_scope(host: str) -> bool:
        return host == "acme.example" or host.endswith(".acme.example")

    @staticmethod
    def is_oos(_host: str) -> bool:
        return False


def _running_run(project, run_id: str) -> store.Run:
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _ctx(run: store.Run):
    return SimpleNamespace(
        run=run,
        scope=_Scope(),
        profile=SimpleNamespace(apex_domains=["acme.example"], cidr=[]),
        echo=lambda _message: None,
        http_timeout=3,
    )


def _start(call):
    values, failures = [], []

    def invoke():
        try:
            values.append(call())
        except BaseException as exc:  # assertions inspect cancellation identity too
            failures.append(exc)

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    return thread, values, failures


def _join(thread, failures) -> None:
    thread.join(timeout=5)
    assert not thread.is_alive(), "provider fixture did not settle"
    assert not failures, failures


def _refs(record: dict) -> set[str]:
    refs = set(record.get("raw_refs") or ())
    if record.get("raw_ref"):
        refs.add(record["raw_ref"])
    return refs


def test_kaeferjaeger_claim_precedes_local_scan_and_spans_publish_entities_and_record(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, "local-kj-race")
    ctx = _ctx(run)
    dataset = tmp_path / "kaeferjaeger"
    dataset.mkdir()
    (dataset / "cloud_sni.txt").write_text("ignored input\n", encoding="utf-8")
    monkeypatch.setattr(horizontal, "_kaeferjaeger_dir", lambda: dataset)

    entered, release = threading.Event(), threading.Event()

    class BlockingMatcher:
        @staticmethod
        def findall(_line):
            entered.set()
            assert release.wait(5), "seal-race fixture was not released"
            return ["sni.acme.example"]

    monkeypatch.setattr(horizontal, "_KJ_HOST_RX", BlockingMatcher())
    thread, values, failures = _start(lambda: horizontal._kaeferjaeger(ctx))
    assert entered.wait(3), "local dataset scan was not reached"

    final = run.dir / "raw" / "horizontal" / "kaeferjaeger" / "matches.txt"
    assert not final.exists(), "a private stage became authoritative before publication"
    assert run._live_artifact_claim_count() >= 1
    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="live artifact claim"):
        sealer.begin_finalization()
    assert sealer.state == "running"

    release.set()
    _join(thread, failures)
    assert values == [1]
    assert final.read_text(encoding="utf-8") == "sni.acme.example\tcloud_sni.txt:1\n"
    [row] = [r for r in run.read("subdomain") if r["host"] == "sni.acme.example"]
    assert _refs(row) == {str(final)}
    [result] = [r for r in run.tool_runs("horizontal") if r.tool == "kaeferjaeger"]
    assert result.status == "success"
    assert run._live_artifact_claim_count() == 0
    sealer.begin_finalization()
    assert sealer.state == "finalizing"


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_kaeferjaeger_publication_fault_fences_stage_preserves_prior_and_releases_claim(
    tmp_path, monkeypatch, failure_type,
):
    run = _running_run(tmp_path, f"local-kj-{failure_type.__name__.lower()}")
    ctx = _ctx(run)
    dataset = tmp_path / f"dataset-{failure_type.__name__}"
    dataset.mkdir()
    (dataset / "cloud_sni.txt").write_text("new.acme.example\n", encoding="utf-8")
    monkeypatch.setattr(horizontal, "_kaeferjaeger_dir", lambda: dataset)

    final = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "horizontal", "kaeferjaeger", "matches.txt"),
        b"prior.acme.example\tprior.txt:1\n",
    )
    failure = failure_type("publication cancelled")

    def fail_publish(_stage):
        raise failure

    with monkeypatch.context() as publication_fault:
        publication_fault.setattr(privfs, "replace_private_stage", fail_publish)
        with pytest.raises(failure_type) as caught:
            horizontal._kaeferjaeger(ctx)

    assert caught.value is failure
    assert final.read_bytes() == b"prior.acme.example\tprior.txt:1\n"
    assert "new.acme.example" not in run.values("subdomain")
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))
    store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()


def test_csp_claim_precedes_resolution_and_publishes_before_raw_ref(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "local-csp-race")
    ctx = _ctx(run)
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(horizontal, "_kaeferjaeger", lambda _ctx: 0)

    def guard(_ctx, hosts, *, phase):
        assert hosts == ["acme.example"] and phase == "horizontal.csp"
        entered.set()
        assert release.wait(5), "seal-race fixture was not released"
        return hosts

    def scoped_headers(_ctx, url, *, insecure):
        assert insecure is True
        return ({"Content-Security-Policy": "connect-src https://api.acme.example"},
                b"", url, 200)

    monkeypatch.setattr(horizontal.netguard, "guard_hosts", guard)
    monkeypatch.setattr(horizontal.fetch, "scoped_headers", scoped_headers)
    monkeypatch.setattr(cloud, "discover", lambda _ctx: 0)
    thread, values, failures = _start(lambda: horizontal.run(ctx))
    assert entered.wait(3), "fresh resolution was not reached"

    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="live artifact claim"):
        sealer.begin_finalization()
    assert sealer.state == "running"
    release.set()
    _join(thread, failures)
    assert values == [None]

    final = run.dir / "raw" / "horizontal" / "csp" / "csp.txt"
    assert "api.acme.example" in final.read_text(encoding="utf-8")
    [row] = [r for r in run.read("subdomain") if r["host"] == "api.acme.example"]
    assert _refs(row) == {str(final)}
    [result] = [r for r in run.tool_runs("horizontal") if r.tool == "csp"]
    assert result.status == "success"
    assert run._live_artifact_claim_count() == 0
    sealer.begin_finalization()


def test_csp_publication_failure_keeps_prior_and_emits_no_new_entity(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "local-csp-fault")
    ctx = _ctx(run)
    monkeypatch.setattr(horizontal, "_kaeferjaeger", lambda _ctx: 0)
    monkeypatch.setattr(horizontal.netguard, "guard_hosts", lambda *_args, **_kwargs: ["acme.example"])
    monkeypatch.setattr(
        horizontal.fetch, "scoped_headers",
        lambda _ctx, url, **_kwargs: (
            {"Content-Security-Policy": "connect-src https://new.acme.example"}, b"", url, 200,
        ),
    )
    monkeypatch.setattr(cloud, "discover", lambda _ctx: 0)
    final = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "horizontal", "csp", "csp.txt"),
        b"prior CSP evidence\n",
    )

    failure = RuntimeError("durability fault")
    with monkeypatch.context() as publication_fault:
        publication_fault.setattr(
            privfs,
            "replace_private_stage",
            lambda _stage: (_ for _ in ()).throw(failure),
        )
        with pytest.raises(RuntimeError) as caught:
            horizontal.run(ctx)

    assert caught.value is failure
    assert final.read_bytes() == b"prior CSP evidence\n"
    assert "new.acme.example" not in run.values("subdomain")
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))
    store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()


def test_vertical_sources_hold_claim_across_contact_publication_and_entities(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "local-vertical-race")
    ctx = _ctx(run)
    entered, release = threading.Event(), threading.Event()

    monkeypatch.setattr(vertical, "run_provider", lambda _source, call, **_kwargs: call())
    monkeypatch.setattr(vertical.secrets, "certspotter", lambda: "certspotter-token")
    monkeypatch.setattr(vertical.settings, "concurrency", lambda _name, _default: 5)
    monkeypatch.setattr(
        vertical.settings, "openintel", lambda: {"binary": "/opt/openintel", "db": "/data/subs"},
    )
    monkeypatch.setattr(vertical.secrets, "censys", lambda: {"token": "censys-token", "org": "org-1"})
    monkeypatch.setattr(vertical, "censys_entitlement_skip", lambda _cfg, _roots: False)

    def crtsh(_apex):
        entered.set()
        assert release.wait(5), "seal-race fixture was not released"
        return {"ct.acme.example", "*.wildct.acme.example"}

    monkeypatch.setattr(vertical, "_crtsh", crtsh)
    monkeypatch.setattr(vertical, "_certspotter", lambda *_args, **_kwargs: {"cert.acme.example"})
    monkeypatch.setattr(vertical, "_openintel", lambda *_args, **_kwargs: {"oi.acme.example"})
    monkeypatch.setattr(
        vertical, "_censys",
        lambda *_args, **_kwargs: {"cen.acme.example", "*.wildcen.acme.example"},
    )

    thread, values, failures = _start(
        lambda: vertical._local_provider_sources(ctx, ctx.profile, ctx.scope),
    )
    assert entered.wait(3), "CT provider contact was not reached"
    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="live artifact claim"):
        sealer.begin_finalization()
    assert sealer.state == "running"
    release.set()
    _join(thread, failures)
    assert values == [{"wildct.acme.example", "wildcen.acme.example"}]

    expectations = {
        "ct.acme.example": "crtsh",
        "wildct.acme.example": "crtsh",
        "cert.acme.example": "certspotter",
        "oi.acme.example": "openintel",
        "cen.acme.example": "censys",
        "wildcen.acme.example": "censys",
    }
    rows = {row["host"]: row for row in run.read("subdomain")}
    assert set(rows) == set(expectations)
    for host, source in expectations.items():
        final = run.dir / "raw" / "vertical" / source / "hosts.txt"
        assert final.is_file() and host in final.read_text(encoding="utf-8").replace("*.", "")
        assert _refs(rows[host]) == {str(final)}
    assert run._live_artifact_claim_count() == 0
    sealer.begin_finalization()


def test_vertical_publication_fault_preserves_prior_and_cannot_cite_it_as_current(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, "local-vertical-fault")
    ctx = _ctx(run)
    monkeypatch.setattr(vertical, "run_provider", lambda _source, call, **_kwargs: call())
    monkeypatch.setattr(vertical.secrets, "certspotter", lambda: None)
    monkeypatch.setattr(vertical.settings, "concurrency", lambda _name, _default: 5)
    monkeypatch.setattr(vertical, "_crtsh", lambda _apex: {"newct.acme.example"})
    monkeypatch.setattr(vertical, "_certspotter", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(vertical.settings, "openintel", lambda: {})
    monkeypatch.setattr(vertical.secrets, "censys", lambda: {})
    monkeypatch.setattr(vertical, "censys_entitlement_skip", lambda _cfg, _roots: False)
    final = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "vertical", "crtsh", "hosts.txt"),
        b"priorct.acme.example\n",
    )

    failure = RuntimeError("vertical publication fault")
    with monkeypatch.context() as publication_fault:
        publication_fault.setattr(
            privfs,
            "replace_private_stage",
            lambda _stage: (_ for _ in ()).throw(failure),
        )
        with pytest.raises(RuntimeError) as caught:
            vertical._local_provider_sources(ctx, ctx.profile, ctx.scope)

    assert caught.value is failure
    assert final.read_bytes() == b"priorct.acme.example\n"
    assert "newct.acme.example" not in run.values("subdomain")
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))
    store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()


def test_fake_compatibility_is_only_outside_real_run_authority(tmp_path):
    class FakeRun:
        def __init__(self, path: Path):
            self.path = path

        def raw_path(self, _phase, _tool, _name):
            return self.path

    outside = tmp_path / "compat-raw.txt"
    assert _local_raw.replace_text(FakeRun(outside), "x", "y", "z", "compat\n") == outside
    assert outside.read_text(encoding="utf-8") == "compat\n"

    run = _running_run(tmp_path / "project", "managed-fake-refusal")
    managed = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "horizontal", "fixture", "managed.txt"),
        b"repository-owned\n",
    )
    with pytest.raises(ContractError, match="exact repository Run authority"):
        _local_raw.replace_text(FakeRun(managed), "x", "y", "z", "ambient overwrite\n")
    assert managed.read_bytes() == b"repository-owned\n"
