"""Phase 1: fixed stdout names never make preserved finals current again."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import cloud, store
from quarry_recon.phases import horizontal, vertical
from quarry_recon.runner import RunResult, Status


pytestmark = pytest.mark.offline


class _Scope:
    passive_only = False

    @staticmethod
    def in_scope(_host: str) -> bool:
        return True

    @staticmethod
    def is_oos(_host: str) -> bool:
        return False


def _write_list(run: store.Run, name: str, values) -> Path:
    path = run.dir / "work" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(map(str, values)) + "\n", encoding="utf-8")
    return path


def test_mapcidr_unpublished_attempt_never_feeds_preserved_ips_to_consumers(
    tmp_path, monkeypatch,
):
    run = store.Run.create(tmp_path, "acme.example", run_id="mapcidr-current")
    run.write_state("running")
    prior = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "horizontal", "mapcidr", "ips.txt"),
        b"198.51.100.77\n",
    )
    consumed: list[tuple[str, Path]] = []

    def execute(tool, cmd, **_kwargs):
        if tool == "mapcidr":
            # This is the repository runner's fenced-publication shape: the
            # process was useful enough to classify PARTIAL, but no current
            # stdout final was authenticated and the prior final remains.
            return RunResult(
                tool, cmd, Status.PARTIAL, 0, 0.1, None, 1,
                note="repository publication fenced",
                meta={"repository_publication": "fenced"},
            )
        if tool in {"tlsx", "dnsx"}:
            consumed.append((tool, Path(cmd[cmd.index("-l") + 1])))
        return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0)

    monkeypatch.setattr(horizontal, "_kaeferjaeger", lambda _ctx: 0)
    monkeypatch.setattr(horizontal.netguard, "guard_hosts", lambda *_a, **_kw: [])
    monkeypatch.setattr(cloud, "discover", lambda _ctx: 0)
    monkeypatch.setattr(horizontal, "have", lambda _tool: False)
    monkeypatch.setattr(horizontal, "exec_tool", execute)
    ctx = SimpleNamespace(
        run=run,
        scope=_Scope(),
        profile=SimpleNamespace(
            apex_domains=["acme.example"], cidr=["192.0.2.0/30"], asn=[],
        ),
        write_list=lambda name, values: _write_list(run, name, values),
        echo=lambda _message: None,
        http_timeout=3,
    )

    horizontal.run(ctx)

    cidr_file = run.dir / "work" / "cidr.txt"
    assert consumed == [("tlsx", cidr_file), ("dnsx", cidr_file)]
    assert prior.read_bytes() == b"198.51.100.77\n"


def test_alterx_unpublished_attempt_never_ingests_preserved_permutations(
    tmp_path, monkeypatch,
):
    run = store.Run.create(tmp_path, "acme.example", run_id="alterx-current")
    run.write_state("running")
    prior = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "vertical", "alterx", "perms_1.txt"),
        b"stale.acme.example\n",
    )
    submitted: list[list[str]] = []

    def execute(tool, cmd, **_kwargs):
        if tool == "alterx":
            return RunResult(
                tool, cmd, Status.PARTIAL, 0, 0.1, None, 1,
                note="repository publication fenced",
                meta={"repository_publication": "fenced"},
            )
        assert tool == "puredns"
        submitted.append(Path(cmd[2]).read_text(encoding="utf-8").splitlines())
        return RunResult(tool, cmd, Status.EMPTY, 0, 0.1, None, 0)

    monkeypatch.setattr(vertical, "have", lambda _tool: True)
    monkeypatch.setattr(vertical, "exec_tool", execute)
    monkeypatch.setattr(vertical.policy, "limit", lambda name: 1 if name == "MAX_ITERS" else 0)
    monkeypatch.setattr(vertical.remainder, "emit", lambda _row: None)
    ctx = SimpleNamespace(
        run=run,
        scope=_Scope(),
        write_list=lambda name, values: _write_list(run, name, values),
        echo=lambda _message: None,
        http_timeout=3,
    )
    profile = SimpleNamespace(
        apex_domains=["acme.example"], dns_rate=0, http_rl=0, takeover=False,
    )

    vertical._recursive_permute(
        ctx, profile, ctx.scope, tmp_path / "trusted.txt", None, set(),
    )

    assert submitted == [["acme.example"]]
    assert prior.read_bytes() == b"stale.acme.example\n"
