"""QR39-002 — one validated run enumeration. `recon/campaigns/` (and other reserved/non-run dirs) must
never be mistaken for a run, so `latest`/`status`/`report`/`delta` keep working after a campaign settles."""
import os

import pytest

from quarry_recon import exports
from quarry_recon.store import RESERVED_RECON_DIRS, Run

pytestmark = pytest.mark.offline


def test_list_runs_excludes_reserved_symlinks_and_nonruns(tmp_path):
    r1, r2 = Run.create(tmp_path, "t"), Run.create(tmp_path, "t")
    recon = tmp_path / "recon"
    (recon / "campaigns").mkdir()             # reserved namespace
    (recon / "state").mkdir(exist_ok=True)    # reserved namespace
    (recon / "stray").mkdir()                 # a directory with no run identity
    os.symlink(r1.dir, recon / "linkrun")     # a symlink to a real run

    names = [d.name for d in Run.list_runs(tmp_path)]
    assert names == [r1.run_id, r2.run_id]      # chronological (r1 created first)
    assert not (set(names) & (RESERVED_RECON_DIRS | {"stray", "linkrun"}))


def test_latest_returns_real_run_after_campaign_settles(tmp_path):
    r = Run.create(tmp_path, "acme")
    r.write_manifest({}, [], metrics=None, policy=None)
    (tmp_path / "recon" / "campaigns").mkdir()

    latest = Run.latest(tmp_path)             # must not raise, and must not pick the campaign container
    assert latest is not None and latest.run_id == r.run_id and latest.target == "acme"


def test_latest_is_none_when_only_reserved_dirs_exist(tmp_path):
    (tmp_path / "recon" / "campaigns").mkdir(parents=True)
    (tmp_path / "recon" / "state").mkdir()
    assert Run.latest(tmp_path) is None


def test_write_delta_diffs_previous_run_not_campaign(tmp_path):
    r1 = Run.create(tmp_path, "t")
    r1.add("subdomain", {"host": "sub1.example.com"})
    exports.write_all(r1)
    r2 = Run.create(tmp_path, "t")
    r2.add("subdomain", {"host": "sub2.example.com"})
    (tmp_path / "recon" / "campaigns").mkdir()

    exports.write_all(r2)
    exports.write_delta(r2)
    delta = (r2.reports / "delta.md").read_text()
    assert f"vs previous run ({r1.run_id})" in delta      # diffed against the real prior run, not campaigns/
    assert "+ sub2.example.com" in delta


def _mk_run(recon, name, started, target="t"):
    import json
    d = recon / name
    d.mkdir(parents=True)
    (d / "run.json").write_text(json.dumps({"run_id": name, "target": target, "started": started}))
    return d


def test_list_runs_orders_by_started_not_name(tmp_path):
    recon = tmp_path / "recon"
    # a later-sorting NAME with an earlier `started`, and vice versa — name sort would reverse time
    _mk_run(recon, "20260101-000000-ffffffff", "2026-01-01T00:00:00.100000+00:00")   # earlier
    _mk_run(recon, "20260101-000000-00000000", "2026-01-01T00:00:00.900000+00:00")   # later
    names = [d.name for d in Run.list_runs(tmp_path)]
    assert names == ["20260101-000000-ffffffff", "20260101-000000-00000000"]         # chronological
    assert Run.latest(tmp_path).run_id == "20260101-000000-00000000"                  # newest by started


def test_list_runs_rejects_partial_or_mismatched_identity(tmp_path):
    import json
    recon = tmp_path / "recon"
    good = _mk_run(recon, "20260101-000000-aaaaaaaa", "2026-01-01T00:00:00.000000+00:00")
    (recon / "bogus").mkdir()
    (recon / "bogus" / "run.json").write_text(json.dumps({"started": 7}))             # not a string, no id/target
    (recon / "wrongid").mkdir()
    (recon / "wrongid" / "run.json").write_text(                                      # run_id != directory name
        json.dumps({"run_id": "somewhere-else", "target": "t", "started": "2026-01-01T00:00:01+00:00"}))
    names = [d.name for d in Run.list_runs(tmp_path)]
    assert names == [good.name]
    assert Run.latest(tmp_path).run_id == good.name and Run.latest(tmp_path).target == "t"


def test_delta_compares_immediate_predecessor_not_a_future_run(tmp_path):
    a = Run.create(tmp_path, "t"); a.add("subdomain", {"host": "a.example.com"}); exports.write_all(a)
    b = Run.create(tmp_path, "t"); b.add("subdomain", {"host": "b.example.com"}); exports.write_all(b)
    c = Run.create(tmp_path, "t"); c.add("subdomain", {"host": "c.example.com"}); exports.write_all(c)
    exports.write_delta(b)                              # regenerate the MIDDLE run's delta
    delta = (b.reports / "delta.md").read_text()
    assert f"vs previous run ({a.run_id})" in delta     # its predecessor, not the newer run c
    assert c.run_id not in delta


def test_identity_requires_parseable_tzaware_started_and_string_target(tmp_path):
    import json
    recon = tmp_path / "recon"
    good = _mk_run(recon, "20260101-000000-aaaaaaaa", "2026-01-01T00:00:00+00:00")
    _mk_run(recon, "20260101-000000-bbbbbbbb", "zzzz")                    # unparseable started
    _mk_run(recon, "20260101-000000-cccccccc", "2026-01-01T00:00:00")    # naive (no timezone)
    (recon / "20260101-000000-dddddddd").mkdir()
    (recon / "20260101-000000-dddddddd" / "run.json").write_text(        # non-string target
        json.dumps({"run_id": "20260101-000000-dddddddd", "target": 7, "started": "2026-01-01T00:00:00+00:00"}))
    assert [d.name for d in Run.list_runs(tmp_path)] == [good.name]
    assert Run.latest(tmp_path).run_id == good.name


def test_delta_emits_no_comparison_when_current_run_is_damaged(tmp_path):
    a = Run.create(tmp_path, "t"); a.add("subdomain", {"host": "a.example.com"}); exports.write_all(a)
    b = Run.create(tmp_path, "t"); b.add("subdomain", {"host": "b.example.com"}); exports.write_all(b)
    (b.dir / "run.json").write_text("{ broken")     # b can no longer be located in the ordered list
    exports.write_delta(b)
    delta = (b.reports / "delta.md").read_text()
    assert "vs previous run" not in delta            # fail closed: never diff a damaged run against another
