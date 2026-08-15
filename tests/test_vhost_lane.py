"""probe.ffuf_vhost — the A1 lane migrated off VHOST_CAP onto the base-service model.

Five structural review rounds preceded these tests, so they target the CONTRACT that emerged rather than the
happy path: scope exclusion BEFORE contact, base-service membership (origin identity is a rank only), typed
row validation, completion vs retention vs coverage, and a coverage generation on EVERY exit path.

Pure/offline — `run_contract` is faked, no ffuf, no network.
"""
import json

import pytest

from quarry_recon import budget, events, normalize, settings
from quarry_recon.phases import probe
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline


def _res(*pairs):
    """An ffuf vhost artifact body. pairs = (FUZZ word, status)."""
    return json.dumps({"results": [{"status": s, "input": {"FUZZ": w}} for w, s in pairs]})


class _Scope:
    passive_only = False

    def __init__(self, oos=(), inscope_suffix=("ex.com",)):
        self.oos = set(oos)
        self.suffixes = (inscope_suffix,) if isinstance(inscope_suffix, str) else tuple(inscope_suffix)

    def active_allowed(self, host):
        return self.in_scope(host) and not any(host.startswith(p) for p in self.oos)

    def in_scope(self, host):
        return bool(host) and any(host == s or host.endswith("." + s) for s in self.suffixes)

    def is_oos(self, host):
        return any(host.startswith(p) for p in self.oos)


class _Run:
    def __init__(self, d, live):
        self.dir = d
        self._live = live
        self.added = []
        self.recorded = []
        self.fail_add = False

    def raw_path(self, ph, tl, nm):
        p = self.dir / "raw" / ph / tl / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def read(self, kind):
        return self._live if kind == "live" else []

    def values(self, kind):
        return []

    def add(self, kind, e):
        if self.fail_add:
            raise RuntimeError("store write failed")
        self.added.append((kind, e))
        return True

    def record(self, ph, r):
        self.recorded.append(r)


class _Ctx:
    def __init__(self, d, live, scope=None, apexes=("ex.com",)):
        self.run = _Run(d, live)
        self.scope = scope or _Scope()
        self.http_timeout = 60
        self.echoed = []
        self.profile = type("P", (), {"apex_domains": list(apexes), "http_rl": 0})()

    def echo(self, m):
        self.echoed.append(m)

    def tmp(self, nm):
        p = self.run.dir / "work" / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_list(self, nm, it):
        p = self.tmp(nm)
        p.write_text("\n".join(it))
        return p


def _svc(url, addrs=("1.2.3.4",), cdn=False):
    return {
        "url": url, "cdn": cdn,
        "cdn_state": "detected" if cdn else "not_detected",
        "a": list(addrs),
    }


def _drive(tmp_path, monkeypatch, live, *, body=None, status=Status.SUCCESS, words="admin\nstaging\n",
           scope=None, apexes=("ex.com",), have=True, wordlist=True, budget_s=None, ctx=None,
           bodies=None):
    events.reset(); events.configure(tmp_path)
    monkeypatch.setattr(settings, "performance", lambda: {} if budget_s is None else dict(budget_s))
    monkeypatch.setattr(settings, "workers", lambda t, d: d)
    monkeypatch.setattr(probe, "have", lambda t: have)
    wl = tmp_path / "vhost.txt"
    wl.write_text(words)
    monkeypatch.setattr(probe, "_vhost_wordlist", lambda: (wl if wordlist else None))
    seen = []

    def fake(sid, cmd, **k):
        out = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
        seen.append({"out": out, "cmd": cmd,
                     # ffuf's -w value is "<path>:FUZZ" (keyword syntax) — keep only the path
                     "wl": cmd[cmd.index("-w") + 1].rsplit(":FUZZ", 1)[0],
                     "host": cmd[cmd.index("-H") + 1],
                     "u": cmd[cmd.index("-u") + 1],
                     # review#3 (vhost r6): capture the work_unit the lane ACTUALLY passes, so an identity
                     # assertion cannot pass while _vhost_scan stops folding `base` in.
                     "wu": k.get("work_unit")})
        b = bodies.pop(0) if bodies else body
        if b is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(b)
        res = RunResult("ffuf", cmd, status, 0, 1.0, None, 0)
        rc = k.get("reclassify")
        return rc(res) if rc else res
    monkeypatch.setattr(probe, "run_contract", fake)
    c = ctx or _Ctx(tmp_path, live, scope, apexes)
    probe._vhost_enum(c)
    return c, seen


def _cov(tmp_path, measure):
    ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    return [e for e in ev if e.get("measure") == measure]


def _folded(tmp_path):
    """Read events.jsonl through the REAL reconciliation (store._read_coverage / _run_summary).

    review#1 (vhost r6): asserting on `_cov(...)[-1]` only inspects the newest RAW event, so an exit test
    would still pass if `coverage_reset` vanished and a prior generation's units stayed live. This is the
    operator-visible truth: surviving units, their kinds, and the run verdict."""
    from quarry_recon.store import Run
    try:
        st = Run.create(tmp_path / "_folded", "t", run_id="r1")
    except FileExistsError:
        st = Run.open(tmp_path / "_folded", "t", "r1")
    (st.dir / "events.jsonl").write_text((tmp_path / "events.jsonl").read_text())
    summ = st._run_summary()
    units = {}
    for cov in summ["coverage"]:
        if cov["source_id"] != "probe.ffuf_vhost":
            continue
        units[cov["measure"]] = cov
        for u in cov.get("units", []):
            units[f"unit:{u['unit']}"] = u
        for u in cov.get("unknown", []):
            units[f"unknown:{u['unit']}"] = u
    return summ, units


def _ledger_state(tmp_path):
    f = list((tmp_path / "raw" / "probe").glob("probe_ffuf_vhost.*.state.json"))
    return json.loads(f[0].read_text()) if f else None


class TestScopeBeforeContact:
    """The RoE boundary: observe and mine OOS evidence, never actively EXPAND against it."""

    def test_oos_candidates_never_enter_the_submitted_wordlist(self, tmp_path, monkeypatch):
        scope = _Scope(oos=("jobs.", "dev."))
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")],
                         words="admin\njobs\nstaging\ndev\n", scope=scope, body=_res())
        submitted = __import__("pathlib").Path(seen[0]["wl"]).read_text().split()
        assert sorted(submitted) == ["admin", "staging"]
        assert "jobs" not in submitted and "dev" not in submitted

    def test_unknown_cdn_rows_are_gaps_without_starving_detector_negative_rows(
            self, tmp_path, monkeypatch):
        negative = _svc("https://direct.ex.com")
        negative["cdn_state"] = "not_detected"
        unknown = _svc("https://unknown.ex.com", cdn=None)
        unknown["cdn_state"] = "unknown"

        _ctx, seen = _drive(tmp_path, monkeypatch, [negative, unknown], body=_res())

        assert len(seen) == 1
        assert seen[0]["u"] == "https://direct.ex.com/"
        gaps = _cov(tmp_path, "cdn_classification")
        assert gaps and gaps[-1]["kind"] == events.COVERAGE_UNKNOWN

    @pytest.mark.parametrize("bad", ["../admin", "a/b", "-bad", "bad-", "a..b", "x" * 70])
    def test_malformed_candidates_never_enter_the_wordlist(self, tmp_path, monkeypatch, bad):
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")],
                         words=f"admin\n{bad}\n", body=_res())
        submitted = __import__("pathlib").Path(seen[0]["wl"]).read_text().split()
        assert submitted == ["admin"]

    def test_unicode_is_canonicalized_not_transliterated(self, tmp_path, monkeypatch):
        """The builtin idna codec is TRANSITIONAL: it maps `faß` to `fass`, a DIFFERENT name, which would mean
        actively contacting something the operator never scoped."""
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], words="faß\n", body=_res())
        submitted = __import__("pathlib").Path(seen[0]["wl"]).read_text().split()
        assert submitted == ["xn--fa-hia"]
        assert "fass" not in submitted
        assert normalize.idna_ascii("faß.ex.com") == "xn--fa-hia.ex.com"

    def test_exclusions_are_policy_telemetry_not_omitted_coverage(self, tmp_path, monkeypatch):
        """An OOS candidate was never eligible ACTIVE input, so reporting it as omitted would invent a
        shortfall and (via COVERAGE_SAMPLE) a complete_with_limits verdict."""
        scope = _Scope(oos=("jobs.",))
        c, _ = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")],
                      words="admin\njobs\n../bad\n", scope=scope, body=_res())
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led = [e for e in ev if e.get("event") == "ledger"][-1]
        assert led["consumed"] == {"wordlist_submitted": 1, "wordlist_oos_excluded": 1,
                                   "wordlist_invalid": 1}
        assert _cov(tmp_path, "wordlist_candidates") == []      # never a coverage measure

    def test_the_effective_wordlist_digest_is_in_the_resume_identity(self, tmp_path, monkeypatch):
        live = [_svc("https://h.ex.com")]
        _drive(tmp_path, monkeypatch, live, words="admin\nstaging\n", body=_res(("admin", 200)))
        first = _ledger_state(tmp_path)
        assert first["done"] != {}
        # a SCOPE change alters the effective list -> new generation -> re-scan
        c2, seen2 = _drive(tmp_path, monkeypatch, live, words="admin\nstaging\n",
                           scope=_Scope(oos=("staging.",)), body=_res())
        assert len(seen2) == 1
        states = list((tmp_path / "raw" / "probe").glob("probe_ffuf_vhost.*.state.json"))
        assert len(states) == 1                                  # superseded generation pruned


class TestBaseServiceMembership:
    def test_every_base_service_is_a_unit(self, tmp_path, monkeypatch):
        """VHOST_CAP=25 took an arbitrary 25 of 47 in dict order; co-hosted names were collapsed away."""
        live = [_svc(f"https://h{i}.ex.com", addrs=("1.2.3.4",)) for i in range(30)]
        c, seen = _drive(tmp_path, monkeypatch, live, body=_res())
        assert len(seen) == 30                                   # ALL of them, co-hosted or not
        sel = _cov(tmp_path, "base_services")[-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (30, 30, 0)

    def test_the_address_set_ranks_but_never_excludes(self, tmp_path, monkeypatch):
        """One co-hosted representative goes first; the rest still run."""
        live = [_svc("http://a.ex.com", addrs=("1.1.1.1",)),
                _svc("https://b.ex.com", addrs=("1.1.1.1",)),      # same address set, better score
                _svc("https://c.ex.com", addrs=("2.2.2.2",))]
        c, seen = _drive(tmp_path, monkeypatch, live, body=_res())
        assert len(seen) == 3
        first_two = {s["u"] for s in seen[:2]}
        assert "https://b.ex.com/" in first_two and "https://c.ex.com/" in first_two
        assert seen[2]["u"] == "http://a.ex.com/"                 # the co-hosted duplicate is LAST, not dropped

    def test_the_full_address_set_is_used_not_just_the_first(self, tmp_path, monkeypatch):
        """Keeping only a[0] collapsed 74 A-origins to 47 keys on the OTC data.

        review#2 (vhost r6): "both eventually run" was vacuous. So was asserting on the first TWO calls —
        with equal scores the two models produce an identical order. The scores are deliberately unequal here
        so the models diverge observably:

          full address sets: {1.1.1.1,9.9.9.9} -> rep a · {1.1.1.1,8.8.8.8} -> rep b
                             tier0 = [a, b] (ranked by score), tier1 = [c]  ->  order a, b, c
          a[0] only:         all three key on 1.1.1.1, so ONLY a is a representative
                             tier0 = [a], tier1 = [c, b] (by score)          ->  order a, c, b

        The discriminator is which service runs LAST: the genuine co-hosted duplicate (c), or the
        distinct-address-set service (b) that an a[0] regression wrongly demotes."""
        live = [_svc("https://a.ex.com", addrs=("1.1.1.1", "9.9.9.9")),   # rep of set {1,9}, score 3
                _svc("http://b.ex.com", addrs=("1.1.1.1", "8.8.8.8")),    # rep of set {1,8}, score 1
                _svc("https://c.ex.com", addrs=("1.1.1.1", "9.9.9.9"))]   # duplicate of a's set
        c, seen = _drive(tmp_path, monkeypatch, live, body=_res())
        order = [x["u"] for x in seen]
        assert len(order) == 3                                    # nothing excluded, ever
        # b holds a DISTINCT address set, so it must not be demoted behind the duplicate
        assert order == ["https://a.ex.com/", "http://b.ex.com/", "https://c.ex.com/"]
        assert order[-1] == "https://c.ex.com/"                   # the co-hosted duplicate runs last

    def test_cdn_and_non_allowed_services_are_excluded(self, tmp_path, monkeypatch):
        live = [_svc("https://ok.ex.com"), _svc("https://edge.ex.com", cdn=True)]
        c, seen = _drive(tmp_path, monkeypatch, live, body=_res())
        assert len(seen) == 1 and "ok.ex.com" in seen[0]["u"]

    def test_one_unit_per_base_and_apex(self, tmp_path, monkeypatch):
        """review#3 (vhost r6): the earlier version made the second apex out of scope and then expected ONE
        call, so it never exercised the product at all. Two eligible bases x two eligible apexes = FOUR
        distinct units."""
        scope = _Scope(inscope_suffix=("ex.com", "ex2.com"))
        live = [_svc("https://a.ex.com", addrs=("1.1.1.1",)), _svc("https://b.ex.com", addrs=("2.2.2.2",))]
        c, seen = _drive(tmp_path, monkeypatch, live, apexes=("ex.com", "ex2.com"),
                         scope=scope, body=_res())
        assert len(seen) == 4                                      # 2 bases x 2 apexes
        assert {s["host"] for s in seen} == {"Host: FUZZ.ex.com", "Host: FUZZ.ex2.com"}
        assert len({s["wu"] for s in seen}) == 4                   # four DISTINCT work units
        assert len({s["out"].name for s in seen}) == 4             # ...and four distinct artifacts
        sel = _cov(tmp_path, "base_services")[-1]
        assert sel["eligible"] == 4


class TestUnitIdentity:
    def test_scheme_and_port_variants_are_distinct_units(self, tmp_path, monkeypatch):
        """`http://h:80` and `https://h:443` collapsed into one identity, so two distinct observations merged
        and could conflict on status."""
        live = [_svc("http://h.ex.com", addrs=("1.1.1.1",)), _svc("https://h.ex.com", addrs=("1.1.1.1",))]
        c, seen = _drive(tmp_path, monkeypatch, live, body=_res(("admin", 200)))
        assert len({s["out"].name for s in seen}) == 2            # separate artifacts
        ids = {e["id"] for k, e in c.run.added if k == "review"}
        assert ids == {"vhost:http://h.ex.com:admin.ex.com", "vhost:https://h.ex.com:admin.ex.com"}

    def test_the_finding_carries_the_base_not_a_fake_ip(self, tmp_path, monkeypatch):
        c, _ = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com", addrs=("1.2.3.4",))],
                      body=_res(("admin", 200)))
        rev = [e for k, e in c.run.added if k == "review"][0]
        assert rev["base"] == "https://h.ex.com"
        assert rev["a"] == ["1.2.3.4"]                            # DNS context...
        assert "ip" not in rev                                    # ...never an `ip` claim
        assert "base service" in rev["note"]

    def test_a_changed_base_is_a_new_unit(self, tmp_path, monkeypatch):
        """A better representative discovered later must not reuse the old completion.

        review#3 (vhost r6): comparing two events.work_unit() calls directly proved nothing about the WIRING —
        it passed even if _vhost_scan stopped folding `base` in. These are the work_units the lane actually
        handed to run_contract."""
        live = [_svc("http://h.ex.com", addrs=("1.1.1.1",)), _svc("https://h.ex.com", addrs=("1.1.1.1",))]
        c, seen = _drive(tmp_path, monkeypatch, live, body=_res())
        assert len(seen) == 2
        wus = [s["wu"] for s in seen]
        assert all(w for w in wus)                                # a work_unit really was passed
        assert wus[0] != wus[1]                                   # ...and the BASE distinguishes them
        # same apex, same wordlist, same match codes: only `base` differs
        assert {s["host"] for s in seen} == {"Host: FUZZ.ex.com"}


class TestTypedRowContract:
    def _submitted(self):
        return {"admin", "staging"}

    @pytest.mark.parametrize("row", [
        {"status": True, "input": {"FUZZ": "admin"}},              # bool is an int subclass
        {"status": "200", "input": {"FUZZ": "admin"}},
        {"status": 999, "input": {"FUZZ": "admin"}},
        {"status": 0, "input": {"FUZZ": "admin"}},
        {"status": 200, "input": ["admin"]},                       # input not an object
        {"status": 200, "input": {"FUZZ": 5}},
        {"status": 200, "input": {"FUZZ": "../admin"}},            # never becomes a hostname
        {"status": 200, "input": {"FUZZ": "notsubmitted"}},        # we never asked for it
        {"status": 200},
    ])
    def test_unusable_rows_are_rejected(self, row):
        assert probe._vhost_row(row, self._submitted(), "ex.com", _Scope()) is False

    def test_a_genuine_row_is_accepted(self):
        assert probe._vhost_row({"status": 200, "input": {"FUZZ": "admin"}},
                                self._submitted(), "ex.com", _Scope()) is True

    def test_unusable_rows_make_the_unit_non_resumable(self, tmp_path, monkeypatch):
        body = json.dumps({"results": [{"status": 200, "input": {"FUZZ": "notsubmitted"}}]})
        c, _ = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], body=body)
        assert _ledger_state(tmp_path)["done"] == {}
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_UNKNOWN and "input/FUZZ contract" in rows["reason"]

    def test_valid_siblings_survive_an_unusable_row(self, tmp_path, monkeypatch):
        body = json.dumps({"results": [{"status": 200, "input": {"FUZZ": "admin"}},
                                       {"status": True, "input": {"FUZZ": "staging"}}]})
        c, _ = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], body=body)
        hosts = [e["host"] for k, e in c.run.added if k == "review"]
        assert hosts == ["admin.ex.com"]


class TestCompletionRetentionCoverage:
    @pytest.mark.parametrize("status", [Status.PARTIAL, Status.BLOCKED, Status.FAILED, Status.TIMED_OUT])
    def test_a_degraded_run_is_not_recorded_but_is_retained(self, tmp_path, monkeypatch, status):
        live = [_svc("https://h.ex.com")]
        c, _ = _drive(tmp_path, monkeypatch, live, status=status, body=_res(("admin", 200)))
        assert _ledger_state(tmp_path)["done"] == {}               # never complete
        assert _ledger_state(tmp_path)["evidence"] != {}            # but retained
        c2, seen2 = _drive(tmp_path, monkeypatch, live, status=status, body=_res())
        assert len(seen2) == 1                                     # re-runs
        assert "admin.ex.com" in {e["host"] for k, e in c2.run.added if k == "review"}   # replayed

    def test_a_clean_usable_run_completes_and_resumes(self, tmp_path, monkeypatch):
        live = [_svc("https://h.ex.com")]
        _drive(tmp_path, monkeypatch, live, body=_res(("admin", 200)))
        assert _ledger_state(tmp_path)["done"] != {}
        c2, seen2 = _drive(tmp_path, monkeypatch, live, body=_res())
        assert seen2 == []                                         # resumed
        assert "admin.ex.com" in {e["host"] for k, e in c2.run.added if k == "review"}   # re-ingested

    def test_a_dirty_history_does_not_block_a_later_completion(self, tmp_path, monkeypatch):
        live = [_svc("https://h.ex.com")]
        dirty = json.dumps({"results": [{"status": 200, "input": {"FUZZ": "admin"}},
                                        {"status": True, "input": {"FUZZ": "staging"}}]})
        _drive(tmp_path, monkeypatch, live, body=dirty)
        assert _ledger_state(tmp_path)["done"] == {}
        _drive(tmp_path, monkeypatch, live, body=_res(("staging", 200)))
        assert _ledger_state(tmp_path)["done"] != {}                # completion granted
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_TIMEOUT             # and the gap is CLEARED

    def test_retries_never_overwrite_recorded_evidence(self, tmp_path, monkeypatch):
        live = [_svc("https://h.ex.com")]
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_res(("admin", 200)))
        first = seen1[0]["out"]
        c2, seen2 = _drive(tmp_path, monkeypatch, live, words="admin\nstaging\nextra\n",
                           body=_res(("staging", 200)))
        assert seen2 and seen2[0]["out"] != first
        assert first.exists() and "admin" in first.read_text()

    def test_a_tampered_retained_artifact_is_not_replayed(self, tmp_path, monkeypatch):
        live = [_svc("https://h.ex.com")]
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_res(("admin", 200)))
        seen1[0]["out"].write_text(_res(("staging", 200)))          # tamper after recording
        c2, _ = _drive(tmp_path, monkeypatch, live, body=_res())
        hosts = {e["host"] for k, e in c2.run.added if k == "review"}
        assert "staging.ex.com" not in hosts                        # digest mismatch -> not replayed


class TestBudgetAndReporting:
    def test_the_budget_gates_launching_only(self, tmp_path, monkeypatch):
        live = [_svc("https://z.ex.com", addrs=("9.9.9.9",))]
        _drive(tmp_path, monkeypatch, live, body=_res(("admin", 200)))          # z completes
        real = budget.Budget.exhausted
        monkeypatch.setattr(budget.Budget, "exhausted", lambda self: True)
        c, seen = _drive(tmp_path, monkeypatch,
                         live + [_svc("https://a.ex.com", addrs=("1.1.1.1",))],
                         body=_res(), budget_s={"VHOST_BUDGET_S": 1})
        monkeypatch.setattr(budget.Budget, "exhausted", real)
        assert seen == []                                            # nothing launched
        sel = _cov(tmp_path, "base_services")[-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 1, 1)   # done unit still counted
        assert "admin.ex.com" in {e["host"] for k, e in c.run.added if k == "review"}   # and replayed

    def test_a_never_launched_unit_emits_no_row_unit(self, tmp_path, monkeypatch):
        real = budget.Budget.exhausted
        monkeypatch.setattr(budget.Budget, "exhausted", lambda self: True)
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], body=_res(),
                         budget_s={"VHOST_BUDGET_S": 1})
        monkeypatch.setattr(budget.Budget, "exhausted", real)
        assert seen == [] and _cov(tmp_path, "result_rows") == []
        sel = _cov(tmp_path, "base_services")[-1]
        assert sel["omitted"] == 1

    def test_candidate_count_is_unique_per_lifecycle(self, tmp_path, monkeypatch):
        live = [_svc("https://h.ex.com")]
        dirty = json.dumps({"results": [{"status": 200, "input": {"FUZZ": "admin"}},
                                        {"status": True, "input": {"FUZZ": "staging"}}]})
        for _ in range(4):
            c, _ = _drive(tmp_path, monkeypatch, live, body=dirty)   # four retained attempts, one candidate
        line = next(m for m in c.echoed if "vhost ffuf:" in m)
        assert "1 candidate(s)" in line

    def test_persistence_failure_is_reported(self, tmp_path, monkeypatch):
        monkeypatch.setattr(budget.Ledger, "save", lambda self: False)
        c, _ = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], body=_res(("admin", 200)))
        st = _cov(tmp_path, "state_persisted")[-1]
        assert st["omitted"] == 1
        assert any("NOT persisted" in m for m in c.echoed)


class TestEveryExitOpensAGeneration:
    """A prior run's counters must never remain current — whatever the reason we stopped.

    review#1 (vhost r6): these assert through the REAL reconciliation, not the newest raw event. The earlier
    versions would all have passed with `coverage_reset` removed and the previous generation's `result_rows`
    units still live."""

    def _populate(self, tmp_path, monkeypatch):
        _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], body=_res(("admin", 200)))
        _summ, units = _folded(tmp_path)
        assert units["base_services"]["eligible"] == 1
        assert any(k.startswith("unit:rows:") for k in units)      # a per-unit row record really existed
        return units

    def test_no_base_services_clears_prior_coverage(self, tmp_path, monkeypatch):
        self._populate(tmp_path, monkeypatch)
        c, seen = _drive(tmp_path, monkeypatch, [], body=_res())
        summ, units = _folded(tmp_path)
        assert units["base_services"]["eligible"] == 0 and units["base_services"]["omitted"] == 0
        assert not [k for k in units if k.startswith("unit:rows:")]      # the prior row unit is GONE
        assert not [k for k in units if k.startswith("unknown:rows:")]
        assert c.run.recorded and seen == []

    def test_all_candidates_excluded_clears_prior_coverage(self, tmp_path, monkeypatch):
        self._populate(tmp_path, monkeypatch)
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")],
                         scope=_Scope(oos=("admin.", "staging.")), body=_res())
        summ, units = _folded(tmp_path)
        assert units["base_services"]["eligible"] == 0
        assert not [k for k in units if k.startswith("unit:rows:")]
        assert seen == []

    @pytest.mark.parametrize("kw", [{"have": False}, {"wordlist": False}])
    def test_unavailable_tooling_is_unknown_not_zero(self, tmp_path, monkeypatch, kw):
        """review#1 (vhost r5): a missing ffuf or wordlist is not "zero eligible input" — we could not LOOK,
        so a clean 0/0 would assert there was nothing to find. review#1 (r6): asserted at the VERDICT."""
        self._populate(tmp_path, monkeypatch)
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")], body=_res(), **kw)
        summ, units = _folded(tmp_path)
        # the prior generation's row unit must be gone, and the lane must read UNKNOWN
        assert not [k for k in units if k.startswith("unit:rows:")]
        for m in ("base_services", "base_services_scanned", "state_persisted"):
            assert units[m]["valid"] is False                       # no trustworthy counters
        gaps = [g for g in summ["gaps"] if g["tool"] == "probe.ffuf_vhost"]
        assert gaps and all(g["status"] == "coverage:unknown" for g in gaps)
        assert summ["verdict"] == "complete_with_gaps"
        assert seen == [] and c.run.recorded

    def test_a_zero_exit_is_not_reported_as_unknown(self, tmp_path, monkeypatch):
        """The distinction has to hold in BOTH directions: genuinely-empty input is a clean zero, so it must
        NOT produce a coverage:unknown gap the way unavailable tooling does."""
        c, seen = _drive(tmp_path, monkeypatch, [], body=_res())
        summ, units = _folded(tmp_path)
        assert units["base_services"]["valid"] is True
        gaps = [g for g in summ["gaps"] if g["tool"] == "probe.ffuf_vhost"]
        assert gaps == []

    def test_an_apex_with_no_contactable_candidate_is_a_clean_skip(self, tmp_path, monkeypatch):
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")],
                         scope=_Scope(oos=("admin.", "staging.")), body=_res())
        notes = " ".join(getattr(r, "note", "") or "" for r in c.run.recorded)
        assert "contactable" in notes


class TestNoCrashOnAnyStatus:
    """The `origin`/`hashlib` NameErrors only surfaced when the lane was actually EXECUTED — compilation and
    916 unrelated tests both passed while every vhost run crashed."""

    @pytest.mark.parametrize("status", [Status.SUCCESS, Status.EMPTY, Status.PARTIAL, Status.BLOCKED,
                                        Status.FAILED, Status.TIMED_OUT])
    def test_every_status_branch_runs(self, tmp_path, monkeypatch, status):
        c, seen = _drive(tmp_path, monkeypatch, [_svc("https://h.ex.com")],
                         status=status, body=_res(("admin", 200)))
        assert len(seen) == 1
        assert c.run.recorded

    def test_a_store_failure_is_reported_as_unmeasured(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, [_svc("https://h.ex.com")])
        ctx.run.fail_add = True
        with pytest.raises(RuntimeError):
            _drive(tmp_path, monkeypatch, None, body=_res(("admin", 200)), ctx=ctx)
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_UNKNOWN
