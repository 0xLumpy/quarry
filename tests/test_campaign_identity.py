"""Cross-run entity identity — settle prerequisite A.

A campaign compares what two CHILD RUNS know, and entities are run-scoped: a second `Run.create` in the
same project starts empty. So the comparison needs three things from a finished run — the canonical
IDENTITY of each entity, a MONOTONIC merge, and a fingerprint over MATERIAL content only. These tests pin
the properties the supervisor will rely on, not the implementation that provides them.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import store


class TestMaterialContent:
    def test_run_scoped_bookkeeping_is_NOT_material(self):
        """Artifact paths and timestamps say WHERE and WHEN we looked, not what is true. If they counted,
        every child would look like progress and a fixed point could never be reached."""
        base = {"host": "a.acme.com", "sources": ["crtsh"], "a": ["1.2.3.4"],
                "raw_ref": "/runs/1/raw/x.json", "first_seen": "t0", "last_seen": "t1"}
        later = dict(base, raw_ref="/runs/2/raw/y.json", raw_refs=["/runs/2/raw/y.json"],
                     first_seen="t9", last_seen="t9")
        assert store.fingerprint("resolved", base) == store.fingerprint("resolved", later)
        assert not store.adds_material("resolved", base, later)
        # `_inherited` joined them with the campaign bootstrap: how a run GOT an entity is bookkeeping,
        # so an inherited copy fingerprints exactly like the record it came from
        assert set(store.RUN_SCOPED_FIELDS) == {"first_seen", "last_seen", "raw_ref", "raw_refs",
                                                "_inherited"}

    def test_list_ORDER_is_not_material(self):
        """Two runs can report the same IPs in a different order; that is not discovery."""
        one = {"host": "a.acme.com", "a": ["1.2.3.4", "5.6.7.8"], "sources": ["crtsh", "subfinder"]}
        other = {"host": "a.acme.com", "a": ["5.6.7.8", "1.2.3.4"], "sources": ["subfinder", "crtsh"]}
        assert store.fingerprint("resolved", one) == store.fingerprint("resolved", other)
        assert not store.adds_material("resolved", one, other)

    def test_a_new_SOURCE_is_material(self):
        """Provenance is not noise: a second, independent source for the same host is a fact."""
        base = {"host": "a.acme.com", "sources": ["crtsh"]}
        assert store.adds_material("subdomain", base, {"host": "a.acme.com", "sources": ["shodan"]})

    def test_ENRICHMENT_of_a_known_identity_is_material(self):
        """The case a count can never see: same identity, same total, new knowledge."""
        base = {"host": "a.acme.com", "sources": ["crtsh"]}
        assert store.adds_material("resolved", base, {"host": "a.acme.com", "a": ["1.2.3.4"]})


class TestProgressIsMonotonic:
    def test_an_OSCILLATING_scalar_counts_ONCE(self):
        """A title, a DNS answer or a rotating certificate can alternate for ever. The first swing is a
        fact the union did not hold; going back adds nothing, because the union holds both."""
        union = {"url": "https://a.acme.com/", "title": "A"}
        assert store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "B"})
        union = store.merge("live", union, {"url": "https://a.acme.com/", "title": "B"})
        assert not store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "A"})
        assert not store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "B"})
        # ...and a THIRD, genuinely new value still is progress
        assert store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "C"})

    def test_merging_never_REMOVES_a_fact(self):
        union = {"host": "a.acme.com", "sources": ["crtsh"], "a": ["1.2.3.4"], "tech": ["nginx"]}
        merged = store.merge("resolved", union, {"host": "a.acme.com", "sources": ["shodan"]})
        assert set(merged["sources"]) == {"crtsh", "shodan"}
        assert merged["a"] == ["1.2.3.4"] and merged["tech"] == ["nginx"]

    def test_a_pure_duplicate_is_not_progress(self):
        rec = {"host": "a.acme.com", "sources": ["crtsh"], "a": ["1.2.3.4"]}
        assert not store.adds_material("resolved", rec, dict(rec))


class TestIdentityAcrossRuns:
    def test_the_canonical_key_is_the_cross_run_identity(self):
        """Case, trailing dots and URL shape are the store's business, and the campaign must use the same
        rule — otherwise `API.acme.com` and `api.acme.com` are two identities in the union."""
        assert store.canonical_key("subdomain", {"host": "API.Acme.com."}) == \
            store.canonical_key("subdomain", {"host": "api.acme.com"})
        # the URL rule normalises SCHEME + HOSTNAME only: path, query and userinfo are evidence and are
        # preserved exactly (`/API` != `/api`), and an explicit port stays part of the identity
        assert store.canonical_key("live", {"url": "HTTPS://A.Acme.COM./x"}) == \
            store.canonical_key("live", {"url": "https://a.acme.com/x"})
        assert store.canonical_key("live", {"url": "https://a.acme.com/API"}) != \
            store.canonical_key("live", {"url": "https://a.acme.com/api"})

    def test_a_FINISHED_run_reads_exactly_as_it_did_while_live(self, tmp_path):
        """The supervisor reads a child AFTER it ended; folding its log must reproduce the merged view the
        run itself had — same identities, same merged provenance."""
        run = store.Run.create(tmp_path, "t")
        run.add("subdomain", {"host": "a.acme.com", "sources": ["crtsh"], "raw_ref": "/x"})
        run.add("subdomain", {"host": "A.ACME.com", "sources": ["subfinder"], "raw_ref": "/y"})
        run.add("subdomain", {"host": "b.acme.com", "sources": ["crtsh"]})
        live = {k: v for k, v in ((store.canonical_key("subdomain", r), r) for r in run.read("subdomain"))}
        folded = store.fold_observations(run.normalized / "subdomain.jsonl")
        assert folded.status == "valid" and folded.trustworthy and folded.dropped == 0, folded
        assert set(folded.records) == set(live) == {"a.acme.com", "b.acme.com"}
        assert set(folded.records["a.acme.com"]["sources"]) == {"crtsh", "subfinder"}
        for key in live:
            assert store.fingerprint("subdomain", folded.records[key]) == \
                store.fingerprint("subdomain", live[key])

    def test_a_CORRUPT_line_costs_one_observation_and_is_COUNTED(self, tmp_path):
        f = tmp_path / "subdomain.jsonl"
        f.write_text(json.dumps({"host": "a.acme.com", "sources": ["x"]}) + "\n"
                     + "{not json\n" + "[]\n" + json.dumps({"no": "key"}) + "\n"
                     + json.dumps({"host": "b.acme.com"}) + "\n")
        folded = store.fold_observations(f)
        assert set(folded.records) == {"a.acme.com", "b.acme.com"}
        assert (folded.status, folded.dropped, folded.trustworthy) == ("degraded", 3, False), folded

    def test_ONE_invalid_byte_costs_ONE_row_not_the_log(self, tmp_path):
        """`read_text()` decoded the whole file before rows were isolated, so a single 0xff destroyed every
        valid observation before and after it."""
        f = tmp_path / "subdomain.jsonl"
        f.write_bytes(json.dumps({"host": "a.acme.com"}).encode() + b"\n"
                      + b'{"host":"\xff\xfe.acme.com"}\n'
                      + json.dumps({"host": "b.acme.com"}).encode() + b"\n")
        folded = store.fold_observations(f)
        assert set(folded.records) == {"a.acme.com", "b.acme.com"}, folded
        assert (folded.status, folded.dropped) == ("degraded", 1), folded

    def test_UNREADABLE_is_never_reported_as_EMPTY(self, tmp_path):
        """The distinction a campaign lives on: bootstrapping from a lost log would drop evidence silently,
        and a fixed point declared over it would claim finished work nobody could see."""
        absent = store.fold_observations(tmp_path / "nope.jsonl")
        assert (absent.status, absent.records, absent.trustworthy) == ("absent", {}, True)
        unusable = store.fold_observations(tmp_path)              # a directory, not a log
        assert unusable.status == "unusable" and not unusable.trustworthy, unusable
        assert unusable.reason and unusable.records == {}, unusable
        empty = tmp_path / "subdomain.jsonl"
        empty.write_text("")
        clean = store.fold_observations(empty)
        assert (clean.status, clean.records, clean.trustworthy) == ("valid", {}, True)   # a REAL empty

    @pytest.mark.parametrize("entity", sorted(store.ENTITY_KEYS))
    def test_every_entity_kind_has_an_identity_and_a_fingerprint(self, entity):
        """Every kind the store can hold must be comparable across runs — a kind the campaign cannot key
        is a kind whose discovery it would silently ignore."""
        field = store.ENTITY_KEYS[entity]
        rec = {field: "value-1", "sources": ["x"]}
        assert store.canonical_key(entity, rec)
        assert store.fingerprint(entity, rec) and len(store.fingerprint(entity, rec)) == 32
        assert not store.adds_material(entity, rec, dict(rec))
        assert store.adds_material(entity, rec, {field: "value-1", "sources": ["y"]})


class TestMaterialIsCanonicalAtEveryDepth:
    def test_a_NESTED_list_order_is_not_material(self):
        """The contract says list order is never material; a shallow pass left everything below the first
        dict order-sensitive, so identical records could fingerprint differently."""
        one = {"id": "x", "detail": [{"ports": [443, 80], "tags": ["a", "b"]}]}
        other = {"id": "x", "detail": [{"tags": ["b", "a"], "ports": [80, 443]}]}
        assert store.fingerprint("finding", one) == store.fingerprint("finding", other)
        assert not store.adds_material("finding", one, other)

    def test_a_nested_ADDITION_is_still_material(self):
        one = {"id": "x", "detail": [{"ports": [443]}]}
        other = {"id": "x", "detail": [{"ports": [443, 8443]}]}
        assert store.fingerprint("finding", one) != store.fingerprint("finding", other)


class TestTrustIsAnEvidenceClaim:
    """A parser saying "I read this file cleanly" is not the same as "this is what the run held". A log can
    be deleted after the manifest was written, or truncated on a line boundary — both parse without a
    single dropped row, and both would hand a campaign a smaller corpus that looks authoritative."""

    def _run(self, tmp_path, hosts=("a.acme.com", "b.acme.com")):
        run = store.Run.create(tmp_path, "t")
        for h in hosts:
            run.add("subdomain", {"host": h, "sources": ["crtsh"]})
        run.write_manifest(profile_summary={}, phases_run=["vertical"])
        return run

    def test_a_clean_run_reconciles(self, tmp_path):
        run = self._run(tmp_path)
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert (folded.status, len(folded.records), folded.trustworthy) == ("valid", 2, True), folded

    def test_a_DELETED_log_is_unusable_not_empty(self, tmp_path):
        """Absence proves nothing on its own: the manifest says the run held two."""
        run = self._run(tmp_path)
        (run.normalized / "subdomain.jsonl").unlink()
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert folded.status == "unusable" and not folded.trustworthy, folded
        assert "the log is gone" in folded.reason and folded.records == {}, folded

    def test_a_TRUNCATED_log_parses_cleanly_and_is_still_degraded(self, tmp_path):
        """The case a parser can never catch: cut on a line boundary, no dropped row, fewer entities."""
        run = self._run(tmp_path)
        f = run.normalized / "subdomain.jsonl"
        f.write_text(f.read_text().splitlines()[0] + "\n")
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert folded.status == "degraded" and not folded.trustworthy, folded
        assert "the run recorded 2" in folded.reason and len(folded.records) == 1, folded

    def test_a_run_that_held_NOTHING_is_an_authoritative_zero(self, tmp_path):
        run = store.Run.create(tmp_path, "t")
        run.write_manifest(profile_summary={}, phases_run=["vertical"])
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert (folded.status, folded.records, folded.trustworthy) == ("valid", {}, True), folded

    def test_a_missing_or_broken_MANIFEST_is_UNKNOWN(self, tmp_path):
        run = self._run(tmp_path)
        run.manifest_path.unlink()
        unknown = store.fold_run_entity(run.dir, "subdomain")
        assert unknown.status == "unknown" and not unknown.trustworthy, unknown
        run.manifest_path.write_text("{not json")
        assert store.fold_run_entity(run.dir, "subdomain").status == "unknown"
        run.manifest_path.write_text(json.dumps({"run_id": "x"}))      # no entity_counts at all
        assert store.fold_run_entity(run.dir, "subdomain").status == "unknown"

    def test_rows_the_manifest_never_counted_are_degraded(self, tmp_path):
        """The other direction: a log holding more than the run recorded is not a corpus either."""
        run = self._run(tmp_path)
        manifest = json.loads(run.manifest_path.read_text())
        del manifest["entity_counts"]["subdomain"]
        run.manifest_path.write_text(json.dumps(manifest))
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert folded.status == "degraded" and not folded.trustworthy, folded


    @pytest.mark.parametrize("bogus", [True, False, 1.0, 0.0, "1", None, -1, [1], {"n": 1}])
    def test_a_MALFORMED_count_certifies_nothing(self, tmp_path, bogus):
        """`True == 1` and `1.0 == 1`, so a malformed count would have passed a one-record log off as
        authoritative — and an explicit `null` would have read as "the run recorded none of this kind"."""
        run = self._run(tmp_path, hosts=("a.acme.com",))
        manifest = json.loads(run.manifest_path.read_text())
        manifest["entity_counts"]["subdomain"] = bogus
        run.manifest_path.write_text(json.dumps(manifest))
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert folded.status == "unknown" and not folded.trustworthy, (bogus, folded)
        assert "exact non-negative int" in folded.reason, folded

    def test_an_ABSENT_key_is_still_an_authoritative_zero(self, tmp_path):
        """Absence of the key is a different statement from a malformed value, and it stays usable."""
        run = store.Run.create(tmp_path, "t")
        run.write_manifest(profile_summary={}, phases_run=["vertical"])
        assert "subdomain" not in json.loads(run.manifest_path.read_text())["entity_counts"]
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert (folded.status, folded.trustworthy) == ("valid", True), folded

    def test_an_exact_ZERO_count_is_honoured(self, tmp_path):
        run = self._run(tmp_path, hosts=())
        manifest = json.loads(run.manifest_path.read_text())
        manifest["entity_counts"]["subdomain"] = 0
        run.manifest_path.write_text(json.dumps(manifest))
        folded = store.fold_run_entity(run.dir, "subdomain")
        assert (folded.status, folded.records, folded.trustworthy) == ("valid", {}, True), folded


class TestOneFoldForLiveAndFinished:
    def test_the_LIVE_reader_survives_the_same_invalid_byte(self, tmp_path):
        """The live reader had its own whole-file decode, so the byte contained by `fold_observations`
        still raised here — two implementations, one of them wrong."""
        run = store.Run.create(tmp_path, "t")
        run.add("subdomain", {"host": "a.acme.com", "sources": ["x"]})
        with (run.normalized / "subdomain.jsonl").open("ab") as fh:
            fh.write(b'{"host":"\xff\xfe.acme.com"}\n')
            fh.write(json.dumps({"host": "b.acme.com"}).encode() + b"\n")
        fresh = store.Run.open(tmp_path, run.target, run.run_id)     # a REOPENED run reads the same log
        assert set(fresh.values("subdomain")) == {"a.acme.com", "b.acme.com"}

    def test_live_and_finished_agree_record_for_record(self, tmp_path):
        run = store.Run.create(tmp_path, "t")
        run.add("subdomain", {"host": "a.acme.com", "sources": ["crtsh"], "raw_ref": "/x"})
        run.add("subdomain", {"host": "A.ACME.com", "sources": ["subfinder"]})
        live = {store.canonical_key("subdomain", r): r for r in run.read("subdomain")}
        folded = store.fold_observations(run.normalized / "subdomain.jsonl").records
        assert set(live) == set(folded)
        for key in live:
            assert store.fingerprint("subdomain", live[key]) == store.fingerprint("subdomain", folded[key])
