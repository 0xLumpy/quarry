"""The campaign's cumulative store — settle prerequisite C.

Entities are RUN-SCOPED, so a supervisor that repeats runs needs somewhere for what earlier children
learned to live AND must seed every later child from it. These tests pin the invariants the supervisor will
rely on: absorbing only trustworthy evidence, monotonic progress, an idempotent bootstrap, and an inherited
entity that is never counted as the child's own discovery.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import campaign, store
from quarry_recon.state import ContractError


def _finished(tmp_path, *entities, target="t"):
    run = store.Run.create(tmp_path, target)
    for kind, rec in entities:
        run.add(kind, rec)
    run.write_manifest(profile_summary={}, phases_run=["vertical"])
    return run


class TestAbsorbingAChild:
    def test_a_child_s_entities_become_the_union(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}),
                        ("subdomain", {"host": "b.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        result = union.absorb(run.dir)
        assert (result.new, result.enriched, result.progressed) == (2, 0, True), result
        assert set(union.records) == {("subdomain", "a.acme.com"), ("subdomain", "b.acme.com")}
        assert union.path.exists() and union.status == "valid"
        rows = (union.dir / json.loads(union.path.read_text())["file"]).read_text().splitlines()
        assert len(rows) == 2, rows

    def test_absorbing_the_SAME_run_twice_REPLAYS_what_it_added(self, tmp_path):
        """The union already holds it, so a second merge finds nothing new — which is not the same fact
        as the child having added nothing, and a resume that read it that way would invent a fixed point."""
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        assert union.absorb(run.dir).new == 1
        generation, records = union.generation, dict(union.records)
        again = union.absorb(run.dir)
        assert (again.new, again.enriched, again.progressed) == (1, 0, True), again
        assert (union.generation, union.records) == (generation, records), "a replay published again"

    def test_ANOTHER_child_that_re_sees_a_known_identity_adds_nothing(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        assert union.absorb(first.dir).new == 1
        second = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        again = union.absorb(second.dir)
        assert (again.new, again.enriched, again.progressed) == (0, 0, False), again

    def test_ENRICHMENT_of_a_known_identity_is_progress(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        second = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["shodan"]}))
        result = union.absorb(second.dir)
        assert (result.new, result.enriched, result.progressed) == (0, 1, True), result
        held = union.records[("subdomain", "a.acme.com")]
        assert set(held["sources"]) == {"crtsh", "shodan"}          # provenance UNIONed, never replaced

    def test_an_UNREADABLE_child_is_never_absorbed_as_empty(self, tmp_path):
        """The difference between "this child found nothing" and "we could not read what it found" is the
        difference between a fixed point and a lie."""
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        (run.normalized / "subdomain.jsonl").unlink()               # the manifest still says 1
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        result = union.absorb(run.dir, kinds=["subdomain"])
        assert result.unusable and "unusable" in result.unusable["subdomain"], result
        assert not result.progressed and union.records == {}, result

    def test_an_OSCILLATION_is_absorbed_once(self, tmp_path):
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        a = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "A"}))
        b = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "B"}))
        c = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "A"}))
        assert union.absorb(a.dir).new == 1
        assert union.absorb(b.dir).enriched == 1                    # the first swing IS new knowledge
        assert not union.absorb(c.dir).progressed                   # ...going back adds nothing

    def test_a_corrupt_row_keeps_the_rest_but_is_NOT_trustworthy(self, tmp_path):
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["x"]}))
        union.absorb(run.dir)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        with gen.open("ab") as fh:
            fh.write(b"{not json\n[]\n" + json.dumps({"kind": "subdomain", "record": {"no": "key"}}).encode()
                     + b"\n")
        reopened = campaign.Union(union.path)
        assert set(reopened.records) == {("subdomain", "a.acme.com")}
        assert (reopened.status, reopened.dropped, reopened.trustworthy) == ("degraded", 3, False)


class TestBootstrappingTheNextChild:
    def test_a_child_STARTS_from_what_the_campaign_knows(self, tmp_path):
        """The P0 this exists for: with acquisition closed, provider-found hosts would otherwise be absent
        from the next child's corpus and the campaign would call that a fixed point."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["shodan"],
                                                   "raw_ref": "/runs/1/raw/shodan.json"}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        assert child.values("subdomain") == []                      # run-scoped: it starts EMPTY
        assert union.bootstrap(child) == {"subdomain": 1}
        assert child.values("subdomain") == ["a.acme.com"]
        seeded = child.read("subdomain")[0]
        assert seeded["sources"] == ["shodan"], seeded              # provenance INTACT
        assert seeded["raw_ref"] == "/runs/1/raw/shodan.json", seeded
        assert seeded[campaign.INHERITED] is True, seeded

    def test_an_INHERITED_entity_is_not_the_child_s_discovery(self, tmp_path):
        """`add()`'s NEW-key answer is what phases count as production. An entity the campaign handed over
        must never answer yes, or every child would report the whole union as its own find."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        assert child.add("subdomain", {"host": "a.acme.com", "sources": ["httpx"]}) is False
        assert child.add("subdomain", {"host": "new.acme.com", "sources": ["httpx"]}) is True

    def test_bootstrapping_TWICE_writes_nothing_the_second_time(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        assert union.bootstrap(child) == {"subdomain": 1}
        before = (child.normalized / "subdomain.jsonl").read_text()
        assert union.bootstrap(child) == {}
        assert (child.normalized / "subdomain.jsonl").read_text() == before

    def test_an_inherited_record_FINGERPRINTS_like_its_origin(self, tmp_path):
        """`_inherited` is bookkeeping about how this run got the entity, never a fact about the world."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        origin = union.records[("subdomain", "a.acme.com")]
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        seeded = child.read("subdomain")[0]
        assert store.fingerprint("subdomain", seeded) == store.fingerprint("subdomain", origin)

    def test_a_bootstrapped_child_can_be_absorbed_back_without_inventing_progress(self, tmp_path):
        """The round trip the supervisor will do every cycle: seed, run, absorb. What was handed over must
        not come back as discovery."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        child.add("subdomain", {"host": "found.acme.com", "sources": ["httpx"]})
        child.write_manifest(profile_summary={}, phases_run=["vertical"])
        result = union.absorb(child.dir, kinds=["subdomain"])
        assert (result.new, result.progressed) == (1, True), result       # ONLY the new host
        assert result.enriched == 0, result
        assert set(k for _kind, k in union.records) == {"a.acme.com", "found.acme.com"}

    def test_a_child_that_found_NOTHING_new_shows_no_progress(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        child.write_manifest(profile_summary={}, phases_run=["vertical"])
        result = union.absorb(child.dir, kinds=["subdomain"])
        assert not result.progressed and (result.new, result.enriched) == (0, 0), result


class TestTheUnionIsDurable:
    def test_it_reloads_exactly(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}),
                        ("live", {"url": "https://a.acme.com/", "title": "T"}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(run.dir)
        reopened = campaign.Union(union.path)
        assert set(reopened.records) == set(union.records)
        for slot, rec in union.records.items():
            assert store.fingerprint(slot[0], reopened.records[slot]) == store.fingerprint(slot[0], rec)

    def test_every_row_carries_its_kind_identity_and_fingerprint(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(run.dir)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        row = json.loads(gen.read_text().splitlines()[0])
        assert row["kind"] == "subdomain" and row["id"] == "a.acme.com"
        assert row["fp"] == store.fingerprint("subdomain", row["record"])


class TestTheUnionCarriesItsOwnTrust:
    """The union is the campaign's memory. A deleted, truncated or tampered one would hand the next child
    LESS than the campaign knows, and the difference would come back as a fixed point."""

    def _union(self, tmp_path, hosts=("a.acme.com", "b.acme.com")):
        run = _finished(tmp_path, *[("subdomain", {"host": h, "sources": ["crtsh"]}) for h in hosts])
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        union.absorb(run.dir)
        return union

    def test_a_NEW_union_must_be_asked_for(self, tmp_path):
        """Absence is only "nothing known yet" when someone said so; otherwise it is evidence gone."""
        made = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        assert (made.status, made.trustworthy, made.records) == ("new", True, {})
        opened = campaign.Union.for_campaign(tmp_path, "c2")
        assert (opened.status, opened.trustworthy) == ("unusable", False), opened

    def test_a_saved_union_reopens_VALID(self, tmp_path):
        union = self._union(tmp_path)
        reopened = campaign.Union(union.path)
        assert (reopened.status, len(reopened.records)) == ("valid", 2), reopened.reason

    def test_a_TRUNCATED_union_is_caught_by_its_metadata(self, tmp_path):
        """Cut on a line boundary: every remaining row parses and verifies, and only the recorded count and
        digest can tell that half the campaign's memory is gone."""
        union = self._union(tmp_path)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text(gen.read_text().splitlines()[0] + "\n")
        reopened = campaign.Union(union.path)
        assert reopened.status == "degraded" and not reopened.trustworthy, reopened
        assert "records 2" in reopened.reason and len(reopened.records) == 1

    def test_a_SAME_COUNT_rewrite_is_caught_by_the_digest(self, tmp_path):
        """Swap one record for another, keeping the count: only the published digest can tell."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        gen = union.dir / json.loads(union.path.read_text())["file"]
        rec = {"host": "planted.acme.com", "sources": ["crtsh"]}
        gen.write_text(json.dumps({"kind": "subdomain", "id": "planted.acme.com", "record": rec,
                                   "fp": store.fingerprint("subdomain", rec)}) + "\n")
        reopened = campaign.Union(union.path)
        assert reopened.dropped == 0 and len(reopened.records) == 1     # every row verifies on its own
        assert reopened.status == "degraded" and "changed since it was published" in reopened.reason

    def test_a_TAMPERED_record_is_dropped_by_its_fingerprint(self, tmp_path):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        gen = union.dir / json.loads(union.path.read_text())["file"]
        row = json.loads(gen.read_text().splitlines()[0])
        row["record"]["sources"] = ["planted"]                    # content changed, `fp` not recomputed
        gen.write_text(json.dumps(row) + "\n")
        reopened = campaign.Union(union.path)
        assert reopened.status == "degraded" and reopened.dropped == 1, reopened
        assert reopened.records == {}, reopened.records

    def test_a_row_whose_ID_does_not_match_its_record_is_dropped(self, tmp_path):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        gen = union.dir / json.loads(union.path.read_text())["file"]
        row = json.loads(gen.read_text().splitlines()[0])
        row["id"] = "somewhere.else.com"
        gen.write_text(json.dumps(row) + "\n")
        assert campaign.Union(union.path).dropped == 1

    def test_an_UNREGISTERED_kind_is_not_an_entity(self, tmp_path):
        """The closed registry rejects an invented kind before keying, and a planted union row is dropped."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        rec = {"value": "whatever"}
        row = {"kind": "not_an_entity", "id": "whatever", "record": rec,
               "fp": "planted"}
        with pytest.raises(ContractError, match="unknown entity"):
            store.canonical_key("not_an_entity", rec)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text(json.dumps(row) + "\n")
        reopened = campaign.Union(union.path)
        assert reopened.dropped == 1 and reopened.records == {}, reopened

    def test_absorb_rejects_every_requested_kind_before_reading_the_child(self, tmp_path, monkeypatch):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        monkeypatch.setattr(campaign._revision, "view_identity",
                            lambda _path: pytest.fail("child view was read before kinds were validated"))
        with pytest.raises(ContractError, match="unknown entity"):
            union.absorb(tmp_path / "recon" / "never-read", kinds=["subdomain", "invented"])

    def test_absorb_refuses_a_run_path_outside_the_campaign_project(self, tmp_path, monkeypatch):
        outside = _finished(tmp_path / "outside", ("subdomain", {"host": "outside.example"}))
        union = self._union(tmp_path, hosts=("a.acme.com",))
        monkeypatch.setattr(campaign._revision, "view_identity",
                            lambda _path: pytest.fail("external child view was read"))

        with pytest.raises(ContractError, match="outside this campaign's project"):
            union.absorb(outside.dir)

    def test_absorb_refuses_a_symlinked_child_run_before_view_reads(self, tmp_path, monkeypatch):
        outside = _finished(tmp_path / "outside", ("subdomain", {"host": "outside.example"}))
        union = self._union(tmp_path, hosts=("a.acme.com",))
        child = tmp_path / "recon" / outside.run_id
        child.symlink_to(outside.dir, target_is_directory=True)
        monkeypatch.setattr(campaign._revision, "view_identity",
                            lambda _path: pytest.fail("symlinked child view was read"))

        with pytest.raises(ContractError, match="not a safe real directory"):
            union.absorb(child)

    def test_a_union_with_NO_POINTER_is_unusable(self, tmp_path):
        """The generations survive, but nothing says which one is the campaign — and a supervisor may not
        pick for itself."""
        union = self._union(tmp_path)
        union.path.unlink()
        reopened = campaign.Union(union.path)
        assert (reopened.status, reopened.trustworthy, reopened.records) == ("unusable", False, {})
        assert union.dir.glob("union-gen*.jsonl")

    def test_an_untrustworthy_union_REFUSES_to_bootstrap_or_absorb(self, tmp_path):
        """Refusing loudly is the only answer that cannot be mistaken for progress."""
        union = self._union(tmp_path)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text(gen.read_text().splitlines()[0] + "\n")
        broken = campaign.Union(union.path)
        child = store.Run.create(tmp_path, "t")
        with pytest.raises(campaign.UnionUnusable):
            broken.bootstrap(child)
        with pytest.raises(campaign.UnionUnusable):
            broken.absorb(child.dir)
        assert child.values("subdomain") == []               # ...and nothing was seeded on the way out

    def test_save_REFUSES_to_certify_a_degraded_union(self, tmp_path):
        """The false-fixed-point path in its purest form: truncate, republish the survivors, and the
        campaign reappears as a smaller healthy one. Ordinary publication may not launder a loss."""
        union = self._union(tmp_path)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text("")                                        # every record gone, cleanly
        broken = campaign.Union(union.path)
        assert broken.status == "degraded" and broken.records == {}
        with pytest.raises(campaign.UnionUnusable):
            broken.save()
        assert campaign.Union(union.path).status == "degraded"    # ...and nothing was rewritten

    def test_RECOVERY_is_explicit_and_states_the_loss(self, tmp_path):
        union = self._union(tmp_path)
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text("")
        broken = campaign.Union(union.path)
        with pytest.raises(ValueError):
            broken.recover("")                                    # a recovery must say what was lost
        broken.recover("generation truncated to zero records")
        pointer = json.loads(union.path.read_text())
        assert [r["reason"] for r in pointer["recoveries"]] == ["generation truncated to zero records"]
        assert campaign.Union(union.path).status == "valid"

    def test_a_RECOVERY_survives_every_later_publication(self, tmp_path):
        """The campaign's only durable admission that evidence was lost. Recorded in the pointer that made
        the recovery and nowhere else, it would vanish on the next ordinary save — and a later supervisor
        would see a healthy union and declare completion over a corpus that had been rebuilt."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text("")
        broken = campaign.Union(union.path)
        broken.recover("lost one entity")
        assert broken.was_recovered and len(broken.recoveries) == 1, broken.recoveries

        run = _finished(tmp_path, ("subdomain", {"host": "b.acme.com", "sources": ["crtsh"]}))
        broken.absorb(run.dir, kinds=["subdomain"])               # an ORDINARY publication
        pointer = json.loads(union.path.read_text())
        assert pointer["generation"] == 3, pointer
        assert [r["reason"] for r in pointer["recoveries"]] == ["lost one entity"], pointer
        reopened = campaign.Union(union.path)
        assert reopened.was_recovered and reopened.recoveries[0]["generation"] == 2, reopened.recoveries

    def test_recoveries_ACCUMULATE(self, tmp_path):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        for n, why in ((1, "first loss"), (2, "second loss")):
            gen = union.dir / json.loads(union.path.read_text())["file"]
            gen.write_text("")
            broken = campaign.Union(union.path)
            broken.recover(why)
        assert [r["reason"] for r in campaign.Union(union.path).recoveries] == ["first loss", "second loss"]

    _STAMP = "2026-08-02T14:10:33.442233+00:00"

    @pytest.mark.parametrize("history", [
        "not a list", [None],
        [{"reason": "x", "at": _STAMP}],                                   # no generation
        [{"generation": 0, "reason": "x", "at": _STAMP}],                  # not a generation
        [{"generation": True, "reason": "x", "at": _STAMP}],               # a bool is not an int
        [{"generation": 1, "reason": "", "at": _STAMP}],                   # no reason given
        [{"generation": 1, "reason": "x"}],                                # no timestamp
        [{"generation": 1, "reason": "x", "at": ""}],                      # ...an empty one
        [{"generation": 1, "reason": "x", "at": "nonsense"}],              # ...an unparseable one
        [{"generation": 1, "reason": "x", "at": "2026-08-02T14:10:33"}],   # ...a NAIVE one
        [{"generation": 1, "reason": "x", "at": _STAMP, "extra": 1}],      # an unaccounted key
        [{"generation": 1, "reason": "x", "at": _STAMP},
         {"generation": 1, "reason": "y", "at": _STAMP}],                  # duplicate generations
        [{"generation": 2, "reason": "x", "at": _STAMP},
         {"generation": 1, "reason": "y", "at": _STAMP}],                  # descending
        [{"generation": 999, "reason": "x", "at": _STAMP}],                # from a generation never reached
    ])
    def test_an_UNREADABLE_recovery_history_makes_the_union_unusable(self, tmp_path, history):
        """If we cannot read the campaign's admission that evidence was lost, we cannot certify the corpus
        it describes."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        pointer = json.loads(union.path.read_text())
        pointer["recoveries"] = history
        union.path.write_text(json.dumps(pointer))
        reopened = campaign.Union(union.path)
        assert (reopened.status, reopened.trustworthy) == ("unusable", False), (history, reopened)
        assert "recovery history" in reopened.reason, reopened


    def test_CREATE_refuses_over_an_existing_campaign(self, tmp_path):
        """A deleted pointer beside its generations is evidence loss, not a new campaign."""
        union = self._union(tmp_path)
        union.path.unlink()
        orphaned = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        assert (orphaned.status, orphaned.trustworthy) == ("unusable", False), orphaned
        assert "existing generation" in orphaned.reason, orphaned

    def test_a_PUBLICATION_is_one_pointer_swap(self, tmp_path):
        """Two files written separately are not one publication. The generation is written COMPLETE first,
        so an interruption before the pointer lands leaves the PREVIOUS generation as what the campaign
        reads — never a corpus described by someone else's metadata."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        first_pointer = json.loads(union.path.read_text())
        run = _finished(tmp_path, ("subdomain", {"host": "b.acme.com", "sources": ["crtsh"]}))
        union.records[("subdomain", "b.acme.com")] = {"host": "b.acme.com", "sources": ["crtsh"]}
        union._publish()
        second = json.loads(union.path.read_text())
        assert second["generation"] == first_pointer["generation"] + 1, (first_pointer, second)
        assert second["file"] != first_pointer["file"]
        # the earlier generation is still on disk: a failed swap costs nothing
        assert (union.dir / first_pointer["file"]).exists()
        assert campaign.Union(union.path).status == "valid"

    def test_an_interrupted_swap_leaves_the_PREVIOUS_generation_readable(self, tmp_path):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        before = json.loads(union.path.read_text())
        union.records[("subdomain", "b.acme.com")] = {"host": "b.acme.com", "sources": ["crtsh"]}
        # write the next generation, then die before the pointer swap
        body = "\n".join(json.dumps({"kind": k, "id": key, "record": r,
                                     "fp": store.fingerprint(k, r)})
                         for (k, key), r in sorted(union.records.items())) + "\n"
        (union.dir / "union-gen000099.jsonl").write_text(body)
        reopened = campaign.Union(union.path)
        assert reopened.status == "valid" and set(reopened.records) == {("subdomain", "a.acme.com")}
        assert json.loads(union.path.read_text()) == before

    def test_a_FAILED_publication_absorbs_nothing(self, tmp_path):
        """`absorb` must not leave records in memory that no disk holds — a bootstrap would then seed a
        child from a corpus that was never committed."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        run = _finished(tmp_path, ("subdomain", {"host": "new.acme.com", "sources": ["crtsh"]}))

        def _boom(path, text):
            raise OSError("read-only campaign directory")

        import unittest.mock as _m
        with _m.patch.object(store, "_atomic_write", _boom):
            result = union.absorb(run.dir, kinds=["subdomain"])
        assert not result.absorbed and not result.progressed, result
        assert result.unusable["__union__"], result
        assert set(union.records) == {("subdomain", "a.acme.com")}, union.records
        # ...and the object now holds exactly what the pointer holds, so seeding from it is still correct:
        # the PUBLISHED corpus, never the one this absorb hoped to add
        child = store.Run.create(tmp_path, "t")
        assert union.bootstrap(child) == {"subdomain": 1}
        assert child.values("subdomain") == ["a.acme.com"]
        assert campaign.Union(union.path).status == "valid"      # the disk still holds the old generation


    @pytest.mark.parametrize("gen", [True, False, 0, -1, 1.0, "1", None, [1]])
    def test_a_MALFORMED_generation_makes_the_pointer_unusable(self, tmp_path, gen):
        """The generation is IDENTITY. Defaulting a malformed one to 0 let the next publication write
        `union-gen000001.jsonl` — over the generation the pointer still names, destroying the authoritative
        corpus before the swap meant to replace it."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        pointer = json.loads(union.path.read_text())
        pointer["generation"] = gen
        union.path.write_text(json.dumps(pointer))
        reopened = campaign.Union(union.path)
        assert (reopened.status, reopened.trustworthy) == ("unusable", False), (gen, reopened)
        assert "identify a generation" in reopened.reason, reopened

    @pytest.mark.parametrize("name", ["../escape.jsonl", "union-gen000002.jsonl", "/etc/passwd",
                                      "sub/union-gen000001.jsonl", "union-gen1.jsonl"])
    def test_the_FILE_must_be_the_name_the_generation_implies(self, tmp_path, name):
        """Deriving the filename rather than trusting the pointer's string is what keeps a generation
        inside its own campaign directory."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        pointer = json.loads(union.path.read_text())
        pointer["file"] = name
        union.path.write_text(json.dumps(pointer))
        assert campaign.Union(union.path).status == "unusable", name

    def test_a_CANCELLED_publication_leaves_the_object_holding_what_the_DISK_holds(self, tmp_path):
        """A rollback that only caught `OSError` left a cancelled publication with `valid` status and
        records no disk held — the next bootstrap would seed a child from them."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        published = dict(union.records)
        union.records[("subdomain", "ghost.acme.com")] = {"host": "ghost.acme.com", "sources": ["x"]}

        import unittest.mock as _m
        with _m.patch.object(store, "_atomic_write", side_effect=GeneratorExit("cancelled")):
            with pytest.raises(GeneratorExit):
                union._publish()
        assert union.records == published, union.records          # the ghost is gone
        assert union.status == "valid" and union.generation == 1, union
        assert campaign.Union(union.path).records == published

    def test_a_cancelled_ABSORB_re_raises_and_settles(self, tmp_path):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        published = dict(union.records)
        run = _finished(tmp_path, ("subdomain", {"host": "new.acme.com", "sources": ["crtsh"]}))
        import unittest.mock as _m
        with _m.patch.object(store, "_atomic_write", side_effect=KeyboardInterrupt("ctrl-c")):
            with pytest.raises(KeyboardInterrupt):
                union.absorb(run.dir, kinds=["subdomain"])
        assert union.records == published, union.records
        assert campaign.Union(union.path).records == published

    def test_a_failure_in_PREPARATION_settles_too(self, tmp_path):
        """Serialisation, fingerprinting and the generation choice all happen after the caller mutated the
        records — a raise there would otherwise leave the object `valid` holding an unpublished record."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        published = dict(union.records)
        union.records[("subdomain", "ghost.acme.com")] = {"host": "ghost.acme.com", "sources": ["x"]}
        real, calls = store.fingerprint, {"n": 0}

        def flaky(kind, rec):
            calls["n"] += 1
            if calls["n"] == 1:                       # fails while PREPARING, recovers for the re-read
                raise RuntimeError("boom")
            return real(kind, rec)

        import unittest.mock as _m
        with _m.patch.object(store, "fingerprint", flaky):
            with pytest.raises(RuntimeError):
                union._publish()
        assert union.records == published and union.status == "valid", union.records
        assert campaign.Union(union.path).records == published

    def test_when_SETTLING_also_fails_the_union_says_so(self, tmp_path):
        """The original failure still propagates — but the object may not keep claiming to be valid."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        union.records[("subdomain", "ghost.acme.com")] = {"host": "ghost.acme.com", "sources": ["x"]}
        import unittest.mock as _m
        with _m.patch.object(store, "fingerprint", side_effect=RuntimeError("boom everywhere")):
            with pytest.raises(RuntimeError, match="boom everywhere"):
                union._publish()
        assert union.status == "unusable" and not union.trustworthy, union
        assert "could not be re-read" in union.reason, union

    def test_RECOVERY_never_overwrites_a_surviving_generation(self, tmp_path):
        """A malformed pointer leaves `generation = 0`, and `+1` would publish OVER the generation that
        still holds the campaign's only copy of its evidence."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        gen_one = union.dir / "union-gen000001.jsonl"
        before = gen_one.read_text()
        pointer = json.loads(union.path.read_text())
        pointer["generation"] = "not a generation"
        union.path.write_text(json.dumps(pointer))
        broken = campaign.Union(union.path)
        assert broken.status == "unusable" and broken.generation == 0
        broken.recover("pointer generation was malformed")
        assert gen_one.read_text() == before, "the surviving generation was overwritten"
        assert broken.generation == 2 and json.loads(union.path.read_text())["generation"] == 2

    def test_publication_refuses_when_the_next_generation_NAME_is_taken(self, tmp_path):
        """The scan counts generation FILES, so something else wearing that name — a directory, say — is
        invisible to it. Publishing anyway would replace or fail over whatever is there."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        (union.dir / "union-gen000002.jsonl").mkdir()
        published = dict(union.records)
        union.records[("subdomain", "b.acme.com")] = {"host": "b.acme.com", "sources": ["x"]}
        with pytest.raises(OSError, match="already exists"):
            union._publish()
        assert union.records == published, union.records
        assert campaign.Union(union.path).generation == 1

    def test_an_UNINSPECTABLE_directory_is_never_a_new_campaign(self, tmp_path):
        """"I could not look" must never be mistaken for "nothing is here"."""
        import unittest.mock as _m
        with _m.patch.object(pathlib.Path, "glob", side_effect=PermissionError("denied")):
            union = campaign.Union.for_campaign(tmp_path, "c9", create=True)
        assert (union.status, union.trustworthy) == ("unusable", False), union
        assert "could not be inspected" in union.reason, union

    def test_publication_REFUSES_when_the_directory_cannot_be_inspected(self, tmp_path):
        union = self._union(tmp_path, hosts=("a.acme.com",))
        published = dict(union.records)
        union.records[("subdomain", "b.acme.com")] = {"host": "b.acme.com", "sources": ["x"]}
        import unittest.mock as _m
        with _m.patch.object(pathlib.Path, "glob", side_effect=PermissionError("denied")):
            with pytest.raises(OSError):
                union._publish()
        assert union.records == published, union.records

    def test_a_publication_that_LANDED_before_the_interruption_is_adopted(self, tmp_path):
        """The other half: the swap may land a moment before the cancellation. Restoring the old snapshot
        blindly would then discard records the disk DOES hold."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        union.records[("subdomain", "late.acme.com")] = {"host": "late.acme.com", "sources": ["x"]}
        real = store._atomic_write
        calls = {"n": 0}

        def _late(path, text):
            real(path, text)
            calls["n"] += 1
            if calls["n"] == 2:                       # the pointer landed, THEN we are interrupted
                raise GeneratorExit("cancelled after the swap")

        import unittest.mock as _m
        with _m.patch.object(store, "_atomic_write", _late):
            with pytest.raises(GeneratorExit):
                union._publish()
        assert ("subdomain", "late.acme.com") in union.records, union.records
        assert union.status == "valid" and union.generation == 2, union


class TestInheritanceKeepsEveryMaterialFACT:
    def test_conflicting_ALTERNATES_survive_the_bootstrap(self, tmp_path):
        """`_alt` is stripped from CALLER input because an external source could inject it. The campaign
        bootstrap is the TRUSTED path, and prerequisite A treats alternates as material knowledge — a child
        that starts without them starts with less than the campaign holds."""
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        first = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "A"}))
        union.absorb(first.dir)
        second = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "B"}))
        union.absorb(second.dir)
        origin = union.records[("live", "https://a.acme.com/")]
        assert origin["title"] == "A" and origin["_alt"]["title"] == ["B"], origin

        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        seeded = child.read("live")[0]
        assert seeded.get("_alt", {}).get("title") == ["B"], seeded
        assert store.fingerprint("live", seeded) == store.fingerprint("live", origin)

    def test_a_child_that_re_observes_the_alternate_reports_no_progress(self, tmp_path):
        """The point of carrying alternates: the child already holds both, so seeing `B` again is not new."""
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        for title in ("A", "B"):
            union.absorb(_finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": title})).dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        child.add("live", {"url": "https://a.acme.com/", "title": "B"})
        child.write_manifest(profile_summary={}, phases_run=["probe"])
        assert not union.absorb(child.dir, kinds=["live"]).progressed

    def test_ordinary_add_still_STRIPS_caller_supplied_alternates(self, tmp_path):
        """The untrusted path is unchanged: a source cannot inject merge metadata."""
        run = store.Run.create(tmp_path, "t")
        run.add("live", {"url": "https://a.acme.com/", "title": "A", "_alt": {"title": ["planted"]}})
        assert "_alt" not in run.read("live")[0], run.read("live")[0]
