"""The campaign's cumulative store — settle prerequisite C.

Entities are RUN-SCOPED, so a supervisor that repeats runs needs somewhere for what earlier children
learned to live AND must seed every later child from it. These tests pin the invariants the supervisor will
rely on: absorbing only trustworthy evidence, monotonic progress, an idempotent bootstrap, and an inherited
entity that is never counted as the child's own discovery.
"""
from __future__ import annotations

import json

import pytest

from quarry_recon import campaign, store


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

    def test_absorbing_the_SAME_child_twice_adds_nothing(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1", create=True)
        assert union.absorb(run.dir).new == 1
        again = union.absorb(run.dir)
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
        """A row that would key perfectly well under the default field — only the REGISTRY says it is not
        an entity Quarry holds, and a union that accepted it would seed a child with invented kinds."""
        union = self._union(tmp_path, hosts=("a.acme.com",))
        rec = {"value": "whatever"}
        row = {"kind": "not_an_entity", "id": "whatever", "record": rec,
               "fp": store.fingerprint("not_an_entity", rec)}
        assert store.canonical_key("not_an_entity", rec) == "whatever"      # it WOULD key
        gen = union.dir / json.loads(union.path.read_text())["file"]
        gen.write_text(json.dumps(row) + "\n")
        reopened = campaign.Union(union.path)
        assert reopened.dropped == 1 and reopened.records == {}, reopened

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
        assert pointer["recovered"] == "generation truncated to zero records", pointer
        assert campaign.Union(union.path).status == "valid"


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
        with pytest.raises(campaign.UnionUnusable):
            union.bootstrap(store.Run.create(tmp_path, "t"))
        assert campaign.Union(union.path).status == "valid"      # the disk still holds the old generation


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
