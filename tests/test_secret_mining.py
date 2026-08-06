"""What an exposed file actually yields — the FORMATS, not just the filenames.

Backlog item closed here (filed after a range run): four secret formats were DETECTED as files by content
discovery and then mined for nothing, because the miner had no rule that fit their shape. Measured
against the real `evidence.mine` before writing any of it:

    rails config/master.key    NOTHING EXTRACTED   (32 hex chars, no key, no assignment)
    .NET appsettings.json      NOTHING EXTRACTED   (password lives INSIDE a connection string)
    bcrypt hash                NOTHING EXTRACTED   (no rule for the shape)
    laravel .env APP_KEY       already worked      (the note was stale on this one)

A secret Quarry fetched, saved and could not read is a finding it paid for and threw away.
"""
from __future__ import annotations

import re

import pytest

from quarry_recon import evidence


def self_appsettings() -> str:
    return TestSecretsHiddenInsideValues.APPSETTINGS


def kinds(text: str, path: str | None = None) -> dict:
    return {k: v for k, v, _ln in evidence.mine(text, source_path=path)}



def stream_fake(body: bytes = b"", final=None, status: int = 200, complete: bool = True):
    """A fake `fetch.scoped_get_file`: writes `body` to the caller's `dest` and hands back an
    `Acquisition`, exactly as the real one does. The lane reads the ARTIFACT now, so a fake that only
    returns bytes would leave every mining site with an empty file to read (2026-08-06)."""
    import hashlib as _h
    from pathlib import Path as _P
    from quarry_recon import fetch as _f

    def _fake(ctx, url, dest, *a, **k):
        d = _P(dest)
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(body)
        return (_f.Acquisition(d, len(body), _h.sha256(body).hexdigest(), complete),
                url if final is None else final, status)
    return _fake


class TestAFormatClaimNeedsTheFILE:
    """review#1 (Lumpy): 32 lowercase hex is a Rails master key in `config/master.key` and an MD5, a git
    blob id or an ETag everywhere else. The BODY cannot carry that claim, so format rules are gated on
    the source path — and a body with no path is not classified at all."""

    KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

    def test_a_rails_master_key_is_extracted_from_its_own_file(self):
        assert kinds(self.KEY + "\n", "https://t/config/master.key") == {"rails-master-key": self.KEY}

    def test_the_SAME_body_elsewhere_is_not_a_secret(self):
        for path in ("https://t/checksums.txt", "https://t/api/v1/objects/abc", "https://t/index.html"):
            assert kinds(self.KEY + "\n", path) == {}, path

    def test_without_a_path_no_format_rule_fires(self):
        """An unclassified body is not a Rails secret. Silence is the honest answer."""
        assert kinds(self.KEY + "\n") == {}

    def test_a_hash_INSIDE_a_document_is_not_a_key_file(self):
        assert kinds(f"the checksum is {self.KEY} for that file", "https://t/config/master.key") == {}
        assert kinds(f'{{"etag": "{self.KEY}"}}', "https://t/config/master.key") == {}

    def test_surrounding_whitespace_does_not_hide_it(self):
        assert "rails-master-key" in kinds(f"\n  {self.KEY}  \n", "https://t/config/master.key")

    def test_there_is_no_unnamed_generic_hex_rule(self):
        """review#3: a whole-body 64-hex "key" had no named format, no expected path and no way to tell a
        key from a checksum. A rule with nothing behind it does not belong in the miner."""
        body = "0" * 63 + "f"
        assert kinds(body, "https://t/config/master.key") == {}
        assert not any(kind == "hex-key-64" for kind, *_ in evidence.mine(body, source_path="/x"))
        assert len(evidence._FORMAT_RULES) == 1, "every format rule names a file format"


class TestSecretsHiddenInsideValues:
    """.NET writes the password INSIDE a connection string, under a key like `DefaultConnection` that no
    secret-ish KEY pattern will ever match."""

    APPSETTINGS = ('{"ConnectionStrings":{"DefaultConnection":'
                   '"Server=db;Database=app;User Id=sa;Password=P@ssw0rd123;"},'
                   '"Jwt":{"Key":"super-secret-signing-value-1234"}}')

    def test_a_connection_string_password_is_extracted(self):
        assert kinds(self.APPSETTINGS)["connection-string-password"] == "P@ssw0rd123"

    def test_a_bare_password_assignment_is_NOT_called_a_database_credential(self):
        """review#6 (Lumpy): `password=` appears in documentation, examples, query strings and prose.
        Calling those database credentials is a claim we cannot support, so the match requires
        connection-string STRUCTURE around it."""
        for text in ("to log in, use password=changeme in the form",
                     "GET /login?user=bob&password=hunter2 HTTP/1.1",
                     "# example: password=YOUR_PASSWORD_HERE"):
            assert "connection-string-password" not in kinds(text), text

    def test_a_bare_Key_field_is_a_secret_IN_THAT_FORMAT(self):
        """`appsettings.json` is where .NET writes the symmetric signing secret. The same body from an
        unknown path is signing CONTEXT only — see `TestTheBareKeyRuleNeedsContextToo`."""
        got = kinds(self.APPSETTINGS, "https://t/appsettings.json")
        assert got["json:Key"] == "super-secret-signing-value-1234"
        assert kinds(self.APPSETTINGS)["signing-key"] == "super-secret-signing-value-1234"

    def test_a_bare_key_field_with_a_SHORT_value_is_not(self):
        """`"key": "name"` is how a thousand harmless config blocks are written. The value's length is
        what distinguishes a signing secret from an identifier."""
        assert kinds('{"key": "name", "type": "string"}') == {}
        assert kinds('{"key": "id"}') == {}

    def test_an_XML_web_config_connection_string_is_extracted(self):
        xml = ('<connectionStrings><add name="Default" '
               'connectionString="Data Source=.;Initial Catalog=app;User ID=sa;Password=Sup3rS3cret" />'
               '</connectionStrings>')
        assert kinds(xml)["connection-string-password"] == "Sup3rS3cret"

    def test_a_masked_value_is_not_reported_as_a_secret(self):
        assert kinds('{"db.password": "******"}') == {}


class TestPasswordHashes:
    """A hash is not a password, and it is still evidence: it proves the store leaked and it is
    offline-crackable. review#2 (Lumpy): it must therefore NOT be published as a recovered secret."""

    HASH = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

    def test_a_bcrypt_hash_is_extracted(self):
        assert kinds(f"admin:{self.HASH}\n")["bcrypt-hash"] == self.HASH

    def test_every_bcrypt_variant_is_recognised(self):
        for prefix in ("$2a$", "$2b$", "$2x$", "$2y$"):
            body = prefix + "12$" + self.HASH.split("$", 3)[3]
            assert "bcrypt-hash" in kinds(body), prefix

    def test_a_dollar_string_that_is_not_bcrypt_is_ignored(self):
        assert kinds("$2y$10$tooshort") == {}
        assert kinds("price is $2 and $10 today") == {}


class TestTheKnownGoodPathsStillWork:
    def test_laravel_APP_KEY(self):
        got = kinds("APP_NAME=Laravel\nAPP_KEY=base64:Yi9kZk9wVGhpc0lzQVJlYWxLZXk=\nAPP_DEBUG=true\n")
        assert got["dotenv:APP_KEY"] == "base64:Yi9kZk9wVGhpc0lzQVJlYWxLZXk="

    def test_a_provider_token_still_wins_over_the_generic_rule(self):
        got = evidence.mine("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        assert ("aws-access-key", "AKIAIOSFODNN7EXAMPLE", 1) in got

    def test_a_value_containing_a_HASH_is_not_dropped(self):
        """Measured 2026-08-05: the value pattern excluded `#`, so a password containing one yielded
        NOTHING — not a truncated value, no value at all. Quoted values keep it; a bare value keeps it
        too unless it starts an inline comment, which needs preceding whitespace."""
        assert kinds("API_SECRET=\"a#b#c#dddd\"\n")["dotenv:API_SECRET"] == "a#b#c#dddd"
        assert kinds("DB_PASSWORD=abc#notcomment\n")["dotenv:DB_PASSWORD"] == "abc#notcomment"
        assert kinds("DB_PASSWORD=hunter2hunter2   # the prod one\n")["dotenv:DB_PASSWORD"] \
            == "hunter2hunter2"

    def test_values_are_kept_VERBATIM(self):
        """A discovered secret is bounty evidence: never masked, never truncated, never rewritten. Only
        Quarry's OWN configured credentials are redacted, and that happens at the telemetry sink."""
        raw = "P@ss w/ spaces & symbols!#$%^&*()_+-=[]{}|;:,.<>?"
        got = kinds(f"DB_PASSWORD='{raw}'\n")
        assert got["dotenv:DB_PASSWORD"] == raw


class TestWhatWeFETCHIsWhatWeCanMINE:
    """The gap class this closes: content discovery probed these paths, the fetcher did not recognise
    them as sensitive, and nothing was ever mined from them."""

    def test_the_new_formats_are_fetched_as_sensitive_files(self):
        for path in ("/config/master.key", "/appsettings.json", "/appsettings.Production.json",
                     "/web.config", "/config/credentials.yml.enc"):
            assert evidence.SENSITIVE_FILE_RX.search(path), path

    def test_probing_a_path_is_not_a_sensitivity_claim(self):
        """review#5 (Lumpy): discovery wordlists carry paths worth COLLECTING for many reasons —
        metadata, debugging, technology identification. Membership establishes collection interest, not
        evidence classification, so the fetcher keeps its own explicit list."""
        from pathlib import Path
        import quarry_recon
        words = (Path(quarry_recon.__file__).parent / "data" / "content-configleak.txt").read_text()
        probed = [w.strip() for w in words.splitlines() if w.strip() and not w.startswith("#")]
        assert probed, "the wordlist is not empty"
        assert any(not evidence.SENSITIVE_FILE_RX.search("/" + w) for w in probed), \
            "not everything we probe is a secret store — and the fetcher must not assume it is"

    def test_the_named_formats_map_to_their_expected_evidence(self):
        """The mapping, stated explicitly rather than derived from a wordlist."""
        expect = {
            "https://t/config/master.key": "rails-master-key",     # the file IS the key
            "https://t/appsettings.json": "connection-string-password",
        }
        bodies = {"https://t/config/master.key": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
                  "https://t/appsettings.json": self_appsettings()}
        for url, kind in expect.items():
            assert evidence.SENSITIVE_FILE_RX.search("/" + url.split("/", 3)[3]), url
            assert kind in kinds(bodies[url], url), (url, kind)

    def test_ordinary_pages_are_still_not_sensitive_files(self):
        for path in ("/index.html", "/about", "/static/app.js", "/api/v1/users"):
            assert not evidence.SENSITIVE_FILE_RX.search(path), path


class TestAHashIsNotARecoveredCredential:
    """review#2 (Lumpy): every mined kind was added as a `secret`, so a bcrypt hash entered the secret
    queues, counters and reports as though Quarry had recovered a password. Five call sites each decided
    that separately — which is how four of them got it wrong."""

    @staticmethod
    def _ctx():
        from types import SimpleNamespace
        added: list = []
        run = SimpleNamespace(add=lambda kind, rec: (added.append((kind, rec)), True)[1])
        return SimpleNamespace(run=run), added

    HASH = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

    def test_a_hash_goes_to_REVIEW_not_to_the_secret_queue(self):
        ctx, added = self._ctx()
        got = evidence.publish_finding(ctx, "bcrypt-hash", self.HASH, 3, url="https://t/dump.sql",
                                       dest="/raw/x", source="exposed-fetch")
        assert got == "hash"
        kind, rec = added[0]
        assert kind == "review" and rec["klass"] == "credential-hash"
        assert rec["value"] == self.HASH, "the COMPLETE hash is retained"
        assert "NOT the password" in rec["note"]
        assert rec["raw_ref"] == "/raw/x" and rec["location"] == "https://t/dump.sql"

    def test_a_real_secret_still_goes_to_the_secret_queue(self):
        ctx, added = self._ctx()
        got = evidence.publish_finding(ctx, "aws-access-key", "AKIAIOSFODNN7EXAMPLE", 1,
                                       url="https://t/.env", dest="/raw/y", source="exposed-fetch")
        assert got == "secret" and added[0][0] == "secret"

    def test_EVERY_call_site_routes_through_the_same_decision(self):
        """One place decides what a kind IS. Five call sites deciding separately is the defect."""
        import inspect
        src = inspect.getsource(evidence)
        body = src[src.index("def publish_finding"):]
        after = body[body.index("def fetch_and_extract"):]
        assert 'add("secret"' not in after, "a call site is publishing secrets on its own again"
        # sites now reach the router either directly or through `_mine_file` (which scans an artifact of
        # any size in windows and calls it per match). Both are the SAME decision point; what must never
        # come back is a site that publishes a secret itself, asserted above.
        assert src.count("publish_finding(ctx") + src.count("_mine_file(ctx") >= 5, \
            "every mining site goes through the router"


class TestEncryptedStoresAreNotMinedSecrets:
    """review#4 (Lumpy): `credentials.yml.enc` is worth fetching and preserving — it IS the credential
    store — but it is ciphertext. Reporting it as "fetched; no secret pattern" says "nothing here"; it is
    an exposed encrypted store, and it becomes plaintext the moment its key leaks."""

    def test_the_encrypted_store_is_recognised(self):
        for path in ("/config/credentials.yml.enc", "/config/credentials.production.yml.enc",
                     "/config/secrets.yml.enc"):
            assert evidence.ENCRYPTED_STORE_RX.search(path), path

    def test_an_ordinary_yaml_is_not(self):
        for path in ("/config/database.yml", "/credentials.yml", "/app.enc.js"):
            assert not evidence.ENCRYPTED_STORE_RX.search(path), path

    def test_it_is_still_fetched_as_a_sensitive_file(self):
        assert evidence.SENSITIVE_FILE_RX.search("/config/credentials.yml.enc")

    def test_mining_ciphertext_claims_nothing(self):
        assert kinds("\x00\x01binary-ciphertext-garbage\x02", "https://t/config/credentials.yml.enc") == {}

    def test_the_REVIEW_note_says_it_is_encrypted(self, tmp_path, monkeypatch):
        """The note is what an operator reads. "fetched; no secret pattern" over a credential store is
        technically true and actively misleading."""
        from types import SimpleNamespace
        from quarry_recon import fetch
        added: list = []
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: (added.append((kind, rec)), True)[1])
        ctx = SimpleNamespace(run=run,
                              scope=SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                                    active_allowed=lambda h: True))
        monkeypatch.setattr(fetch, "scoped_get_file", stream_fake(b"\x00encrypted-blob"))
        evidence.fetch_exposed(ctx, ["https://t/config/credentials.yml.enc"])
        notes = [r["note"] for kind, r in added if kind == "review" and r.get("klass") == "exposure"]
        assert notes, added
        assert "ENCRYPTED credential store" in notes[0], notes
        assert "no secret pattern" not in notes[0]

    def test_an_ordinary_exposed_file_keeps_its_plain_note(self, tmp_path, monkeypatch):
        from types import SimpleNamespace
        from quarry_recon import fetch
        added: list = []
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: (added.append((kind, rec)), True)[1])
        ctx = SimpleNamespace(run=run,
                              scope=SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                                    active_allowed=lambda h: True))
        monkeypatch.setattr(fetch, "scoped_get_file", stream_fake(b"nothing here"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        notes = [r["note"] for kind, r in added if kind == "review" and r.get("klass") == "exposure"]
        assert notes and "no secret pattern" in notes[0], notes


class TestClassificationFollowsWhatANSWERED:
    """review#2 (Lumpy): `scoped_get` follows redirects per hop, so a request for `/config/master.key`
    can be answered by `/checksums.txt`. Classifying on the REQUESTED path calls that body a Rails
    master key. Provenance keeps both — `location` is what we asked for, `final` is what replied."""

    KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

    @staticmethod
    def _ctx(tmp_path):
        from types import SimpleNamespace
        added: list = []
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: (added.append((kind, rec)), True)[1])
        return SimpleNamespace(run=run, scope=SimpleNamespace(
            in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True)), added

    def test_a_redirect_away_from_the_key_path_is_not_a_key(self, tmp_path, monkeypatch):
        from quarry_recon import fetch
        ctx, added = self._ctx(tmp_path)
        monkeypatch.setattr(fetch, "scoped_get_file",
                            stream_fake(self.KEY.encode(), final="https://t/checksums.txt"))
        evidence.fetch_and_extract(ctx, "https://t/config/master.key",
                                   source="exposed-fetch", subdir="exposed")
        assert not [r for kind, r in added if kind == "secret"], added

    def test_the_key_path_answering_itself_still_classifies(self, tmp_path, monkeypatch):
        from quarry_recon import fetch
        ctx, added = self._ctx(tmp_path)
        monkeypatch.setattr(fetch, "scoped_get_file",
                            stream_fake(self.KEY.encode(), final="https://t/config/master.key"))
        evidence.fetch_and_extract(ctx, "https://t/config/master.key",
                                   source="exposed-fetch", subdir="exposed")
        secs = [r for kind, r in added if kind == "secret"]
        assert secs and secs[0]["kind"] == "rails-master-key"

    def test_the_encrypted_store_label_also_follows_the_final_url(self, tmp_path, monkeypatch):
        from quarry_recon import fetch
        ctx, added = self._ctx(tmp_path)
        monkeypatch.setattr(fetch, "scoped_get_file",
                            stream_fake(b"plain page", final="https://t/login"))
        evidence.fetch_exposed(ctx, ["https://t/config/credentials.yml.enc"])
        notes = [r["note"] for kind, r in added if kind == "review" and r.get("klass") == "exposure"]
        assert notes and "ENCRYPTED credential store" not in notes[0], notes

    def test_the_finding_is_attributed_to_the_host_that_ANSWERED(self, tmp_path, monkeypatch):
        """review#1 (Lumpy): an in-scope redirect from `a.example.com/.env` to `b.example.com/real.env`
        puts the credential on b. Recording it against a points the report at the wrong asset."""
        from quarry_recon import fetch
        ctx, added = self._ctx(tmp_path)
        monkeypatch.setattr(fetch, "scoped_get_file",
                            stream_fake(b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
                                        final="https://b.example.com/real.env"))
        evidence.fetch_and_extract(ctx, "https://a.example.com/.env",
                                   source="exposed-fetch", subdir="exposed")
        sec = [r for kind, r in added if kind == "secret"][0]
        assert sec["host"] == "b.example.com", sec
        assert sec["location"] == "https://a.example.com/.env", "…and what we ASKED for is kept"
        assert sec["final"] == "https://b.example.com/real.env"

    def test_a_hash_follows_the_same_attribution(self, tmp_path, monkeypatch):
        from types import SimpleNamespace
        added: list = []
        ctx = SimpleNamespace(run=SimpleNamespace(add=lambda k, r: (added.append((k, r)), True)[1]))
        evidence.publish_finding(ctx, "bcrypt-hash",
                                 "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", 1,
                                 url="https://a.example.com/dump.sql", dest="/raw/x",
                                 source="exposed-fetch", host="a.example.com",
                                 final_url="https://b.example.com/dump.sql")
        assert added[0][1]["host"] == "b.example.com"

    def test_provenance_keeps_BOTH_urls(self, tmp_path, monkeypatch):
        from quarry_recon import fetch
        ctx, added = self._ctx(tmp_path)
        monkeypatch.setattr(fetch, "scoped_get_file",
                            stream_fake(b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", final="https://t/real.env"))
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        sec = [r for kind, r in added if kind == "secret"][0]
        assert sec["location"] == "https://t/.env" and sec["final"] == "https://t/real.env"


class TestTheFindingItselfIsRetained:
    """review#3 (Lumpy): the helper promised the complete value was retained and the entity stored only
    a masked preview. "Grep the raw artifact" is not reporting the secret you found — one artifact can
    hold many values."""

    def test_the_entity_carries_the_COMPLETE_value(self):
        from types import SimpleNamespace
        added: list = []
        ctx = SimpleNamespace(run=SimpleNamespace(add=lambda k, r: (added.append((k, r)), True)[1]))
        raw = "AKIAIOSFODNN7EXAMPLE"
        evidence.publish_finding(ctx, "aws-access-key", raw, 2, url="https://t/.env", dest="/raw/z",
                                 source="exposed-fetch")
        rec = added[0][1]
        assert rec["value"] == raw, "the finding is the value"
        assert rec["preview"] != raw and "…" in rec["preview"], "…and the PREVIEW is what travels"

    def test_report_prose_still_shows_only_the_preview(self):
        """The masked preview is what report lines and digests read; nothing in prose gets the value."""
        import inspect
        from quarry_recon import triage
        src = inspect.getsource(triage)
        assert "s.get('preview', '')" in src or 's.get("preview"' in src
        assert 's.get("value")' not in src.split("secrets")[-1][:400]


class TestTheBareKeyRuleNeedsContextToo:
    """review#1 (Lumpy): `"key": "<20+ chars>"` anywhere made OpenAPI examples, package manifests,
    public ids and ordinary API responses into secrets — the same format-attribution problem already
    fixed for `master.key`."""

    LONG = "super-secret-signing-value-1234"

    def test_a_bare_key_in_an_arbitrary_response_is_not_a_secret(self):
        for path in ("https://t/api/v1/items", "https://t/openapi.json", "https://t/package.json"):
            assert kinds(f'{{"key": "{self.LONG}"}}', path) == {}, path

    def test_the_FORMAT_ALONE_is_no_longer_enough(self):
        """DOCTRINE (review#2): the format says signing secrets CAN live there, not that this key is
        one. It needs the signing context too — see `test_the_format_needs_SIGNING_CONTEXT_too`."""
        for path in ("https://t/appsettings.json", "https://t/appsettings.Production.json"):
            assert kinds(f'{{"key": "{self.LONG}"}}', path) == {}, path

    def test_a_named_signing_parent_is_an_observation_without_the_format(self):
        """DOCTRINE (review#9): a JWT parent says what the key is FOR, not that it is private. A JWKS
        document has the same shape and is published on purpose."""
        got = kinds(f'{{"Jwt": {{"Issuer": "me", "Key": "{self.LONG}"}}}}', "https://t/api/v1/config")
        assert got == {"signing-key": self.LONG}

    def test_an_unrelated_parent_is_not(self):
        assert kinds(f'{{"Pagination": {{"Key": "{self.LONG}"}}}}', "https://t/api/v1/x") == {}

    @pytest.mark.parametrize("parent", ["authorization", "token", "bearer", "auth"])
    def test_an_AUTH_FLAVOURED_word_is_not_a_signing_context(self, parent):
        """review#2 (Lumpy): `{"authorization": {"key": "public-resource-identifier…"}}` is an ordinary
        API response. Only an explicit JWT/signing parent — or a companion signing field — carries the
        claim."""
        assert kinds(f'{{"{parent}": {{"key": "{self.LONG}"}}}}', "https://t/api/v1/x") == {}, parent

    @pytest.mark.parametrize("body", [
        '{{"key": "{v}", "kid": "k1"}}',
        '{{"issuer": "https://idp", "key": "{v}"}}',
        '{{"audience": "api", "key": "{v}"}}',
        '{{"key": "{v}", "kid": "k1", "algorithm": "RS256"}}',
    ])
    def test_signing_CONTEXT_is_an_observation_not_a_secret(self, body):
        """review#9 (Lumpy): `kid`, `issuer`, `audience` and `RS256` accompany PUBLIC verification keys
        as readily as private ones — a JWKS entry is published material by design. It is preserved and
        routed as an observation, not as a leaked credential."""
        assert kinds(body.format(v=self.LONG), "https://t/api/v1/x") == {"signing-key": self.LONG}, body

    @pytest.mark.parametrize("body", [
        '{{"key": "{v}", "algorithm": "HS256"}}',
        '{{"alg": "HS512", "key": "{v}"}}',
        '{{"key": "{v}", "alg": "dir"}}',
    ])
    def test_SYMMETRIC_material_is_a_secret(self, body):
        """A symmetric algorithm means the signing key and the verifying key are the same string, so
        publishing it IS the leak."""
        assert kinds(body.format(v=self.LONG), "https://t/api/v1/x") == {"json:key": self.LONG}, body

    def test_an_ASYMMETRIC_algorithm_stays_an_observation(self):
        for alg in ("RS256", "ES256", "PS384", "EdDSA"):
            body = f'{{"kid": "k9", "key": "{self.LONG}", "alg": "{alg}"}}'
            assert kinds(body, "https://t/api/v1/x") == {"signing-key": self.LONG}, alg

    def test_the_format_needs_SIGNING_CONTEXT_too(self):
        """review#2 (Lumpy): `appsettings.json` also holds cache keys, public ids and nested app config.
        The measured format was a JWT signing-key CONFIG, not every bare `Key` in the file."""
        app = "https://t/appsettings.json"
        assert kinds(f'{{"Jwt": {{"Key": "{self.LONG}"}}}}', app) == {"json:Key": self.LONG}
        assert kinds(f'{{"Cache": {{"Key": "{self.LONG}"}}}}', app) == {}, "a cache key is not a secret"
        assert kinds(f'{{"Key": "{self.LONG}"}}', app) == {}, "…nor a bare top-level Key"

    def test_a_long_public_identifier_is_still_not_a_secret(self):
        assert kinds(f'{{"key": "{self.LONG}", "label": "public"}}', "https://t/api/v1/x") == {}


class TestConnectionStringsRegardlessOfFieldOrder:
    """review#4 (Lumpy): requiring the anchor BEFORE the password missed
    `Password=x;User ID=sa;Server=db;Database=app`, which is a perfectly ordinary connection string."""

    def test_password_first_is_still_a_connection_string(self):
        got = kinds('cs = "Password=Sup3rS3cret;User ID=sa;Server=db;Database=app"')
        assert got["connection-string-password"] == "Sup3rS3cret"

    def test_password_last_still_works(self):
        got = kinds('cs = "Server=db;Database=app;User Id=sa;Password=Sup3rS3cret"')
        assert got["connection-string-password"] == "Sup3rS3cret"

    def test_a_semicolon_list_with_no_connection_anchor_is_not_one(self):
        assert kinds('note = "password=changeme;remember=false;theme=dark"') == {}


class TestSigningObservationsAreRouted:
    """A key in signing context is preserved with its provenance and does NOT enter the secret queue."""

    @staticmethod
    def _ctx():
        from types import SimpleNamespace
        added: list = []
        return SimpleNamespace(run=SimpleNamespace(
            add=lambda k, r: (added.append((k, r)), True)[1])), added

    def test_it_goes_to_review_as_a_signing_key(self):
        ctx, added = self._ctx()
        got = evidence.publish_finding(ctx, "signing-key", "public-material-1234567890", 4,
                                       url="https://t/.well-known/jwks.json", dest="/raw/j",
                                       source="exposed-fetch")
        assert got == "observation"
        kind, rec = added[0]
        assert kind == "review" and rec["klass"] == "signing-key"
        assert rec["value"] == "public-material-1234567890", "kept whole"
        assert "not evidence of a leaked secret" in rec["note"]

    def test_it_is_not_counted_as_a_secret(self, tmp_path, monkeypatch):
        from quarry_recon import fetch
        from types import SimpleNamespace
        added: list = []
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: (added.append((kind, rec)), True)[1])
        ctx = SimpleNamespace(run=run, scope=SimpleNamespace(
            in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True))
        body = b'{"key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "kid": "k1", "alg": "RS256"}'
        monkeypatch.setattr(fetch, "scoped_get_file",
                            stream_fake(body, final="https://t/.well-known/jwks.json"))
        res = evidence.fetch_and_extract(ctx, "https://t/.well-known/jwks.json",
                                         source="exposed-fetch", subdir="exposed")
        assert res["secrets"] == 0, res
        assert [r for kind, r in added if kind == "review" and r.get("klass") == "signing-key"]


class TestClassificationIsSTRUCTURAL:
    """review#1 (Lumpy): a ±200-character window promoted a PUBLIC key to a secret because a
    NEIGHBOURING object mentioned HS256. Text proximity does not establish a relationship."""

    LONG = "public-material-long-enough-1234"

    def test_a_neighbouring_objects_algorithm_does_not_bleed(self):
        body = ('{"published": {"key": "%s", "kid": "k1"}, "session": {"algorithm": "HS256"}}'
                % self.LONG)
        assert kinds(body, "https://t/api") == {"signing-key": self.LONG}

    def test_the_SAME_objects_algorithm_does_decide(self):
        body = '{"session": {"key": "%s", "algorithm": "HS256"}}' % self.LONG
        assert kinds(body, "https://t/api") == {"json:key": self.LONG}

    def test_a_jwks_array_entry_is_an_observation(self):
        body = '{"keys": [{"key": "%s", "kid": "k1", "alg": "RS256"}]}' % self.LONG
        assert kinds(body, "https://t/.well-known/jwks.json") == {"signing-key": self.LONG}

    def test_a_body_that_does_not_parse_never_promotes(self):
        """XML, templates and truncated dumps have no readable object boundaries, so the fallback stays
        an observation — it cannot prove which fields belong together."""
        xml = ('<add key="Jwt:Key" value="%s" /><add key="alg" value="HS256" />' % self.LONG)
        assert "json:key" not in kinds(xml, "https://t/web.config")
        broken = '{"Jwt": {"Key": "%s", "algorithm": "HS256"' % self.LONG      # truncated
        assert kinds(broken, "https://t/appsettings.json") == {"signing-key": self.LONG}


class TestLocalEvidenceIsREADABLE:
    """Lumpy, 2026-08-05: "All reports and hotlists should have the data clearly readable (not masked or
    redacted). I don't want to jump between 11 files to eventually find a false positive."

    Quarry's OWN configured credentials are still redacted everywhere. A DISCOVERED secret is the
    finding, and the report is where the operator reads it."""

    RAW = "AKIAIOSFODNN7EXAMPLE"

    @staticmethod
    def _run(tmp_path, rows):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "readable")
        for r in rows:
            run.add("secret", r)
        return run

    def test_the_HOTLIST_prints_the_VALUE_not_a_preview(self, tmp_path):
        from quarry_recon import secrets as sec, triage
        from quarry_recon.config import ScopeMatcher
        run = self._run(tmp_path, [{"id": "s1", "kind": "aws-access-key", "value": self.RAW,
                                    "preview": sec.mask(self.RAW), "file": "/raw/x",
                                    "sources": ["exposed-fetch"]}])
        md = triage.build(run, ScopeMatcher([], [], [], False))
        assert self.RAW in md, "the operator must be able to read the finding"
        assert sec.mask(self.RAW) not in md, "…and not have to decode a preview"

    def test_the_DIGEST_carries_the_value(self, tmp_path):
        from quarry_recon import secrets as sec, triage
        from quarry_recon.config import ScopeMatcher
        run = self._run(tmp_path, [{"id": "s1", "kind": "aws-access-key", "value": self.RAW,
                                    "preview": sec.mask(self.RAW), "sources": ["exposed-fetch"]}])
        d = triage.digest_json(run, ScopeMatcher([], [], [], False))
        blob = __import__("json").dumps(d)
        assert self.RAW in blob, "digest.json is LOCAL — it is the recon->attack contract"

    def test_a_legacy_entity_with_no_value_still_shows_something(self, tmp_path):
        from quarry_recon import secrets as sec, triage
        from quarry_recon.config import ScopeMatcher
        run = self._run(tmp_path, [{"id": "s2", "kind": "old", "preview": sec.mask(self.RAW),
                                    "sources": ["legacy"]}])
        md = triage.build(run, ScopeMatcher([], [], [], False))
        assert sec.mask(self.RAW) in md, "a pre-value run still reports what it has"

    def test_no_producer_throws_the_value_away(self):
        """Every secret producer stores the complete value on the entity. `pop("data")` deleted it."""
        import inspect
        from quarry_recon.phases import crawl
        src = inspect.getsource(crawl)
        assert 'e.pop("data"' not in src, "the value was popped off the entity"
        assert src.count('e["value"] = d') >= 2, "jsluice + sourcemap both keep it"
        assert '"value": sec,' in src and '"value": raw_s,' in src, "gitleaks + trufflehog keep it"

    def test_OUR_credentials_are_still_redacted(self):
        from quarry_recon import secrets as sec
        assert sec.redact("token=ABC") is not None
        assert callable(sec.mask), "masking still exists for channels that leave the box"


class TestNothingIsHiddenByAPresentationCap:
    """Lumpy, 2026-08-05: HOTLIST showed `secrets[:25]`, and `evidence.MAX_FETCHES = 50` silently sliced
    the candidate set before anything was even fetched. Both hide findings — one after collection, one
    before it."""

    @staticmethod
    def _run(tmp_path, n):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "caps")
        for i in range(n):
            run.add("secret", {"id": f"s{i}", "kind": "aws-access-key",
                               "value": f"AKIA{i:016d}", "sources": ["exposed-fetch"]})
        return run

    def test_the_HOTLIST_prints_EVERY_secret(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        md = triage.build(self._run(tmp_path, 40), ScopeMatcher([], [], [], False))
        for i in (0, 24, 25, 39):
            assert f"AKIA{i:016d}" in md, i

    def test_a_display_cap_that_remains_says_what_it_holds_back(self, tmp_path):
        """Context lists still cap for readability — and must never look complete while doing it."""
        import inspect
        from quarry_recon import triage
        src = inspect.getsource(triage)
        # every capped section says what it holds back — either through `_more` or with its own line
        # naming the exact store. What must never happen is a section that simply stops.
        import re
        # LOOPS that display a slice — not `hexdigest()[:10]` and friends
        capped = len(re.findall(r"for \w+ in [\w\.\(\)]+\[:\d+\]:", src))
        announced = src.count("_more(A,") + src.count("more — full list in") \
            + src.count("more prioritised")
        assert announced >= capped, (announced, capped)
        assert "not shown here" in inspect.getsource(triage._more)

    def test_fetching_has_no_membership_cap(self):
        from quarry_recon import evidence
        import inspect
        assert not hasattr(evidence, "MAX_FETCHES")
        src = inspect.getsource(evidence)
        assert "[:MAX_FETCHES]" not in src

    def test_the_fetch_lane_reports_what_it_looked_at(self, tmp_path, monkeypatch):
        from types import SimpleNamespace
        from quarry_recon import events, evidence, fetch
        events.reset()
        events.configure(tmp_path)
        added: list = []
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: (added.append((kind, rec)), True)[1])
        ctx = SimpleNamespace(run=run, scope=SimpleNamespace(
            in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True))
        monkeypatch.setattr(fetch, "scoped_get_file", stream_fake(b"x"))
        urls = [f"https://t/f{i}" for i in range(60)]
        evidence.fetch_exposed(ctx, urls)
        import json as _json
        evs = [_json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_fetches"]
        assert cov and cov[-1]["eligible"] == 60 and cov[-1]["tested"] == 60, cov
        assert len([r for k, r in added if k == "review"]) == 60, "the 51st was fetched too"
        events.reset()

    def test_the_fetch_count_is_MEASURED_not_intended(self, tmp_path, monkeypatch):
        """review#11 (Lumpy): the record was emitted BEFORE the loop with `tested=len(urls)`, so a run
        whose every candidate was out of scope, refused or threw still published `60/60 fetched`."""
        from types import SimpleNamespace
        from quarry_recon import events, evidence, fetch
        events.reset()
        events.configure(tmp_path)
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: True)
        # nothing is in scope: nothing is eligible and nothing was tested
        ctx = SimpleNamespace(run=run, scope=SimpleNamespace(
            in_scope=lambda h: False, is_oos=lambda h: True, active_allowed=lambda h: False))
        monkeypatch.setattr(fetch, "scoped_get_file",
                            lambda *a, **k: pytest.fail("a request was issued for an out-of-scope host"))
        evidence.fetch_exposed(ctx, [f"https://t/f{i}" for i in range(60)])
        import json as _json
        evs = [_json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_fetches"]
        assert cov and cov[-1]["eligible"] == 0 and cov[-1]["tested"] == 0, cov
        events.reset()

    def test_a_candidate_that_THREW_was_ATTEMPTED_not_ignored(self, tmp_path, monkeypatch):
        """review#12 (Lumpy): a refused connection, a TLS error or a timeout happened AFTER contact was
        made. The gap count is right either way; calling it "never looked at" describes the run
        wrongly."""
        from types import SimpleNamespace
        from quarry_recon import events, evidence, fetch
        events.reset()
        events.configure(tmp_path)
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: True)
        ctx = SimpleNamespace(run=run, scope=SimpleNamespace(
            in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True))
        calls = {"n": 0}

        _ok = stream_fake(b"body")

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] % 2:
                raise OSError("connection refused")
            return _ok(*a, **k)
        monkeypatch.setattr(fetch, "scoped_get_file", flaky)
        evidence.fetch_exposed(ctx, [f"https://t/f{i}" for i in range(10)])
        import json as _json
        evs = [_json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_fetches"][-1]
        assert cov["eligible"] == 10 and cov["tested"] == 5, cov
        assert cov["omitted"] == 5
        assert "5 attempted without a readable response" in cov["reason"], cov["reason"]
        assert "never requested" not in cov["reason"], "they WERE requested"
        events.reset()

    def test_a_host_we_never_requested_is_described_as_such(self, tmp_path, monkeypatch):
        from types import SimpleNamespace
        from quarry_recon import events, evidence, fetch
        events.reset()
        events.configure(tmp_path)
        run = SimpleNamespace(
            raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
            if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda kind, rec: True)
        allowed = {"https://t/f0", "https://t/f1"}
        ctx = SimpleNamespace(run=run, scope=SimpleNamespace(
            in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True))
        # in scope for the lane, refused by the FETCHER's own guard (passive host, netguard, …)
        monkeypatch.setattr(evidence, "fetch_and_extract",
                            lambda ctx, u, **k: {"ok": False, "off_scope": False, "final": u,
                                                 "status": None, "attempted": u in allowed,
                                                 "error": None, "dest": None, "secrets": 0,
                                                 "links": 0})
        evidence.fetch_exposed(ctx, [f"https://t/f{i}" for i in range(4)])
        import json as _json
        evs = [_json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_fetches"][-1]
        assert "2 never requested" in cov["reason"], cov["reason"]
        assert "2 attempted without a readable response" in cov["reason"], cov["reason"]
        events.reset()


class TestTheConnectionStringScanIsLinear:
    """MEASURED 2026-08-06: `mine()` spent 3.7 s per MiB inside `_connstring_passwords`, and 99% of that
    was one candidate pattern — a LAZY 400-character prefix retried at every offset, so a long line with
    no `=` cost ~400 character tests per position. The 2 MiB body cap had been hiding it; removing the cap
    made it the dominant cost of interpreting an artifact.

    The rewrite anchors on `=` and expands a bounded window. Same answers, ~300x faster."""

    #: the ORIGINAL implementation, kept as the ORACLE. Equivalence is the claim being made, so the claim
    #: needs the thing it is equivalent to — not a hand-written expectation of what it probably did.
    _OLD_RX = re.compile(r"[^\"'\r\n]{0,400}?=[^\"'\r\n]{0,400}")

    @classmethod
    def _old(cls, text):
        out = []
        for m in cls._OLD_RX.finditer(text):
            chunk = m.group(0)
            if ";" not in chunk:
                continue
            fields = [f.split("=", 1) for f in chunk.split(";") if "=" in f]
            if not any(evidence._CONNSTR_ANCHOR.match(k) for k, _v in fields):
                continue
            for k, v in fields:
                if evidence._CONNSTR_PASSWORD.match(k) and len(v.strip()) >= 4:
                    out.append(v.strip())
        return sorted(set(out))

    @pytest.mark.parametrize("text", [
        "Server=db;Database=app;User ID=sa;Password=Sup3rSecret!;",
        "Password=x;User ID=sa;Server=db",                       # anchor AFTER the password
        'cfg = "Data Source=h;Initial Catalog=c;pwd=hunter22;"',
        "password=notacredential",                               # no anchor, no claim
        "a=b;c=d;",                                              # neither
        "Server=db;Password=abc",                                # too short to publish
        "x" * 500 + ";Server=db;Password=longenough;",           # past the 400-char window
        # the anchor and the password are 120 chars apart: inside the 400-char window the scan is
        # specified to use, and outside any narrower one. A shrunken window silently stops calling these
        # database credentials at all.
        "Server=db;" + ";".join(f"Opt{i}=v{i}" for i in range(15)) + ";Password=hunter22;",
        "Password=hunter22;" + ";".join(f"Opt{i}=v{i}" for i in range(15)) + ";Data Source=db;",
    ])
    def test_it_answers_exactly_what_the_old_scan_answered(self, text):
        assert sorted({v for v, _ in evidence._connstring_passwords(text)}) == self._old(text)

    def test_equivalence_over_random_input(self):
        import random
        import string
        random.seed(7)
        alpha = (list(string.ascii_letters + string.digits + "=;'\" \t\r\n_.-")
                 + ["Server", "Password", "User ID", "pwd", "Data Source", "Database"])
        for _ in range(2000):
            text = "".join(random.choice(alpha) for _ in range(random.randint(1, 300)))
            assert sorted({v for v, _ in evidence._connstring_passwords(text)}) == self._old(text), text

    def test_a_long_line_without_an_equals_is_not_quadratic(self):
        import time
        body = "x" * (2 * 1024 * 1024)
        t = time.perf_counter()
        evidence.mine(body)
        took = time.perf_counter() - t
        assert took < 1.0, f"{took:.2f}s for 2 MiB — the quadratic scan is back"
