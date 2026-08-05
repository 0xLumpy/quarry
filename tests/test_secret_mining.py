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

from quarry_recon import evidence


def kinds(text: str) -> dict:
    return {k: v for k, v, _ln in evidence.mine(text)}


class TestTheFileIsTheSecret:
    """A Rails master key is 32 hex characters and nothing else: no assignment for a `KEY=value` rule and
    no field for a JSON rule. It decrypts `credentials.yml.enc` outright."""

    def test_a_rails_master_key_is_extracted(self):
        got = kinds("a1b2c3d4e5f60718293a4b5c6d7e8f90\n")
        assert got == {"rails-master-key": "a1b2c3d4e5f60718293a4b5c6d7e8f90"}

    def test_a_64_hex_key_file_is_extracted(self):
        body = "0" * 63 + "f"
        assert kinds(body) == {"hex-key-64": body}

    def test_a_hash_INSIDE_a_document_is_not_a_key_file(self):
        """Matching a bare 32-hex string anywhere would flag every MD5 and every git blob id. The rule is
        deliberately whole-body only."""
        assert kinds("the checksum is a1b2c3d4e5f60718293a4b5c6d7e8f90 for that file") == {}
        assert kinds('{"etag": "a1b2c3d4e5f60718293a4b5c6d7e8f90"}') == {}

    def test_surrounding_whitespace_does_not_hide_it(self):
        assert "rails-master-key" in kinds("\n  a1b2c3d4e5f60718293a4b5c6d7e8f90  \n")


class TestSecretsHiddenInsideValues:
    """.NET writes the password INSIDE a connection string, under a key like `DefaultConnection` that no
    secret-ish KEY pattern will ever match."""

    APPSETTINGS = ('{"ConnectionStrings":{"DefaultConnection":'
                   '"Server=db;Database=app;User Id=sa;Password=P@ssw0rd123;"},'
                   '"Jwt":{"Key":"super-secret-signing-value-1234"}}')

    def test_a_connection_string_password_is_extracted(self):
        assert kinds(self.APPSETTINGS)["connection-string-password"] == "P@ssw0rd123"

    def test_a_bare_Key_field_with_a_long_value_is_extracted(self):
        assert kinds(self.APPSETTINGS)["json:Key"] == "super-secret-signing-value-1234"

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
    offline-crackable."""

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

    def test_the_content_wordlist_and_the_fetcher_agree(self):
        """Every one of these is already in `content-configleak.txt`, i.e. Quarry ASKS for them."""
        from pathlib import Path
        import quarry_recon
        words = (Path(quarry_recon.__file__).parent / "data" / "content-configleak.txt").read_text()
        for probe in ("config/master.key", "appsettings.json"):
            assert probe in words, probe
            assert evidence.SENSITIVE_FILE_RX.search("/" + probe), probe

    def test_ordinary_pages_are_still_not_sensitive_files(self):
        for path in ("/index.html", "/about", "/static/app.js", "/api/v1/users"):
            assert not evidence.SENSITIVE_FILE_RX.search(path), path
