# Secrets

API keys and webhooks live in `~/.config/quarry/secrets.yaml` (`chmod 600`). Only credentials Quarry
**owns, reads, or passes** belong here — it calls Whoxy/Shodan/Censys directly, and hands other keys to
tools. Tools that read their own credential files (subfinder, waymore) keep them; see
[external-integrations.md](external-integrations.md).

Everything is optional; a blank value is never an error. Most sources simply skip without their key — but
not all: `certspotter` still runs keyless (at lower rate limits), ProjectDiscovery tools run without the
`projectdiscovery` (PDCP) key, and an unset `oob` block selects the public Interactsh backend. Configured
secret values are stripped (`***`) from recorded commands, notes, manifests, reports, and notifications
before anything is written or sent.

Back up the file before editing: `cp secrets.yaml secrets.yaml.bak`.

## Keys

| Key | Unlocks | Notes |
|-----|---------|-------|
| `github` (list) | `github-subdomains` | GitHub PATs. Use burner accounts — passed to the tool via a temporary 0600 file, never on a command line. |
| `shodan` | shosubgo, favicon/cert pivots, per-IP host records | one Shodan API key |
| `whoxy` | `quarry osint` reverse-whois | charges one credit per page (see spending controls in [configuration.md](configuration.md)) |
| `projectdiscovery` | subfinder PDCP sources, asnmap | exported to ProjectDiscovery tools as `PDCP_API_KEY` |
| `certspotter` | CT-log subdomains (SSLMate) | optional; the free tier works keyless |
| `censys` `{token, org}` | vertical Censys certificate search | **needs both** `token` (PAT) and `org` (organization id) or the source stays silent |
| `oob` `{callback_server, auth_token}` | self-hosted OOB callback backend | unset → the public Interactsh service. `auth_token` only if your server requires it. Standing up a server: [external-integrations.md](external-integrations.md). |
| `notify` `{events, slack, discord, telegram, webhook}` | run notifications | nothing sends unless both an event and a channel are set. Webhook/token setup: [external-integrations.md](external-integrations.md). |

```yaml
github:
  - ghp_xxxxxxxxxxxxxxxxxxxx        # burner account
shodan:  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
censys:
  token: censys_pat_xxxxxxxxxxxxxxxxxxxx
  org:   00000000-0000-0000-0000-000000000000
```

`quarry doctor` reports the individual provider keys it checks as set or missing and flags an obviously
malformed value (an unedited placeholder, a wrong-shaped token). Not every block is inspected — Censys
appears only when configured (unset is silent), notifications and OOB are summarised as sections, and the reserved `ai`
block is not checked. The provider is the final authority; Quarry never blocks a lane on its own shape check.

## What is redacted, and what is not

`redact()` attempts to mask only **Quarry's own configured** secrets (the values above, length ≥ 6) in
recorded or sent text such as manifests, display commands, notes, events, and notifications. In `v0.3.9`
it performs literal replacement: encoded, transformed, split, or overlapping representations are not a
proven confidentiality boundary, and a coincidental substring can alter benign telemetry. Treat it as
defense in depth. The pending integrity contract requires typed per-tool credential delivery and exclusion
from recordable values by construction.

The function does **not** mask non-secret fields such as `censys.org`, `telegram.chat_id`, and
`oob.callback_server`; those are identifiers and stay readable.

A **discovered** secret — one a scanner finds on the target — is different: it is evidence and is intended
to remain **whole** on its entity and in every full-fidelity private artifact. A short `preview` and a
`fingerprint` may sit beside it for recognition and deduplication, but they do not replace the value.
`v0.3.9` still has report paths where literal configured-secret masking or lossy rendering violates that
rule; those are release defects, not a reason to destructively redact the evidence.

## Reserved

The template ships an `ai:` block for future AI-assisted triage. It is reserved and **currently unused** —
leave it as-is.
