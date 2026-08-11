# External integrations

Some things Quarry talks to are configured **outside** Quarry — a tool that reads its own credential file,
a callback server you host, a chat webhook you create. This page is the single place those live: a brief
note and a link to the upstream documentation for each. Quarry does not reproduce or maintain external
setup instructions — follow the linked source, then point Quarry at the result.

For credentials Quarry owns, reads, or passes, see [secrets.md](secrets.md).

## External tool credentials

A few tools read their **own** config files, not Quarry's `secrets.yaml`. Quarry runs them as-is and does
not manage these keys:

- **subfinder** — passive-source API keys live in subfinder's provider config. Set them up per the
  [subfinder docs](https://docs.projectdiscovery.io/tools/subfinder) (post-install provider config).
- **waymore** — optional API keys (URLScan, VirusTotal) live in waymore's own config. See
  [waymore](https://github.com/xnl-h4ck3r/waymore) (see its README config section).

`quarry doctor` does not report these — they are the tool's to validate.

## Out-of-band callback server (blind XSS / OOB)

Quarry runs its **own** `interactsh-client` session for one lane — `params.oob_probe` — and `quarry oob
poll` resumes *that* session. Nuclei and dalfox (`MODES.BLIND_XSS`) each open their **native** interactsh
session and own their own correlation; Quarry does not manage those. All of them use the **public**
Interactsh service unless you point them at a server you host:

- Host it per the [interactsh](https://github.com/projectdiscovery/interactsh) (self-hosted server section).
- Then set it in `secrets.yaml`:

```yaml
oob:
  callback_server: oob.example.com      # your server's domain (not a payload host)
  auth_token:                           # only if your server requires auth
```

Poll for delayed callbacks after a run with `quarry oob poll`; import an external interactsh log with
`quarry oob import`. See [oob.md](oob.md).

## Run notifications

Quarry can post a short message when a run completes, errors, or finds a lead. It sends only when both an
`events` list and at least one channel are set. Create the webhook/token upstream, then paste it into the
`notify` block in `secrets.yaml`:

- **Slack** — an [incoming webhook](https://api.slack.com/messaging/webhooks)
- **Discord** — a [channel webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)
- **Telegram** — a [bot token](https://core.telegram.org/bots/features#botfather) and your chat id

```yaml
notify:
  events: [complete, error, lead]
  slack:    https://hooks.slack.com/services/XXX/YYY/ZZZ
  discord:  https://discord.com/api/webhooks/XXX/YYY
  telegram: {token: "123456:ABC-DEF", chat_id: "987654321"}
  webhook:  https://your.endpoint/quarry     # plain JSON POST, for anything else
```

Check the configured channels with `quarry notify`, which shows and validates them without sending a run.
Notification content applies Quarry's configured-secret masking. In `v0.3.9` that is exact-value defense
in depth, not proof against encoded, transformed, or split representations. Do not send target evidence to
a notification channel unless that channel is approved for it; the release contract requires
Quarry-owned credentials to be excluded structurally rather than relying on text repair.

## Operator-supplied data

Two optional sources are **data you provide**, not tools Quarry installs. Quarry reads them if present
and never downloads or updates them.

### kaeferjaeger SNI datasets

The horizontal phase greps local Kaeferjaeger SNI dumps for in-scope hostnames. Download the provider
`*_sni.txt` datasets you want into `~/.config/quarry/kaeferjaeger/`; Quarry reads **every `*.txt`** there,
line by line. With no dataset present the lane records a visible skip.

- Datasets: [kaeferjaeger SNI-IP ranges](https://kaeferjaeger.gay/?dir=sni-ip-ranges)

### OpenINTEL subdomains

An optional extra passive subdomain source. It needs **two operator-supplied files** — the
`openintel-subs` executable and a prepared `subs.db` (SQLite) — configured by path under a top-level
`openintel:` key in `config.yaml` (not `secrets.yaml`):

```yaml
# config.yaml, top-level:
openintel:
  binary: /path/to/openintel-subs
  db:     /path/to/subs.db
```

Both paths must exist or the source stays unused. Quarry neither installs nor updates these.

> **Distribution gap.** There is currently **no public download or build source** for this binary and
> prepared database. OpenINTEL publishes raw research datasets
> ([forward-DNS top-lists](https://openintel.nl/data/forward-dns/top-lists/)), not Quarry's prepared
> SQLite `subs.db`. Until a canonical build/host exists, this source is only usable by an operator who
> already has both files — treat it as advanced/unavailable, not a copy-paste setup.
