# Out-of-band interaction

Some checks confirm a vulnerability only when the target calls back out-of-band — blind XSS, SSRF, and
Nuclei's OAST templates. Quarry uses **interactsh** for this. By default the callbacks go to
ProjectDiscovery's **public** Interactsh service; you can point them at a server you host instead. Three
separate channels run, and they do **not** share a session.

## Who owns which callback

| Channel | Session & correlation owner | Backend |
|---------|-----------------------------|---------|
| Quarry SSRF probe (`params.oob_probe`) | **Quarry** (`interactsh-client`) | public Interactsh pool, or a configured server |
| Nuclei OAST templates | **nuclei** | public pool, or a configured server |
| Dalfox blind XSS (`MODES.BLIND_XSS`) | **dalfox** | public pool, or a configured server |

Only the Quarry-owned session is resumable with `quarry oob poll`. Nuclei and dalfox open and correlate
their **own** sessions; Quarry does not manage those.

## Public vs self-hosted

With nothing configured, all three use the **public** Interactsh service — meaning the public operator of
that service can observe your interactions. To keep callbacks on infrastructure you control, host your own
server and set it once:

```yaml
# secrets.yaml
oob:
  callback_server: oob.example.com      # your server's domain
  auth_token:                           # only if it requires auth
```

Standing up a server is upstream work — see [external-integrations.md](external-integrations.md).

> **`auth_token` needs a `callback_server`.** Quarry drops it unless a valid callback host is configured,
> so it is never sent to the public backend. For every owner that needs it, Quarry writes the credential to
> an ephemeral owner-only `0600` config file and passes that file with the tool's config-file option
> (`-config` or `--config`); the token itself is never placed in argv. Configured secrets are redacted from Quarry's records, but not from
> what a tool sends to its own backend.

## Delayed callbacks

An OOB interaction can arrive long after the run ends. Quarry's own session persists, so pull late hits:

```bash
quarry oob poll -t acme --wait 8            # resume Quarry's session, collect new callbacks
```

Callbacks the tool did not issue can be imported from an external interactsh `-json` log:

```bash
quarry oob import interactsh.jsonl -t acme
```

Imported rows become `oob_interaction` evidence. A row is **correlated** to its source (target / param /
payload) only when it carries a Quarry-issued token; otherwise it is kept as an uncorrelated observation.

## Consent

`MODES.BLIND_XSS` arms a **stored** payload that can fire later, in someone else's browser. It is off by
default and is a deliberate engagement decision — see [target-reference.md](target-reference.md).

The **absence** of a callback is not proof the channel worked or the target is clean — only that nothing
called back within the window observed.
