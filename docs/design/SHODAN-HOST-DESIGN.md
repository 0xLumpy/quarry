# `/shodan/host/{ip}` — the measured envelope and what Quarry concludes from it

Reference for `src/quarry_recon/shodan_host.py`. Measured 2026-07-30 against a real account at a **zero**
query-credit balance: the delta was 0 either side, so this endpoint is free where `/shodan/host/search`
is not.

## The measurement

    a known IP      HTTP 200, 19 top-level keys —
                    {"ip_str": "1.1.1.1", "ip": 16843009,             <- `ip` is an int, not the address
                     "ports": [161, 2082, 80, 53, 443, ...],          <- unsorted
                     "hostnames": [...], "domains": [...], "tags": [],
                     "org": "...", "isp": "...", "asn": "AS13335",    <- a string, with the AS prefix
                     "os": null, "last_update": "2026-07-30T04:14:37.743242",
                     "data": [ ...12 banner records... ]}
    an unseen IP    HTTP 404, {"error": "No information available for that IP."}
    a banner        {"port": 53, "transport": "tcp", "hostnames": [...], "domains": [...],
                     "_shodan": {"module": "dns-tcp", "crawler": ..., "id": ..., "ptr": ...},
                     "ssl": {...}   <- present on some banners only (3 of 12 here)}
    `vulns`         absent entirely when the host has none — not an empty list.

`null` appears as the provider's own "unknown" for scalar values (`"os": null`, `"area_code": null`).
It is never the measured form of a collection, so a null container is a part we could not read.

## Two rules

**"Not in Shodan" is an answer.** A 404 carrying the measured error string is empty coverage: the lane
asked and got a definitive reply. Any other 404 body is a 404 we do not understand and stays a failure
(`contract.is_measured_empty`). Both facts have to agree — the status *and* the wording — or a 500 that
happens to carry the same sentence would report absence we never established.

**Passive evidence is not a probe result.** Everything here is Shodan's memory of a scan it ran, at a
time it chose. A port in this record is not proven open now, and a hostname in it is not proven to
resolve. The lane's entity choices follow from that: observations are keyed `(port, transport)` because
53/tcp and 53/udp are different services, while the store identity stays `ip:port` to match the `port`
entity nmap and naabu already write, with the transport in a list-valued field so passive provenance can
coexist with a later active observation instead of fighting it as a first-write scalar.

`vulns` is deliberately half-unmeasured: the measured host has none, so its type is unknown. A list of
CVE ids and a `{cve: detail}` map are both accepted (Shodan has used both); anything else is counted
unusable rather than coerced into a shape we have never seen.

## Eligibility is observation, not enumeration

Only addresses Quarry has observed are eligible — resolved from an in-scope host, or carried on a port
record we already own. A declared CIDR is a scope *filter*, never an address *generator*: a /16 in
target.yaml is 65,534 addresses we have no reason to believe exist, and enumerating them would spend a
run's throughput on emptiness while reporting coverage.

An OOS host's address is not eligible. The rules of engagement are observe-and-mine OOS evidence, never
expand against it, and a lookup is an expansion of the address set we act on — even a free one.

## Evidence is run-scoped; scheduling progress is not

The endpoint is free and its records are live, so evidence ownership lives under the run directory: a
project-global ledger would replay a months-old snapshot of a host forever rather than asking again for
nothing.

Scheduling progress is the opposite. `ctx.run.dir` is a fresh directory every invocation, so a run under
a nonzero time budget would start from an empty ledger, ask the same deterministic prefix, and never
reach the tail. `SweepProgress` is therefore durable, project-level, and orders only — never-asked
addresses first, then the longest-unasked. Age is the rank, one tier per distinct last-asked time; a
coarse never/asked split collapses to one tier once everything has been asked once, and netblock
fairness then reproduces the same prefix.

Losing the progress file costs ordering quality, never coverage: the lane degrades to netblock-fair
order, which is where it started.

## Why the free loop is not `shodan_sched.run_work`

That coordinator's whole subject is credits — a balance, a spendable bound, a reserve, a stop cause
naming who ran out. This endpoint costs none. Wiring a free lane through it would make every credit
control apply to work no credit pays for, and an exhausted account would stop a lane it cannot affect.
What is reused is everything that is not about money: `budget.Ledger` ownership, the digest-bound
artifact handshake, the provider taxonomy, and the machinery-boundary discipline.

## Counter vocabulary

`HostOutcome` separates three questions that a single counter would blur:

| question | counters |
|---|---|
| what the provider said | `answered`, `records`, `empty`, `ports_seen`, `hostnames_seen`, `vulns_seen` |
| what the store took | `owned`, `ports`, `hostnames`, `vulns`, `port_rows` |
| what we could not keep or use | `publish_failed`, `unconsumed`, `evidence_invalid`, `records_journaled` |

An entity row is not an observation: one `ip:53` row can hold both TCP and UDP. `port_rows` counts rows
the sink wrote; `ports` counts observations inside them.
