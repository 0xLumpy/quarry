# Manual OSINT broadening

`quarry osint` automates the programmatic scope-expansion: Azure/M365 tenant (azmap.dev), registrant
WHOIS, DMARC pivots, whoxy reverse-WHOIS, CAIDA ASRank ASN discovery, RDAP netblock lookups, asnmap ASN
expansion, and Postman intel (porch-pirate). Everything it finds is a **candidate** written to
`target.suggested.yaml` — never auto-scoped.

Some of the richest sources are **web UIs or paywalled/login-gated** and can't be automated cleanly — on
**larger targets** they're worth doing by hand. This is the playbook for what `quarry osint` can't reach.

**The rule never changes:** these surface *candidates*. **Confirm each is in program scope /
authorized before adding anything** to `target.yaml`, and never active-scan a range you haven't
verified is in scope. Authorization — not ownership — is the gate: in a bug-bounty context an
in-scope asset may not be one you "own", and an asset you own may be out of scope.

---

## 1. ASN / IP ranges
`quarry osint` already runs **CAIDA ASRank** (org → ASNs) and **RDAP** (resolved apex IPs → owning CIDR),
and expands any `ASN` you set via **asnmap**. Those emit `ASN`/`CIDR` *candidates* — a starting point. Go
deeper by hand:
- **bgp.he.net** — search the org name *and* free-form descriptions; note ASNs, subsidiaries, country,
  announced prefixes. The description search surfaces ranges the name search misses.
- **ARIN / RIPE** (and other RIRs) — RDAP UI or full-text search by org/handle to confirm netname,
  registration, and inetnum relationships (deeper than rdap.org's single-IP answer).
- → For each confirmed range/ASN, add to `CIDR` / `ASN` in the profile. Treat every candidate as a lead,
  not gospel — a resolved IP is often a CDN/shared host, not target-owned.

## 2. Acquisitions / subsidiaries / brands (manual)
- **Crunchbase · Tracxn · Pitchbook · OCCRP Aleph · SEC EDGAR** — find acquired companies,
  subsidiaries, and legal entities.
- → New apexes feed back in: add them to `APEX_DOMAINS`, and the legal-entity names to `ORG_NAMES`
  (which drives ASRank + reverse-WHOIS). `BRANDS` is separate — it feeds cloud-bucket candidates during
  active recon, not the OSINT broadening. Then **re-run `quarry osint`** so it expands from the new seeds.

## 3. Ad / analytics relationships (manual)
- **builtwith.com** (Relationships tab) — shared Google Analytics / NewRelic / Ads IDs link
  sibling properties that share infrastructure or ownership.
- → Candidate apexes; verify before adding.

## 4. Cloud certificate sweep
- **Caduceus** runs in the horizontal phase during active recon (not passive) when installed and you have
  set `CIDR` (behind-CDN hostnames from cert scans). **kaeferjaeger** SNI dumps are streamed automatically from local files (see
  `target-prep.md` for the one-time download). To go wider by hand: **merklemap.com** (CT search engine,
  CLI + live-domains API) and **Censys Platform** cert search (the vertical phase queries it too, if you
  set `censys: {token, org}` in `secrets.yaml` — advanced/optional).
- → Hostnames feed subdomain/scope review.

---

## Feeding results back
1. Collect confirmed apexes / ASNs / CIDRs / brands from the above.
2. Add the **verified** ones to `target.yaml` — or uncomment them from the `target.suggested.yaml` that
   `quarry osint` wrote (candidate `APEX_DOMAINS` / `ASN` / `CIDR` blocks, all commented until you
   approve them).
3. Re-run `quarry osint` if you added new seeds (it expands from them).
4. Then run recon against the confirmed scope.

*(There is no `quarry osint --import`: candidate approval is copy-by-hand, deliberately, so a human
confirms every scope addition.)*
