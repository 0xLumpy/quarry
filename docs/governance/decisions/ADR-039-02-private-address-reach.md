# ADR-039-02: private-address reach is enabled by default

**Status:** accepted

**Decision date:** 2026-08-11

**Applies to:** active contact of authorized targets

## Context

Bug-bounty scopes can intentionally include internal, lab, VPN, CGNAT, or split-horizon targets. A blanket
global-address-only rule would lose authorized evidence and make Quarry unsuitable for those engagements.

## Decision

Keep RFC1918, CGNAT and IPv6 ULA reach enabled by default for names and addresses already authorized by
the engagement scope. Preserve an engagement-level opt-out for operators who require global-only reach.

## Required controls

- Private reach never expands scope: relationship or DNS evidence is not authorization.
- Loopback, link-local, the scanner's own addresses, cloud metadata, and declared control-plane endpoints
  remain protected destinations even when private reach is enabled.
- Apply the protected-destination decision to the actual connected peer, every redirect, proxy behavior,
  direct-IP inputs and CIDR expansion—not only to a preflight DNS answer.
- Record the selected private-reach policy and relevant allow/refuse decisions in the run evidence.

## Consequences

An authorized hostname controlled by a target may legitimately route into private address space. Quarry
therefore needs a connect-time/egress enforcement boundary and cannot treat a one-time resolver check as
the complete control. This ADR accepts intended private reach; it does not accept scanner or metadata
contact, DNS-rebinding bypass, or scope expansion.
