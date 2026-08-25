# Identity and Enrichment

WatchTower separates observed behavior from claims about who an endpoint is. Every identity attribute carries provenance, confidence, first/last observation, and scope.

## Coverage levels

- Address coverage: the IP appeared in evidence.
- Evidence-backed identity: at least one attributable name, hardware, ownership, or protocol observation exists.
- Actionable identity: enough context exists to support an investigation decision.
- Strong identity: multiple independent evidence sources agree or an authoritative local source confirms the endpoint.

A generic card such as `Network endpoint 192.0.2.1` is address coverage, not identity success.

## Internal endpoints

Possible evidence includes MAC address and vendor, ARP/NDP bindings, DHCP names and lease details, DNS/PTR, mDNS, LLMNR, NBNS, LLDP/CDP, service discovery, TLS names, observed services, endpoint process telemetry, local host inventory, and relationship context. Device role is an inference and is labeled accordingly.

## External endpoints

Possible evidence includes PTR, RDAP/RIR ownership, ASN and organization, geolocation, DNS and SNI names, certificate metadata, service behavior, public threat intelligence, and observed relationships. External reputation is context; it does not automatically become a detection finding.

## Investigation pivots

The intended path is:

```text
IP -> identity -> conversation -> domain -> certificate -> ASN
   -> related hosts -> finding -> evidence
```

Use `tower lookup IP` for a focused identity card and `tower dive IP` for behavior, relationships, findings, attribution, and timeline context. The UI preserves the selected sensor/source/session scope across these pivots.

## Rebuild operations

```text
tower identity status
tower identity rebuild --dry-run
tower enrich status
tower enrich rebuild --dry-run
```

Rebuilds derive records from stored evidence and create backups before writes. They do not fabricate names for endpoints that lack evidence.
