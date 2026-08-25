# Live Monitoring and Detection

## Processing model

The network path is:

```text
capture source -> Rust/Python decode -> packet events -> conversation tracker
-> parser observations -> detector findings -> scoring -> persistence
```

Directional compatibility flow rows are retained, but stateful detectors consume canonical conversations scoped by sensor node, source, interface, capture session, protocol, and endpoints. This prevents identical five-tuples from separate interfaces or sessions from sharing detector state.

## Backends

Rust is the default for network capture and PCAP replay. It handles capture, VLAN/QinQ, IPv4/IPv6, transport classification, canonical flow keys, filtering, aggregation, and metrics. Raw frames required by Python protocol plugins remain available through bounded batches.

Use Python explicitly when diagnosing parity or using a source unsupported by Rust:

```text
tower start -i eth0 --backend python
```

An explicit Rust failure is reported; it does not silently switch to Python.

## Findings and scoring

Detectors emit typed findings with subject, scope, evidence, confidence, impact, fingerprint, and correlation group. Detectors do not set final risk. Behavioral Scoring V2 applies evidence quality, recurrence, recency, asset context, detector caps, calibration trust, and bounded correlation.

Priority levels are:

```text
0-19   LOW
20-49  MEDIUM
50-79  HIGH
80-100 CRITICAL
```

The score means investigation priority. Assessment confidence is displayed separately.

## Detection families

The active built-in set covers cleartext credentials, authentication bursts, ARP/NDP conflicts, untrusted DHCP and IPv6 routers, vertical and horizontal reconnaissance, SYN floods, administrative fanout, beaconing, DNS and ICMP tunneling, directional exfiltration, TLS mismatches, nonstandard protocol services, executable transfer, and unsafe IoT/OT behavior.

Disabled legacy detectors remain visible in inventory for compatibility and audit history. Their behavior is consolidated into active detector families so duplicate implementations cannot inflate scoring.

## Historical Sigma

Sigma is not a live packet detector. `tower plugins sigma sync` manages the local corpus, and `tower hunt` evaluates compatible rules against stored historical WatchTower metadata. Unsupported Sigma conditions are rejected with explicit reasons.

## False-positive control

Findings can be disposed as `true_positive`, `false_positive`, `benign_expected`, or `unknown`. False-positive and benign-expected findings remain auditable but contribute zero to current priority. Trusted scanner and policy configuration should be used for known administrative activity.

## Visibility limits

Packet capture cannot reliably identify endpoint processes without endpoint telemetry, inspect encrypted application content without keys, observe traffic outside the sensor vantage point, or recover packets dropped before capture. These limitations are surfaced in session and investigation views.
