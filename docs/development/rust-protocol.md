# Rust Sensor Protocol

The Rust sensor owns fast capture, link-layer decoding, canonical flow
aggregation, and bounded metrics. It sends validated length-prefixed batches
to the Python/controller path while retaining the raw frame references needed
by parsers, detectors, and evidence generation.

Python remains the compatibility and orchestration layer. Backend selection is
explicit: a Rust failure is reported, never silently replaced by Python.
Replay tests compare canonical conversations, findings, evidence hashes, and
progress from identical PCAP input.
