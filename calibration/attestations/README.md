# Reviewed Calibration Attestations

This directory stores compact, content-addressed attestations created only by:

```text
tower plugins calibration promote REPORT --reviewer NAME --reason TEXT
```

Commit the generated attestation and matching scoring-profile change together. Runtime reports and field bundles belong under ignored `data/calibration/` paths and must not be committed.
