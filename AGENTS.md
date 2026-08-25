# WatchTower Engineering Agents

## Detector Work

- Follow `docs/agents/detector-authoring.md` when creating or changing a detector.
- Follow `docs/agents/detector-calibration.md` when evaluating or promoting detector trust.
- Never set calibration trust in a detector manifest or edit a profile to bypass calibration.
- Treat `core/detection/scoring_profiles.yaml` as reviewed policy. Non-uncalibrated entries require a valid attestation produced by `tower plugins calibration promote`.
- Keep finding types canonical, evidence structured and redacted, state bounded, and fingerprints deterministic.
- Run focused tests, `tower plugins test`, `tower plugins calibration verify`, and the relevant calibration corpus before requesting review.

## Safety

- Calibration traffic must be generated from repository scenario specifications or explicitly authorized self-addressed fixtures.
- Never commit real captures, credentials, packet payloads, field bundles, databases, or runtime calibration reports.
- A passing agent assessment is not calibration evidence. Only deterministic engine metrics and reviewed attestations affect scoring trust.
