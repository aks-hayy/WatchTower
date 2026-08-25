# WatchTower Documentation

- [Container deployment](containers.md), including the one-command Windows hybrid runtime.

This documentation describes the WatchTower 2.0 source release. Commands assume the repository setup script has completed and `tower` refers to the executable inside `.venv`.

## Operators

- [Getting started](getting-started.md)
- [Operations](operations.md)
- [Live monitoring and detection](live-detection.md)
- [Offline forensics](forensics.md)
- [Identity and enrichment](identity-enrichment.md)
- [AI analyst](ai-analyst.md)
- [Sensor mesh](sensor-mesh.md)
- [Sysmon attribution](sysmon.md)
- [Troubleshooting](troubleshooting.md)

## Developers and maintainers

- [Architecture](architecture.md)
- [API](api.md)
- [Plugin development](plugins.md)
- [Detector calibration](calibration.md)
- [Developer guide](development.md)
- [Maintainer guide](maintainer-guide.md)
- [Testing and release](testing-release.md)
- [Why Neo4j is optional](neo4j.md)
- [Detector authoring playbook](agents/detector-authoring.md)
- [Detector calibration playbook](agents/detector-calibration.md)

## Project policies

- [Contributing](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [License](../LICENSE)
- [Third-party notices](../THIRD_PARTY_NOTICES.md)

WatchTower reports observed evidence, processing completeness, and confidence separately. A behavioral priority score is an investigation-priority index, not the probability that a host is compromised.
