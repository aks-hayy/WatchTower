# Plugins

- [Plugin authoring](../plugins.md)
- [Detector authoring playbook](../agents/detector-authoring.md)
- [Calibration playbook](../agents/detector-calibration.md)
- [Calibration model](../calibration.md)

Every parser, detector, capture source, and hardware extension must declare
its contract, bounded state, reset/finalize behavior, evidence shape, and
tests. Detector trust is granted only by the calibration engine and reviewed
attestation workflow.
