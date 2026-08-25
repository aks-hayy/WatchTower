# Security Policy

## Supported version

Security fixes are applied to the latest commit on the repository's default branch. Pre-2.0 branches are historical and are not supported.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting or security-advisory feature for this repository. Do not open a public issue containing an exploit, credential, capture, internal address, or operator data.

Include:

- The affected commit and operating system.
- The impacted component and required privileges.
- Reproduction steps using synthetic data where possible.
- The expected impact and any known mitigations.
- Whether credentials, packet content, mesh trust, or evidence integrity may be exposed.

You should receive an acknowledgement within seven days. A coordinated disclosure date will be agreed after the issue is reproduced and a remediation path exists.

## Security boundaries

WatchTower protects application access and evidence handling but cannot defend against an attacker with local administrator or root control. The UI and API bind to loopback by default. Remote sensors use explicit enrollment and mTLS. External AI and research providers are opt-in and subject to redaction and approval policy.

The Compose deployment publishes only the loopback UI. It mounts an
installation key as a Docker secret and uses that key to encrypt the
container-local credential vault; do not publish the controller API, mount the
Docker socket, or commit `deploy/container/.env.container` or its secrets.

Never attach a real PCAP, runtime database, credential export, field calibration bundle, private key, or case archive to a public report.
