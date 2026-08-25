# Docker-only Runtime

Docker-only mode is suitable for offline forensics and the controller/UI. It
does not provide transparent access to a host network interface on every
platform. For live capture, use the native Rust sensor and hybrid bridge.

```bash
./scripts/container.sh init
./scripts/container.sh build
./scripts/container.sh up
```

The controller binds to loopback by default. Keep the generated environment
file and volumes outside Git, and use the container status and health output
before uploading a PCAP.
