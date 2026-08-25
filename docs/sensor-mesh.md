# Sensor Mesh

The mesh extends a local WatchTower controller with Windows and Linux sensor nodes. Agents connect outbound using mTLS, spool telemetry while offline, and preserve sensor provenance on every record.

## Connectivity modes

- `local`: controller and nodes share a trusted local network.
- `vpn`: recommended for internet-separated nodes using an overlay such as WireGuard or Tailscale.
- `public`: advanced direct-public exposure requiring explicit risk acknowledgement and independent network hardening.

The WatchTower UI/API remains loopback-only by default. Mesh ports are configured separately.

## Controller setup

### Local Windows controller and sensor

When the controller/UI run in Docker on the same Windows workstation as the
sensor, use the hybrid launcher. It handles the controller setup, short-lived
enrollment package, fingerprint verification, agent lifecycle, and Rust capture
without exposing mesh ports beyond loopback:

```text
install.ps1
watchtower.ps1 start
watchtower.ps1 status
watchtower.ps1 stop
```

The controller UI remains available at `http://127.0.0.1:4173`. This is not a
replacement for remote enrollment: for another computer use VPN mode and the
manual node workflow below.

### Manual controller setup

```text
tower mesh controller setup --mode local
tower mesh controller start
tower mesh controller status
```

For a VPN address:

```text
tower mesh controller setup --mode vpn --address 100.64.0.10
```

Controller stop drains ingestion and preserves enrollment state. Certificate rotation and node removal require recent step-up authentication.

## Add a node

```text
tower mesh nodes add --name branch-sensor
```

The result is a short-lived enrollment package containing the controller address, one-time token, CA fingerprint, expiry, and expected capabilities. Transfer it through a trusted channel. The joining operator must verify the displayed controller fingerprint.

On the node, use the generated package with the `tower mesh agent join` workflow, then start the agent. Agents never accept arbitrary shell commands; controller commands use versioned typed payloads and acknowledgements.

## Lifecycle

```text
tower mesh nodes list
tower mesh nodes show NODE_ID
tower mesh nodes remove NODE_ID --reason "retired"
tower mesh controller restart
tower mesh controller stop
```

Removing a node revokes its certificate and commands while retaining historical evidence under a decommissioned identity. Agent leave removes local enrollment state only after an explicit lifecycle action.

## Data movement

Metadata, findings, health, and graph facts are centralized. Raw PCAPs, artifacts, and evidence excerpts remain on the originating node by default. Approved export transfers a hashed case bundle over the existing mTLS channel.

## Health

Fleet health includes connection state, capability sync, first telemetry status, ingestion lag, spool pressure, queue lag, gaps, dropped telemetry, clock skew, certificate expiry, and graph freshness. Sequence gaps are recorded; they are never hidden by a later successful batch.
