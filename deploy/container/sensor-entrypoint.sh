#!/usr/bin/env sh
set -eu

: "${WATCHTOWER_SENSOR_INTERFACE:?Set WATCHTOWER_SENSOR_INTERFACE to a Linux interface.}"
exec python -m core.mesh.sensor_service \
  --interface "$WATCHTOWER_SENSOR_INTERFACE" \
  --backend rust \
  --interval "${WATCHTOWER_SENSOR_SYNC_INTERVAL:-10}" \
  --limit "${WATCHTOWER_SENSOR_SYNC_LIMIT:-250}"
