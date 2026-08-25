# syntax=docker/dockerfile:1.7
# The controller image intentionally contains no capture privileges.  Live
# collection stays native by default, or runs in the explicit Linux-sensor
# profile where the minimum required Linux capabilities are declared.

FROM rust:1.86-bookworm AS rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/rust/watchtower-sensor
COPY rust/watchtower-sensor/Cargo.toml rust/watchtower-sensor/Cargo.lock ./
COPY rust/watchtower-sensor/src ./src
RUN cargo build --locked --release

FROM python:3.12-slim-bookworm AS python-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY requirements/container.lock ./requirements/container.lock
RUN python -m pip install --upgrade "pip==25.2" && python -m pip install -r requirements/container.lock
COPY pyproject.toml README.md LICENSE ./
COPY core ./core
RUN python -m pip install --no-deps .

FROM python:3.12-slim-bookworm AS controller
LABEL org.opencontainers.image.title="WatchTower Controller" \
      org.opencontainers.image.description="Local-first WatchTower controller and forensic API" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WATCHTOWER_HOME=/var/lib/watchtower \
    WATCHTOWER_CREDENTIAL_BACKEND=encrypted_file \
    WATCHTOWER_MASTER_KEY_FILE=/run/secrets/watchtower_master_key \
    WATCHTOWER_RUST_SENSOR=/opt/watchtower/bin/watchtower-sensor \
    PATH=/opt/watchtower/bin:$PATH
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates libpcap0.8 tini tshark \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 watchtower \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/watchtower --shell /usr/sbin/nologin watchtower \
    && mkdir -p /var/lib/watchtower /opt/watchtower/bin \
    && chown -R watchtower:watchtower /var/lib/watchtower /opt/watchtower
COPY --from=python-builder /usr/local /usr/local
COPY --from=rust-builder /src/rust/watchtower-sensor/target/release/watchtower-sensor /opt/watchtower/bin/watchtower-sensor
COPY core ./core
COPY pyproject.toml README.md LICENSE ./
COPY --chown=watchtower:watchtower --chmod=0555 deploy/container/sensor-entrypoint.sh /opt/watchtower-sensor-entrypoint.sh
COPY --chown=watchtower:watchtower deploy/container/healthcheck.py /opt/watchtower-healthcheck.py
USER watchtower
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=6 CMD python /opt/watchtower-healthcheck.py || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "core.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
