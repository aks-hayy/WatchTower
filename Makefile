.PHONY: help install dev test lint build ui clean release-check container-init container-up container-down container-status

help:
	@echo "WatchTower 2.0"
	@echo "  make install       Install backend, Rust sensor, and UI"
	@echo "  make dev           Install development dependencies"
	@echo "  make test          Run the Python test suite"
	@echo "  make lint          Run Python and UI static checks"
	@echo "  make build         Build Rust and the production UI"
	@echo "  make ui            Launch the local UI"
	@echo "  make release-check Validate the source tree"
	@echo "  make container-up  Start the loopback Docker Compose deployment"

install:
	./scripts/setup.sh

dev:
	./scripts/setup.sh --development

test:
	.venv/bin/python -m pytest -q

lint:
	.venv/bin/ruff check core tests tools scripts
	cd ui && npm run lint && npm run typecheck

build:
	cargo build --locked --release --manifest-path rust/watchtower-sensor/Cargo.toml
	cd ui && npm ci && npm run build

ui:
	.venv/bin/tower ui

release-check:
	.venv/bin/python tools/check_release_tree.py
	.venv/bin/tower plugins calibration verify

clean:
	.venv/bin/python tools/release.py workspace scan

container-init:
	bash ./scripts/container.sh init

container-up:
	bash ./scripts/container.sh up

container-down:
	bash ./scripts/container.sh down

container-status:
	bash ./scripts/container.sh status
