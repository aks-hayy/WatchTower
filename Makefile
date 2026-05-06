.PHONY: install dev build test clean help

help: ## Show this help message
	@echo "Watchtower - Network Forensics Platform"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install backend + frontend dependencies
	pip install -e .
	cd flow-insights && npm install

dev: ## Install with development dependencies
	pip install -e ".[dev,tls]"
	cd flow-insights && npm install

build: ## Build the frontend for production
	cd flow-insights && npm run build

test: ## Run all tests
	python -m pytest tests/ -v

lint: ## Lint Python code with ruff
	ruff check core/
	ruff format --check core/

format: ## Auto-format Python code
	ruff format core/

clean: ## Remove runtime data and build artifacts
	rm -rf data/watchtower.db data/engine.log data/engine.pid
	rm -rf __pycache__ core/__pycache__
	rm -rf dist/ build/ *.egg-info
	rm -rf flow-insights/dist

start: ## Start the capture engine (requires admin/root)
	tower start

stop: ## Stop the capture engine
	tower stop

ui: ## Launch the web dashboard
	tower ui
