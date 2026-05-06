# Contributing to Watchtower

Thank you for considering contributing to Watchtower! This document explains how to get started.

## Development Setup

### Prerequisites
- Python 3.9+
- Node.js 18+
- Npcap (Windows) or libpcap (Linux/Mac)
- Administrator/root privileges (for packet capture features)

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/watchtower.git
cd watchtower

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# .\venv\Scripts\activate  # Windows

# Install in development mode
pip install -e ".[dev]"

# Set up environment
cp .env.example .env

# Install frontend dependencies
cd flow-insights
npm install
cd ..
```

### Running Tests

```bash
# Run all Python tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=core

# Run frontend tests
cd flow-insights
npm test
```

### Code Style

We use **ruff** for Python linting. Check your code before submitting:

```bash
ruff check core/
ruff format core/
```

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/yourusername/watchtower/issues) first
2. Include your OS, Python version, and Watchtower version
3. Provide steps to reproduce the issue
4. Include relevant log output from `data/engine.log` if applicable

### Suggesting Features

Open an issue with the `enhancement` label. Describe:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add or update tests as needed
5. Run the test suite to verify
6. Commit with a clear message: `git commit -m "Add: description of change"`
7. Push to your fork: `git push origin feature/my-feature`
8. Open a Pull Request against `main`

### Commit Message Convention

```
Add: new feature description
Fix: bug description
Docs: documentation change
Refactor: code change that doesn't fix a bug or add a feature
Test: adding or updating tests
Chore: build process or auxiliary tool changes
```

## Project Structure

```
watchtower/
├── core/
│   ├── packet_engine/     # Capture, flow analysis, API server
│   ├── forensics/         # PCAP analysis, parsers, detectors
│   ├── cli/               # Interactive shell and command modules
│   ├── storage/           # SQLite database layer
│   └── ui/                # Dashboard launcher
├── flow-insights/         # React/TypeScript frontend
├── tests/                 # Python test suite
├── data/                  # Runtime data (gitignored)
└── scripts/               # Setup and utility scripts
```

## Potential Contributions & Modularity Guide

Watchtower is highly modular and exceptionally well-suited for open-source community contributions due to its strict separation of concerns. Here is how you can help evolve the platform:

The IPC Daemon Model (`core/daemon/`)
The background capture engines communicate with the rest of the app via local TCP sockets (sending JSON payloads).
- **How to help:** Because of this IPC model, the community can build entirely new integrations. You could write a Go or Rust service that connects to Watchtower's IPC socket to ingest live telemetry and forward it to an enterprise SIEM like Splunk or ElasticSearch.

 Database Abstraction (`core/storage/`)
Watchtower uses SQLAlchemy ORM, abstracting away raw SQL queries.
- **How to help:** Currently using SQLite (perfect for desktop use). For enterprise scaling, a developer could swap SQLite for PostgreSQL by simply changing the SQLAlchemy connection string and adding migration scripts.

Plugins:
The capabilities of watchtower can be extended by adding plugins.
Example plugins:
- Protocol parsers: Add support for new protocols
- Detection modules: Add more detection modules which detects and alerts 
- Sigma Rules: Add more sigma rules


## Code of Conduct

Be respectful and constructive. We're all here to build better security tools.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
