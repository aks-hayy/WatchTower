"""Live, local-only Ollama acceptance probe used by acceptance_full.ps1."""

from __future__ import annotations

import json
import os
import sys

from core.ai.config import ProviderConfig
from core.ai.contracts import ScopedContext
from core.ai.providers import OllamaProvider


def main() -> int:
    model = os.environ.get("WATCHTOWER_ACCEPTANCE_OLLAMA_MODEL", "qwen2.5-coder:latest")
    base_url = os.environ.get("WATCHTOWER_OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    provider = OllamaProvider(ProviderConfig(True, model, base_url, ""), timeout=90.0)
    status = provider.status()
    if not status.get("available"):
        print(json.dumps({"status": status}, sort_keys=True))
        return 2
    models = provider.discover_models()
    probe = provider.probe()
    turn = provider.respond(
        "Reply with exactly one short sentence confirming local WatchTower analyst connectivity.",
        ScopedContext(), [], [],
    )
    result = {
        "status": status,
        "model_count": len(models),
        "model_ids": [item["id"] for item in models],
        "probe": probe,
        "response_present": bool(turn.text.strip()),
        "tool_calls": len(turn.tool_calls),
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["response_present"] else 3


if __name__ == "__main__":
    sys.exit(main())
