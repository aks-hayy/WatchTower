"""Live authoritative RDAP/PTR acceptance probe for public indicators only."""

from __future__ import annotations

import json
import sys

from core.ai.research import ResearchBroker


def main() -> int:
    documents = ResearchBroker().research(["8.8.8.8"], query="RDAP PTR", include_web=False)
    lanes = {item.source_kind for item in documents}
    result = {
        "document_count": len(documents),
        "lanes": sorted(lanes),
        "urls": sorted(item.canonical_url for item in documents),
        "content_hashes": sorted(item.content_hash for item in documents),
        "facts": sum(len(item.facts) for item in documents),
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if {"rdap", "dns-ptr"}.issubset(lanes) else 2


if __name__ == "__main__":
    sys.exit(main())
