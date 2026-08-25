"""Bounded redaction and public-indicator handling for the analyst layer."""

from __future__ import annotations

import ipaddress
import math
import re
from hashlib import sha256
from typing import Any, Iterable, List
from urllib.parse import urlsplit


_SECRET_PATTERNS = (
    re.compile(r"(?im)(password|passwd|pwd)\s*([:=])\s*[^\s&;,]+"),
    re.compile(r"(?im)(authorization\s*:\s*(?:basic|bearer)\s+)[^\s,;]+"),
    re.compile(r"(?im)(api[_-]?key|access[_-]?token|refresh[_-]?token|secret)\s*([:=])\s*[^\s&;,]+"),
    re.compile(r"(?i)(token=)[^&\s]+"),
)
_PRIVATE_HOSTS = re.compile(r"(?i)(?:localhost|\.local\.?$|\.internal\.?$|\.lan\.?$)")
_IP_RE = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:.])")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
_HASH_RE = re.compile(r"(?i)\b[a-f0-9]{64}\b")
_CVE_RE = re.compile(r"(?i)^CVE-\d{4}-\d{4,}$")
_ASN_RE = re.compile(r"(?i)^AS\d{1,10}$")


def redact_text(value: Any, max_chars: int = 8192) -> str:
    text = str(value or "")[:max_chars]
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}{match.group(2) if match.lastindex and match.lastindex > 1 else ''}[REDACTED]", text)
    return text


def redact_value(value: Any, max_depth: int = 5, max_items: int = 100) -> Any:
    if max_depth <= 0:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "[NON_FINITE]"
    if isinstance(value, dict):
        return {str(key)[:128]: redact_value(item, max_depth - 1, max_items) for key, item in list(value.items())[:max_items]}
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item, max_depth - 1, max_items) for item in list(value)[:max_items]]
    if isinstance(value, bytes):
        return {"sha256": sha256(value).hexdigest(), "bytes": len(value), "content": "[BINARY_REDACTED]"}
    return redact_text(value)


def is_public_indicator(value: str) -> bool:
    candidate = str(value or "").strip().rstrip(".")
    if not candidate or _PRIVATE_HOSTS.search(candidate):
        return False
    if _CVE_RE.fullmatch(candidate) or _ASN_RE.fullmatch(candidate):
        return True
    parsed_url = urlsplit(candidate)
    if parsed_url.scheme:
        if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password:
            return False
        candidate = parsed_url.hostname.rstrip(".")
        if _PRIVATE_HOSTS.search(candidate):
            return False
    try:
        return ipaddress.ip_address(candidate).is_global
    except ValueError:
        pass
    return bool(_DOMAIN_RE.fullmatch(candidate) or _HASH_RE.fullmatch(candidate))


def contains_sensitive_external_data(value: Any) -> bool:
    text = redact_text(value, 32768)
    for address in _IP_RE.findall(text):
        try:
            if not ipaddress.ip_address(address).is_global:
                return True
        except ValueError:
            continue
    return bool(_PRIVATE_HOSTS.search(text))


def public_indicators(values: Iterable[str]) -> List[str]:
    return sorted({str(value).strip().rstrip(".") for value in values if is_public_indicator(str(value))})
