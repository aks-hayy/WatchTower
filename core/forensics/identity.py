"""Deterministic identity attribution for passive forensic observations."""

from dataclasses import dataclass
import re
from typing import Dict, Optional


IDENTITY_FIELDS = {
    "mac",
    "local_hostname",
    "netbios_name",
    "username",
    "full_name",
    "device_type",
    "vendor",
}


SOURCE_CONFIDENCE = {
    "Ethernet": 0.98,
    "Kerberos Parser": 0.95,
    "NTLM Parser": 0.92,
    "SMB Stateful Parser": 0.90,
    "DHCP Parser": 0.88,
    "NBNS Parser": 0.82,
    "Discovery Parser": 0.75,
    "Infrastructure Parser": 0.70,
    "Full Name Scraper": 0.62,
    "FTP Parser": 0.45,
}


_SENSITIVE_DIRECTIVE = re.compile(
    r"(?:^|\s)(?:PASS(?:WORD)?|AUTHORIZATION|COOKIE|TOKEN|SECRET)\s*(?:[:=]|\s)",
    re.IGNORECASE,
)


def sanitize_identity_value(field: str, raw_value: object) -> Optional[str]:
    """Bound identity labels and remove any adjacent secret-bearing protocol lines."""
    if raw_value is None:
        return None
    value = str(raw_value).replace("\x00", "").strip()
    if not value:
        return None
    value = value.splitlines()[0].strip()
    marker = _SENSITIVE_DIRECTIVE.search(value)
    if marker:
        value = value[:marker.start()].strip()
    value = "".join(character for character in value if character.isprintable()).strip()
    if not value:
        return None
    maximum = 255 if field in {"full_name", "local_hostname", "netbios_name"} else 128
    value = value[:maximum]
    if field in {"username", "local_hostname", "netbios_name"} and any(
        character.isspace() for character in value
    ):
        return None
    return value


@dataclass(frozen=True)
class IdentityObservation:
    value: str
    source: str
    confidence: float
    observed_at: float


class IdentityResolver:
    """Keeps the strongest observation for each identity field and host."""

    def __init__(self):
        self._observations: Dict[str, Dict[str, IdentityObservation]] = {}

    def observe(
        self,
        ip: str,
        source: str,
        identities: Dict[str, object],
        observed_at: float,
        confidence: Optional[float] = None,
    ) -> Dict[str, str]:
        accepted = {}
        host = self._observations.setdefault(ip, {})
        score = confidence if confidence is not None else SOURCE_CONFIDENCE.get(source, 0.50)

        for field, raw_value in identities.items():
            if field not in IDENTITY_FIELDS or raw_value is None:
                continue
            value = sanitize_identity_value(field, raw_value)
            if not value:
                continue

            current = host.get(field)
            candidate = IdentityObservation(value, source, score, observed_at)
            if current is None or score > current.confidence or (
                score == current.confidence and observed_at >= current.observed_at
            ):
                host[field] = candidate
                accepted[field] = value

        return accepted

    def values_for(self, ip: str) -> Dict[str, str]:
        return {field: observation.value for field, observation in self._observations.get(ip, {}).items()}

    def strongest_source(self, ip: str) -> Optional[IdentityObservation]:
        observations = (
            observation
            for field, observation in self._observations.get(ip, {}).items()
            if field not in {"mac", "vendor"}
        )
        return max(observations, key=lambda item: item.confidence, default=None)
