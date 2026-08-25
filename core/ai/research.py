"""Controlled internet research with provenance, SSRF protection, and bounded caching."""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from hashlib import sha256
import ipaddress
import json
import socket
import time
from typing import Dict, Iterable, List, Optional
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
import uuid

import requests

from core.ai.config import AIConfig, CredentialStore
from core.ai.contracts import EvidenceCitation
from core.ai.redaction import is_public_indicator, public_indicators, redact_text


MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_REDIRECTS = 3
MAX_DOCUMENTS_PER_RUN = 12
_CVE_PREFIX = "CVE-"
_ASN_PREFIX = "AS"


class ResearchSafetyError(ValueError):
    pass


@dataclass
class ResearchDocument:
    source_kind: str
    canonical_url: str
    title: str
    summary: str
    content_hash: str
    retrieved_at: float
    expires_at: float
    reference: str
    facts: List[Dict[str, object]] = field(default_factory=list)

    def citation(self) -> EvidenceCitation:
        return EvidenceCitation(
            reference=self.reference, source=self.source_kind, summary=self.summary,
            kind="external", url=self.canonical_url, retrieved_at=self.retrieved_at,
            content_hash=self.content_hash,
        )


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ResearchSafetyError("External research only permits HTTPS URLs without embedded credentials")
    if parsed.port not in {None, 443}:
        raise ResearchSafetyError("External research only permits standard HTTPS")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith((".local", ".internal", ".lan")):
        raise ResearchSafetyError("External research cannot target local names")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ResearchSafetyError(f"Unable to resolve research host: {hostname}") from exc
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ResearchSafetyError("External research cannot target private or special-use addresses")
    return urlunsplit(("https", hostname, parsed.path or "/", parsed.query, ""))


class SafeHttpClient:
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> tuple[str, bytes, str]:
        current = _canonical_url(url)
        for _ in range(MAX_REDIRECTS + 1):
            response = requests.get(current, headers=headers or {}, timeout=(4, 12), stream=True, allow_redirects=False)
            if response.is_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise ResearchSafetyError("Research redirect did not include a location")
                current = _canonical_url(urljoin(current, location))
                continue
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "").lower()
            if not any(kind in content_type for kind in ("json", "text", "xml", "html")):
                raise ResearchSafetyError("Research response is not a text or JSON document")
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_DOCUMENT_BYTES:
                    raise ResearchSafetyError("Research document exceeds the size limit")
                chunks.append(chunk)
            return current, b"".join(chunks), content_type
        raise ResearchSafetyError("Research redirect limit exceeded")


class ResearchBroker:
    """Researches public indicators only. Callers enforce confirmation for sensitive context."""

    def __init__(self, db=None, config: AIConfig = None, credentials: CredentialStore = None, client: SafeHttpClient = None):
        self.db, self.config = db, config or AIConfig.load()
        self.credentials, self.client = credentials or CredentialStore(), client or SafeHttpClient()

    def sources(self) -> List[Dict[str, object]]:
        providers = self.config.public_dict()["providers"]
        return [
            {"name": "rdap", "lane": "authoritative", "enabled": True, "credential_required": False},
            {"name": "dns-ptr", "lane": "authoritative", "enabled": True, "credential_required": False},
            {"name": "certificate-transparency", "lane": "authoritative", "enabled": True, "credential_required": False},
            {"name": "cisa-kev", "lane": "authoritative", "enabled": True, "credential_required": False},
            {"name": "nvd", "lane": "authoritative", "enabled": True, "credential_required": False},
            {"name": "rdap-asn", "lane": "authoritative", "enabled": True, "credential_required": False},
            {"name": "virustotal", "lane": "threat_intelligence", "enabled": bool(providers["virustotal"]["enabled"]), "credential_required": True},
            {"name": "abuseipdb", "lane": "threat_intelligence", "enabled": bool(providers["abuseipdb"]["enabled"]), "credential_required": True},
            {"name": "brave", "lane": "open_web", "enabled": bool(providers["brave"]["enabled"]), "credential_required": True},
            {"name": "openai-web-search", "lane": "open_web", "enabled": bool(providers["openai"]["enabled"]), "credential_required": True},
        ]

    def research(self, indicators: Iterable[str] = (), query: str = "", include_web: bool = True,
                 web_provider: str = "brave") -> List[ResearchDocument]:
        indicators = public_indicators(indicators)
        if not indicators and not query.strip():
            raise ValueError("Research requires a public indicator or query")
        if any(not is_public_indicator(value) for value in indicators):
            raise ResearchSafetyError("Only public indicators can be researched automatically")
        documents: List[ResearchDocument] = []
        for indicator in indicators[:5]:
            documents.extend(self._authoritative(indicator))
            documents.extend(self._threat_intelligence(indicator))
        if include_web and query.strip():
            documents.extend(self._open_web(redact_text(query, 512), web_provider))
        deduplicated = {item.canonical_url: item for item in documents}
        result = list(deduplicated.values())[:MAX_DOCUMENTS_PER_RUN]
        for document in result:
            self._cache(document)
        return result

    def _document(self, lane: str, url: str, content: bytes, title: str = "", facts: Optional[List[Dict[str, object]]] = None) -> ResearchDocument:
        text = redact_text(content.decode("utf-8", errors="replace"), 16000).replace("\x00", " ")
        summary = " ".join(text.split())[:1400] or "External source returned no readable text."
        now = time.time()
        digest = sha256(content).hexdigest()
        return ResearchDocument(lane, url, title or lane, summary, digest, now,
                                now + self.config.research_cache_days * 86400, f"external:{lane}:{digest[:16]}",
                                facts=list(facts or []))

    @staticmethod
    def _rdap_facts(indicator: str, payload: bytes) -> List[Dict[str, object]]:
        try:
            value = json.loads(payload.decode("utf-8", errors="replace"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        facts: List[Dict[str, object]] = []
        subject = str(indicator)
        for key, predicate in (("name", "network_name"), ("handle", "network_handle"),
                               ("startAddress", "range_start"), ("endAddress", "range_end"),
                               ("country", "country")):
            if value.get(key) not in (None, ""):
                facts.append({"subject": subject, "predicate": predicate, "value": value[key], "confidence": 0.95})
        organizations = []
        for entity in value.get("entities") or []:
            for item in entity.get("vcardArray", [None, []])[1] if isinstance(entity.get("vcardArray"), list) else []:
                if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
                    organizations.append(str(item[3]))
        if organizations:
            facts.append({"subject": subject, "predicate": "organization", "value": organizations[0], "confidence": 0.9})
        return facts

    @staticmethod
    def _ptr_facts(indicator: str, payload: bytes) -> List[Dict[str, object]]:
        try:
            value = json.loads(payload.decode("utf-8", errors="replace"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        names = [str(item.get("data") or "").rstrip(".") for item in value.get("Answer") or []
                 if str(item.get("type")) == "12" and item.get("data")]
        return [{"subject": indicator, "predicate": "ptr", "value": name, "confidence": 0.9} for name in names]

    def _authoritative(self, indicator: str) -> List[ResearchDocument]:
        documents = []
        upper = indicator.upper()
        parsed_url = urlsplit(indicator)
        if parsed_url.scheme == "https":
            try:
                url, body, _ = self.client.get(indicator)
                return [self._document("public-indicator", url, body, f"Public indicator URL: {parsed_url.hostname}")]
            except (requests.RequestException, ResearchSafetyError):
                return []
        if upper.startswith(_CVE_PREFIX):
            return self._cve_documents(upper)
        if upper.startswith(_ASN_PREFIX) and upper[2:].isdigit():
            try:
                url, body, _ = self.client.get(f"https://rdap.org/autnum/{quote(upper[2:], safe='')}")
                return [self._document("rdap-asn", url, body, f"RDAP for {upper}")]
            except (requests.RequestException, ResearchSafetyError):
                return []
        try:
            parsed = ipaddress.ip_address(indicator)
        except ValueError:
            parsed = None
        try:
            if parsed:
                url, body, _ = self.client.get(f"https://rdap.org/ip/{quote(indicator, safe='')}")
                documents.append(self._document("rdap", url, body, f"RDAP for {indicator}", self._rdap_facts(indicator, body)))
                reverse = ".".join(reversed(indicator.split("."))) + ".in-addr.arpa"
                ptr_url = f"https://dns.google/resolve?name={quote(reverse, safe='')}&type=PTR"
                try:
                    canonical, ptr_body, _ = self.client.get(ptr_url, headers={"Accept": "application/dns-json"})
                    documents.append(self._document("dns-ptr", canonical, ptr_body, f"PTR for {indicator}", self._ptr_facts(indicator, ptr_body)))
                except (requests.RequestException, ResearchSafetyError):
                    pass
            elif "." in indicator:
                url, body, _ = self.client.get(f"https://crt.sh/?q={quote(indicator, safe='')}&output=json")
                documents.append(self._document("certificate-transparency", url, body, f"Certificate transparency for {indicator}"))
        except (requests.RequestException, ResearchSafetyError):
            pass
        return documents

    def _cve_documents(self, cve_id: str) -> List[ResearchDocument]:
        """Query NVD and extract only the matching CISA KEV record.

        The KEV feed is intentionally summarized before it becomes research
        evidence, keeping the local cache bounded and avoiding a stored copy
        of the full upstream catalogue.
        """
        documents: List[ResearchDocument] = []
        try:
            url, body, _ = self.client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cve_id, safe='')}"
            )
            documents.append(self._document("nvd", url, body, f"NVD record for {cve_id}"))
        except (requests.RequestException, ResearchSafetyError):
            pass
        try:
            url, body, _ = self.client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            payload = json.loads(body.decode("utf-8", errors="replace"))
            match = next((item for item in payload.get("vulnerabilities") or []
                          if str(item.get("cveID") or "").upper() == cve_id), None)
            if match:
                documents.append(self._document(
                    "cisa-kev", url, json.dumps(match, sort_keys=True).encode("utf-8"),
                    f"CISA KEV entry for {cve_id}",
                ))
        except (ValueError, requests.RequestException, ResearchSafetyError):
            pass
        return documents

    def _threat_intelligence(self, indicator: str) -> List[ResearchDocument]:
        documents = []
        for name, config, path, header in (
            ("virustotal", self.config.virustotal, f"/ip_addresses/{quote(indicator, safe='')}", "x-apikey"),
            ("abuseipdb", self.config.abuseipdb, "/check", "Key"),
        ):
            if not config.enabled:
                continue
            try:
                secret = self.credentials.get(config.credential_ref)
                if not secret:
                    continue
                url = f"{config.base_url.rstrip('/')}{path}"
                if name == "abuseipdb":
                    url += f"?ipAddress={quote(indicator, safe='')}&maxAgeInDays=90"
                    headers = {header: secret, "Accept": "application/json"}
                else:
                    headers = {header: secret, "Accept": "application/json"}
                canonical, body, _ = self.client.get(url, headers=headers)
                documents.append(self._document(name, canonical, body, f"{name} reputation for {indicator}"))
            except Exception:
                continue
        return documents

    def _open_web(self, query: str, provider: str) -> List[ResearchDocument]:
        if provider == "openai":
            return self._openai_web(query)
        if provider != "brave":
            raise ValueError("web_provider must be brave or openai")
        config = self.config.brave
        if not config.enabled:
            return []
        try:
            secret = self.credentials.get(config.credential_ref)
            if not secret:
                return []
            url = f"{config.base_url.rstrip('/')}/res/v1/web/search?q={quote(query, safe='')}"
            canonical, body, _ = self.client.get(url, headers={"X-Subscription-Token": secret, "Accept": "application/json"})
            payload = json.loads(body.decode("utf-8", errors="replace"))
            documents = []
            for item in (payload.get("web") or {}).get("results") or []:
                target = item.get("url")
                if not target:
                    continue
                text = json.dumps({"title": item.get("title"), "description": item.get("description"), "url": target}).encode("utf-8")
                documents.append(self._document("brave", _canonical_url(target), text, str(item.get("title") or "Web result")))
            return documents
        except Exception:
            return []

    def _openai_web(self, query: str) -> List[ResearchDocument]:
        config = self.config.openai
        if not config.enabled:
            return []
        try:
            secret = self.credentials.get(config.credential_ref)
            if not secret:
                return []
            endpoint = _canonical_url(f"{config.base_url.rstrip('/')}/responses")
            response = requests.post(
                endpoint,
                headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
                json={"model": config.model, "tools": [{"type": "web_search"}], "input": query, "max_output_tokens": 1000},
                timeout=(4, 30), allow_redirects=False,
            )
            response.raise_for_status()
            payload = response.json()
            text = str(payload.get("output_text") or "")
            sources = []
            for output in payload.get("output") or []:
                for content in output.get("content") or []:
                    for annotation in content.get("annotations") or []:
                        if annotation.get("type") not in {"url_citation", "url"}:
                            continue
                        url = annotation.get("url")
                        if url:
                            sources.append((url, str(annotation.get("title") or "OpenAI web source")))
            documents = []
            for url, title in sources[:8]:
                try:
                    documents.append(self._document("openai-web-search", _canonical_url(url), text.encode("utf-8"), title))
                except ResearchSafetyError:
                    continue
            if not documents and text:
                documents.append(self._document("openai-web-search", endpoint, text.encode("utf-8"), "OpenAI web search"))
            return documents
        except Exception:
            return []

    def _cache(self, document: ResearchDocument) -> None:
        if not self.db or not hasattr(self.db, "cache_ai_research_document"):
            return
        self.db.cache_ai_research_document({"id": str(uuid.uuid4()), **asdict(document)})
