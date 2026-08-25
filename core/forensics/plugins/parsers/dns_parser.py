import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from typing import Dict, Any
from core.forensics.base import BaseParser

class DNSParser(BaseParser):
    name = "DNS Parser"
    watched_ports = (53,)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                domain = query.rstrip('.')
                dns = packet[DNS]
                question = packet[DNSQR]
                answers = []
                answer = dns.an
                # A bounded answer list is enough to correlate normal DNS
                # without letting a malformed packet grow flow metadata.
                if isinstance(answer, (list, tuple)):
                    answer_records = list(answer)[:32]
                else:
                    answer_records = []
                    for _ in range(min(int(dns.ancount or 0), 32)):
                        if not isinstance(answer, DNSRR):
                            break
                        answer_records.append(answer)
                        answer = answer.payload
                for answer in answer_records:
                    if not hasattr(answer, "type"):
                        continue
                    record_type = int(getattr(answer, "type", 0) or 0)
                    if record_type in {1, 28}:  # A / AAAA
                        try:
                            address = str(answer.rdata)
                            # Validate textual address representation before
                            # handing it to the enrichment index.
                            import ipaddress
                            ipaddress.ip_address(address)
                            raw_name = getattr(answer, "rrname", b"")
                            answer_name = (
                                raw_name.decode("utf-8", errors="ignore")
                                if isinstance(raw_name, bytes) else str(raw_name)
                            )
                            answers.append({
                                "name": answer_name.rstrip(".").lower(),
                                "address": address,
                                "type": "A" if record_type == 1 else "AAAA",
                                "ttl": max(0, min(int(getattr(answer, "ttl", 0) or 0), 86400)),
                            })
                        except (TypeError, ValueError):
                            pass
                return {
                    "identities": {"remote_hostname": domain},
                    "metadata": {
                        "dns_domain": domain.lower(),
                        "dns_qtype": int(question.qtype or 0),
                        "dns_is_response": bool(int(dns.qr or 0)),
                        "dns_rcode": int(dns.rcode or 0),
                        "dns_nxdomain": int(dns.rcode or 0) == 3,
                        "dns_query_name_bytes": len(domain.encode("utf-8", errors="ignore")),
                        "dns_answers": answers,
                    },
                }
            except Exception:
                pass
        return {}
