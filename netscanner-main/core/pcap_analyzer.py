"""
NetScope Pro - PCAP & Forensic Analyzer Engine
Imports, reads, and analyzes .pcap / .pcapng files for forensic investigation.
"""

import os
import math
from typing import List, Dict, Any, Tuple, Optional
import scapy.all as scapy
from core.protocol_parser import ProtocolParser

class PcapAnalyzer:
    """
    Forensic analysis engine for offline .pcap / .pcapng file examination
    and packet stream investigation.
    """

    def __init__(self):
        self.filepath: str = ""
        self.packets: List[scapy.Packet] = []
        self.parsed_packets: List[Dict[str, Any]] = []
        self.duration: float = 0.0

    def load_pcap(self, filepath: str, max_packets: int = 10000) -> bool:
        """
        Loads and parses a .pcap / .pcapng file into memory.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        self.filepath = filepath
        self.packets = []
        self.parsed_packets = []

        try:
            # Read packets using Scapy
            raw_packets = scapy.rdpcap(filepath)
            count = 0
            start_time = None
            end_time = None

            for idx, pkt in enumerate(raw_packets):
                if count >= max_packets:
                    break
                
                t = float(pkt.time) if hasattr(pkt, 'time') else 0.0
                if start_time is None or t < start_time:
                    start_time = t
                if end_time is None or t > end_time:
                    end_time = t

                self.packets.append(pkt)
                parsed = ProtocolParser.parse_packet(pkt, index=idx + 1)
                self.parsed_packets.append(parsed)
                count += 1

            self.duration = max(0.0, (end_time - start_time)) if (start_time and end_time) else 0.0
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to parse PCAP file '{filepath}': {e}")

    def load_from_raw_packets(self, scapy_packets: List[scapy.Packet]):
        """Populates analyzer from an in-memory list of Scapy packets (e.g. live sniff)."""
        self.filepath = "Live Capture"
        self.packets = scapy_packets
        self.parsed_packets = []
        start_time = None
        end_time = None

        for idx, pkt in enumerate(scapy_packets):
            t = float(pkt.time) if hasattr(pkt, 'time') else 0.0
            if start_time is None or t < start_time:
                start_time = t
            if end_time is None or t > end_time:
                end_time = t

            parsed = ProtocolParser.parse_packet(pkt, index=idx + 1)
            self.parsed_packets.append(parsed)

        self.duration = max(0.0, (end_time - start_time)) if (start_time and end_time) else 0.0

    def get_summary_stats(self) -> Dict[str, Any]:
        """Returns overall capture metrics and protocol distribution counts."""
        total_pkts = len(self.parsed_packets)
        total_bytes = sum(p["length"] for p in self.parsed_packets)

        proto_counts: Dict[str, int] = {}
        proto_bytes: Dict[str, int] = {}

        for p in self.parsed_packets:
            proto = p["protocol"]
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
            proto_bytes[proto] = proto_bytes.get(proto, 0) + p["length"]

        avg_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        pkt_rate = (total_pkts / self.duration) if self.duration > 0 else 0.0

        return {
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "duration_sec": round(self.duration, 2),
            "avg_packet_size": round(avg_size, 1),
            "packet_rate": round(pkt_rate, 1),
            "protocol_counts": proto_counts,
            "protocol_bytes": proto_bytes
        }

    def get_top_talkers(self, top_n: int = 10) -> Dict[str, List[Tuple[str, int, int]]]:
        """Calculates top IP sources and top IP destinations by packet count & bytes."""
        src_stats: Dict[str, Dict[str, int]] = {}
        dst_stats: Dict[str, Dict[str, int]] = {}

        for p in self.parsed_packets:
            src = p.get("src_ip")
            dst = p.get("dst_ip")
            length = p.get("length", 0)

            if src:
                if src not in src_stats:
                    src_stats[src] = {"count": 0, "bytes": 0}
                src_stats[src]["count"] += 1
                src_stats[src]["bytes"] += length

            if dst:
                if dst not in dst_stats:
                    dst_stats[dst] = {"count": 0, "bytes": 0}
                dst_stats[dst]["count"] += 1
                dst_stats[dst]["bytes"] += length

        top_src = sorted(
            [(ip, stat["count"], stat["bytes"]) for ip, stat in src_stats.items()],
            key=lambda x: x[2], reverse=True
        )[:top_n]

        top_dst = sorted(
            [(ip, stat["count"], stat["bytes"]) for ip, stat in dst_stats.items()],
            key=lambda x: x[2], reverse=True
        )[:top_n]

        return {"top_sources": top_src, "top_destinations": top_dst}

    def get_conversations(self) -> List[Dict[str, Any]]:
        """Aggregates IP conversation flows (Src <-> Dst pairs)."""
        convs: Dict[Tuple[str, str, str], Dict[str, int]] = {}

        for p in self.parsed_packets:
            src = p.get("src_ip")
            dst = p.get("dst_ip")
            proto = p.get("protocol", "Other")
            length = p.get("length", 0)

            if not src or not dst:
                continue

            # Standardize key (pair)
            pair_key = (src, dst, proto) if src <= dst else (dst, src, proto)
            if pair_key not in convs:
                convs[pair_key] = {"packets": 0, "bytes": 0}

            convs[pair_key]["packets"] += 1
            convs[pair_key]["bytes"] += length

        result = []
        for (ip1, ip2, proto), stats in convs.items():
            result.append({
                "host_a": ip1,
                "host_b": ip2,
                "protocol": proto,
                "packets": stats["packets"],
                "bytes": stats["bytes"]
            })

        return sorted(result, key=lambda x: x["bytes"], reverse=True)

    def get_http_logs(self) -> List[Dict[str, Any]]:
        """Extracts all HTTP request & response transactions."""
        logs = []
        for p in self.parsed_packets:
            http = p.get("http")
            if http:
                logs.append({
                    "packet_index": p["index"],
                    "time": p["time"],
                    "src": p["src_ip"],
                    "dst": p["dst_ip"],
                    "is_request": http.get("is_request", True),
                    "method": http.get("method", ""),
                    "url": f"http://{http.get('host', '')}{http.get('path', '')}" if http.get("is_request") else "",
                    "host": http.get("host", ""),
                    "status_code": http.get("status_code", ""),
                    "content_type": http.get("content_type", ""),
                    "user_agent": http.get("user_agent", ""),
                    "auth": http.get("authorization", ""),
                    "cookie": http.get("cookie", ""),
                    "headers": http.get("headers", {}),
                    "body": http.get("body", "")
                })
        return logs

    def get_dns_logs(self) -> List[Dict[str, Any]]:
        """Extracts all DNS query and response transactions."""
        logs = []
        for p in self.parsed_packets:
            dns = p.get("dns")
            if dns:
                ans_summary = []
                for a in dns.get("answers", []):
                    ans_summary.append(f"{a.get('type')} {a.get('rdata')}")

                logs.append({
                    "packet_index": p["index"],
                    "time": p["time"],
                    "src": p["src_ip"],
                    "dst": p["dst_ip"],
                    "is_query": dns.get("is_query", True),
                    "qname": dns.get("qname", ""),
                    "qtype": dns.get("qtype", ""),
                    "answers": ", ".join(ans_summary) if ans_summary else "No Answers",
                    "raw_answers": dns.get("answers", [])
                })
        return logs

    def get_security_alerts(self) -> List[Dict[str, Any]]:
        """
        Forensic anomaly detection rules:
        - Plaintext HTTP authentication / Credentials
        - ARP Spoofing / Duplicate IP to MAC mapping
        - TCP Port Scan / Host Probing detection
        - Suspicious High Entropy / Long DNS DGA domains
        """
        alerts = []

        # 1. HTTP Plaintext Authorization & Cookies
        for p in self.parsed_packets:
            http = p.get("http")
            if http and http.get("authorization"):
                auth_str = http.get("authorization")
                alerts.append({
                    "level": "CRITICAL",
                    "category": "Cleartext Authentication",
                    "title": f"Cleartext Credentials Detected in HTTP Packet #{p['index']}",
                    "details": f"Host: {http.get('host')} | Auth Header: {auth_str[:50]}...",
                    "src_ip": p["src_ip"],
                    "dst_ip": p["dst_ip"]
                })

        # 2. ARP Poisoning / Spoofing Detection
        ip_mac_map: Dict[str, set] = {}
        for p in self.parsed_packets:
            if p["protocol"] == "ARP" and p["src_ip"] and p["src_mac"]:
                ip = p["src_ip"]
                mac = p["src_mac"]
                if ip not in ip_mac_map:
                    ip_mac_map[ip] = set()
                ip_mac_map[ip].add(mac)

        for ip, macs in ip_mac_map.items():
            if len(macs) > 1:
                alerts.append({
                    "level": "HIGH",
                    "category": "ARP Spoofing / Poisoning",
                    "title": f"Multiple MAC addresses claimed IP {ip}",
                    "details": f"Observed MACs for {ip}: {', '.join(macs)}",
                    "src_ip": ip,
                    "dst_ip": "Broadcast"
                })

        # 3. TCP Port Sweep / Scan Detection
        scanner_ports: Dict[str, set] = {}
        for p in self.parsed_packets:
            if p["protocol"] == "TCP" and "SYN" in p.get("tcp_flags", ""):
                src = p["src_ip"]
                dst_port = p["dst_port"]
                if src and dst_port:
                    if src not in scanner_ports:
                        scanner_ports[src] = set()
                    scanner_ports[src].add(dst_port)

        for src, ports in scanner_ports.items():
            if len(ports) >= 15:
                alerts.append({
                    "level": "MEDIUM",
                    "category": "Port Scanning Activity",
                    "title": f"Potential TCP Port Scan from Host {src}",
                    "details": f"Host {src} targeted {len(ports)} distinct ports in this capture.",
                    "src_ip": src,
                    "dst_ip": "Multiple"
                })

        # 4. DNS High Entropy / DGA Domain Detection
        for p in self.parsed_packets:
            dns = p.get("dns")
            if dns and dns.get("qname"):
                qname = dns.get("qname", "")
                subdomain = qname.split('.')[0] if '.' in qname else qname
                if len(subdomain) > 20 and self._calculate_entropy(subdomain) > 3.8:
                    alerts.append({
                        "level": "WARNING",
                        "category": "DNS Anomaly / DGA Domain",
                        "title": f"High Entropy / DGA Domain Query Detected",
                        "details": f"Domain: '{qname}' (Entropy: {round(self._calculate_entropy(subdomain), 2)})",
                        "src_ip": p["src_ip"],
                        "dst_ip": p["dst_ip"]
                    })

        return alerts

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculates Shannon Entropy of a domain string to detect DGA/tunneling."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
