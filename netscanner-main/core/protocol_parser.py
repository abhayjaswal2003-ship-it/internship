"""
NetScope Pro - Protocol Parser Module
Dissects network packets across Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, and TLS SNI layers.
"""

import re
from typing import Dict, Any, List, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Try importing HTTP layers from Scapy if available
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
    HAS_SCAPY_HTTP = True
except ImportError:
    HAS_SCAPY_HTTP = False


class ProtocolParser:
    """
    Parser for extracting structured protocol headers, forensic fields, and payload contents
    from Scapy packet structures.
    """

    @staticmethod
    def parse_packet(pkt: scapy.Packet, index: int = 0) -> Dict[str, Any]:
        """
        Parses a single Scapy packet into a rich dictionary representation.
        """
        time_epoch = float(pkt.time) if hasattr(pkt, 'time') else 0.0
        pkt_len = len(pkt)

        # Layer 2 & 3 Defaults
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ""
        eth_type = hex(pkt[Ether].type) if pkt.haslayer(Ether) and hasattr(pkt[Ether], 'type') else ""

        src_ip = ""
        dst_ip = ""
        ip_version = 4
        ttl = 64

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_version = 4
            ttl = pkt[IP].ttl
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ip_version = 6
            ttl = pkt[IPv6].hlim

        # Layer 4 Defaults
        protocol = "Other"
        src_port = None
        dst_port = None
        tcp_flags = ""
        info_summary = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = ProtocolParser._parse_tcp_flags(pkt[TCP].flags)
            info_summary = f"{src_port} → {dst_port} [{tcp_flags}] Seq={pkt[TCP].seq} Ack={pkt[TCP].ack} Win={pkt[TCP].window}"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            info_summary = f"{src_port} → {dst_port} Len={pkt[UDP].len}"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = pkt[ICMP].type
            icmp_code = pkt[ICMP].code
            info_summary = f"Type={icmp_type} Code={icmp_code}"
        elif pkt.haslayer(ARP):
            protocol = "ARP"
            op = "Request" if pkt[ARP].op == 1 else "Reply" if pkt[ARP].op == 2 else str(pkt[ARP].op)
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            info_summary = f"Who has {dst_ip}? Tell {src_ip}" if op == "Request" else f"{src_ip} is at {pkt[ARP].hwsrc}"

        # Application Layer Parsers
        http_data = ProtocolParser._parse_http(pkt)
        dns_data = ProtocolParser._parse_dns(pkt)
        tls_sni = ProtocolParser._parse_tls_sni(pkt)

        if http_data:
            protocol = "HTTP"
            if http_data.get("is_request"):
                info_summary = f"{http_data.get('method')} {http_data.get('path')} {http_data.get('version')}"
            else:
                info_summary = f"HTTP {http_data.get('status_code')} {http_data.get('reason')} ({http_data.get('content_type', '')})"
        elif dns_data:
            protocol = "DNS"
            if dns_data.get("is_query"):
                info_summary = f"Standard query {dns_data.get('qtype')} {dns_data.get('qname')}"
            else:
                ans_str = ", ".join([a.get("rdata", "") for a in dns_data.get("answers", [])[:2]])
                info_summary = f"Standard query response {dns_data.get('qname')} -> {ans_str}"
        elif tls_sni:
            protocol = "TLS"
            info_summary = f"Client Hello SNI: {tls_sni}"
        elif src_port == 443 or dst_port == 443:
            protocol = "TLS/HTTPS"

        # Raw Bytes & Hex Dump
        raw_bytes = bytes(pkt)
        hex_dump = ProtocolParser._build_hex_dump(raw_bytes)

        return {
            "index": index,
            "time": time_epoch,
            "length": pkt_len,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "eth_type": eth_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_version": ip_version,
            "ttl": ttl,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "info": info_summary,
            "http": http_data,
            "dns": dns_data,
            "tls_sni": tls_sni,
            "hex_dump": hex_dump,
            "tree_structure": ProtocolParser._build_tree_structure(pkt, http_data, dns_data, tls_sni)
        }

    @staticmethod
    def _parse_tcp_flags(flags) -> str:
        """Converts TCP flags to human readable string (SYN, ACK, FIN, etc.)."""
        flag_map = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
            'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
        }
        res = []
        flag_str = str(flags)
        for char, name in flag_map.items():
            if char in flag_str:
                res.append(name)
        return ", ".join(res) if res else str(flags)

    @staticmethod
    def _parse_http(pkt: scapy.Packet) -> Optional[Dict[str, Any]]:
        """Extracts HTTP header fields and payload from packet."""
        # 1. Scapy built-in HTTP layers check
        if HAS_SCAPY_HTTP:
            if pkt.haslayer(HTTPRequest):
                req = pkt[HTTPRequest]
                headers = {}
                if hasattr(req, 'fields'):
                    for k, v in req.fields.items():
                        if isinstance(v, bytes):
                            try:
                                headers[k.decode('utf-8', errors='ignore')] = v.decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                
                method = req.Method.decode('utf-8', errors='ignore') if hasattr(req, 'Method') and req.Method else "GET"
                path = req.Path.decode('utf-8', errors='ignore') if hasattr(req, 'Path') and req.Path else "/"
                host = req.Host.decode('utf-8', errors='ignore') if hasattr(req, 'Host') and req.Host else ""
                user_agent = req.User_Agent.decode('utf-8', errors='ignore') if hasattr(req, 'User_Agent') and req.User_Agent else ""
                content_type = req.Content_Type.decode('utf-8', errors='ignore') if hasattr(req, 'Content_Type') and req.Content_Type else ""
                authorization = req.Authorization.decode('utf-8', errors='ignore') if hasattr(req, 'Authorization') and req.Authorization else ""
                cookie = req.Cookie.decode('utf-8', errors='ignore') if hasattr(req, 'Cookie') and req.Cookie else ""

                payload_body = ""
                if req.payload:
                    payload_body = bytes(req.payload).decode('utf-8', errors='ignore')

                return {
                    "is_request": True,
                    "method": method,
                    "path": path,
                    "version": "HTTP/1.1",
                    "host": host,
                    "user_agent": user_agent,
                    "content_type": content_type,
                    "authorization": authorization,
                    "cookie": cookie,
                    "headers": headers,
                    "body": payload_body
                }

            elif pkt.haslayer(HTTPResponse):
                res = pkt[HTTPResponse]
                headers = {}
                if hasattr(res, 'fields'):
                    for k, v in res.fields.items():
                        if isinstance(v, bytes):
                            try:
                                headers[k.decode('utf-8', errors='ignore')] = v.decode('utf-8', errors='ignore')
                            except Exception:
                                pass

                status_code = req_code = res.Status_Code.decode('utf-8', errors='ignore') if hasattr(res, 'Status_Code') and res.Status_Code else "200"
                reason = res.Reason_Phrase.decode('utf-8', errors='ignore') if hasattr(res, 'Reason_Phrase') and res.Reason_Phrase else "OK"
                server = res.Server.decode('utf-8', errors='ignore') if hasattr(res, 'Server') and res.Server else ""
                content_type = res.Content_Type.decode('utf-8', errors='ignore') if hasattr(res, 'Content_Type') and res.Content_Type else ""

                payload_body = ""
                if res.payload:
                    payload_body = bytes(res.payload).decode('utf-8', errors='ignore')

                return {
                    "is_request": False,
                    "status_code": status_code,
                    "reason": reason,
                    "version": "HTTP/1.1",
                    "server": server,
                    "content_type": content_type,
                    "headers": headers,
                    "body": payload_body
                }

        # 2. Fallback raw TCP payload HTTP dissector
        if pkt.haslayer(TCP) and (pkt[TCP].dport in (80, 8080, 8000) or pkt[TCP].sport in (80, 8080, 8000)):
            payload = bytes(pkt[TCP].payload)
            if not payload:
                return None

            raw_str = payload.decode('utf-8', errors='ignore')

            # HTTP Request regex
            req_match = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+(HTTP/\d\.\d)', raw_str)
            if req_match:
                lines = raw_str.split('\r\n')
                first_line = lines[0]
                method, path, version = req_match.groups()
                headers = {}
                body = ""
                in_body = False

                for line in lines[1:]:
                    if in_body:
                        body += line + "\n"
                    elif line == "":
                        in_body = True
                    elif ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

                return {
                    "is_request": True,
                    "method": method,
                    "path": path,
                    "version": version,
                    "host": headers.get("Host", ""),
                    "user_agent": headers.get("User-Agent", ""),
                    "content_type": headers.get("Content-Type", ""),
                    "authorization": headers.get("Authorization", ""),
                    "cookie": headers.get("Cookie", ""),
                    "headers": headers,
                    "body": body.strip()
                }

            # HTTP Response regex
            resp_match = re.match(r'^(HTTP/\d\.\d)\s+(\d{3})\s*(.*)', raw_str)
            if resp_match:
                lines = raw_str.split('\r\n')
                version, code, reason = resp_match.groups()
                headers = {}
                body = ""
                in_body = False

                for line in lines[1:]:
                    if in_body:
                        body += line + "\n"
                    elif line == "":
                        in_body = True
                    elif ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

                return {
                    "is_request": False,
                    "status_code": code,
                    "reason": reason.strip(),
                    "version": version,
                    "server": headers.get("Server", ""),
                    "content_type": headers.get("Content-Type", ""),
                    "headers": headers,
                    "body": body.strip()
                }

        return None

    @staticmethod
    def _parse_dns(pkt: scapy.Packet) -> Optional[Dict[str, Any]]:
        """Extracts DNS queries and answer records."""
        if not pkt.haslayer(DNS):
            return None

        dns = pkt[DNS]
        is_query = (getattr(dns, 'qr', 0) == 0)

        qname = ""
        qtype = ""
        qd = getattr(dns, 'qd', None)
        if qd:
            try:
                first_qd = qd[0] if (hasattr(qd, '__getitem__') and not isinstance(qd, scapy.Packet)) else qd
            except Exception:
                first_qd = qd
            if hasattr(first_qd, 'qname'):
                qname_raw = first_qd.qname
                qname = qname_raw.decode('utf-8', errors='ignore').rstrip('.') if isinstance(qname_raw, bytes) else str(qname_raw).rstrip('.')
            if hasattr(first_qd, 'qtype'):
                type_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 5: "CNAME", 2: "NS", 12: "PTR"}
                qtype = type_map.get(first_qd.qtype, f"TYPE{first_qd.qtype}")

        answers = []
        ancount = getattr(dns, 'ancount', 0) or 0
        an = getattr(dns, 'an', None)
        if ancount > 0 and an:
            try:
                an_list = list(an) if hasattr(an, '__iter__') else [an]
            except Exception:
                an_list = [an]

            for curr in an_list:
                if hasattr(curr, 'rrname'):
                    rrname = curr.rrname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(curr.rrname, bytes) else str(curr.rrname).rstrip('.')
                    rdata = getattr(curr, 'rdata', '')
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode('utf-8', errors='ignore')
                    else:
                        rdata = str(rdata)
                    type_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 5: "CNAME", 2: "NS", 12: "PTR"}
                    rrtype = type_map.get(getattr(curr, 'type', 1), str(getattr(curr, 'type', 1)))
                    answers.append({
                        "name": rrname,
                        "type": rrtype,
                        "ttl": getattr(curr, 'ttl', 0),
                        "rdata": rdata
                    })

        return {
            "id": getattr(dns, 'id', 0) or 0,
            "is_query": is_query,
            "rcode": getattr(dns, 'rcode', 0) or 0,
            "qname": qname,
            "qtype": qtype,
            "ancount": len(answers),
            "answers": answers
        }

    @staticmethod
    def _parse_tls_sni(pkt: scapy.Packet) -> str:
        """Extracts TLS Server Name Indication (SNI) hostname from Client Hello packets."""
        if not pkt.haslayer(TCP):
            return ""

        payload = bytes(pkt[TCP].payload)
        if len(payload) < 43 or payload[0] != 0x16:  # Handshake record
            return ""

        try:
            # Check for Client Hello (0x01)
            if payload[5] != 0x01:
                return ""

            # Parse extensions to locate SNI (extension 0x0000)
            sess_id_len = payload[43]
            idx = 44 + sess_id_len
            if idx + 2 > len(payload):
                return ""
            
            cipher_len = int.from_bytes(payload[idx:idx+2], byteorder='big')
            idx += 2 + cipher_len
            if idx + 1 > len(payload):
                return ""

            comp_len = payload[idx]
            idx += 1 + comp_len
            if idx + 2 > len(payload):
                return ""

            ext_len = int.from_bytes(payload[idx:idx+2], byteorder='big')
            idx += 2
            end_ext = idx + ext_len

            while idx + 4 <= end_ext and idx + 4 <= len(payload):
                ext_type = int.from_bytes(payload[idx:idx+2], byteorder='big')
                ext_data_len = int.from_bytes(payload[idx+2:idx+4], byteorder='big')
                idx += 4

                if ext_type == 0:  # Server Name Extension
                    sni_name_len = int.from_bytes(payload[idx+3:idx+5], byteorder='big')
                    sni_name = payload[idx+5:idx+5+sni_name_len].decode('utf-8', errors='ignore')
                    return sni_name

                idx += ext_data_len
        except Exception:
            pass

        return ""

    @staticmethod
    def _build_hex_dump(raw_bytes: bytes) -> str:
        """Generates traditional 16-byte formatted Hex + ASCII dump string."""
        lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04X}  {hex_part:<47}  |{ascii_part}|")
        return "\n".join(lines)

    @staticmethod
    def _build_tree_structure(pkt: scapy.Packet, http_data: Optional[Dict], dns_data: Optional[Dict], tls_sni: str) -> List[Dict[str, Any]]:
        """Constructs a collapsible node tree hierarchy for PyQt QTreeWidget."""
        tree = []

        # 1. Frame Layer
        tree.append({
            "label": f"Frame {getattr(pkt, 'wirelen', len(pkt))} bytes on wire, {len(pkt)} bytes captured",
            "children": [
                {"label": f"Epoch Arrival Time: {getattr(pkt, 'time', 0.0)}"},
                {"label": f"Frame Length: {len(pkt)} bytes"}
            ]
        })

        # 2. Ethernet Layer
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            tree.append({
                "label": f"Ethernet II, Src: {eth.src}, Dst: {eth.dst}",
                "children": [
                    {"label": f"Destination MAC: {eth.dst}"},
                    {"label": f"Source MAC: {eth.src}"},
                    {"label": f"Type: {hex(eth.type)}"}
                ]
            })

        # 3. IP / IPv6 Layer
        if pkt.haslayer(IP):
            ip = pkt[IP]
            ihl_val = (ip.ihl * 4) if getattr(ip, 'ihl', None) is not None else 20
            ip_id = hex(ip.id) if getattr(ip, 'id', None) is not None else "0x0"
            tree.append({
                "label": f"Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}",
                "children": [
                    {"label": f"Version: 4"},
                    {"label": f"Header Length: {ihl_val} bytes"},
                    {"label": f"Total Length: {getattr(ip, 'len', 0)}"},
                    {"label": f"Identification: {ip_id}"},
                    {"label": f"Time to Live (TTL): {getattr(ip, 'ttl', 64)}"},
                    {"label": f"Protocol: {getattr(ip, 'proto', 6)}"},
                    {"label": f"Source Address: {ip.src}"},
                    {"label": f"Destination Address: {ip.dst}"}
                ]
            })
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            tree.append({
                "label": f"Internet Protocol Version 6, Src: {ip6.src}, Dst: {ip6.dst}",
                "children": [
                    {"label": f"Version: 6"},
                    {"label": f"Payload Length: {getattr(ip6, 'plen', 0)}"},
                    {"label": f"Hop Limit: {getattr(ip6, 'hlim', 64)}"},
                    {"label": f"Source Address: {ip6.src}"},
                    {"label": f"Destination Address: {ip6.dst}"}
                ]
            })

        # 4. Transport Layer (TCP / UDP / ICMP / ARP)
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags_str = ProtocolParser._parse_tcp_flags(tcp.flags)
            hdr_len = (tcp.dataofs * 4) if getattr(tcp, 'dataofs', None) is not None else 20
            chksum_val = hex(tcp.chksum) if getattr(tcp, 'chksum', None) is not None else "0x0"
            tree.append({
                "label": f"Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}, Flags: [{flags_str}]",
                "children": [
                    {"label": f"Source Port: {tcp.sport}"},
                    {"label": f"Destination Port: {tcp.dport}"},
                    {"label": f"Sequence Number: {tcp.seq}"},
                    {"label": f"Acknowledgment Number: {tcp.ack}"},
                    {"label": f"Header Length: {hdr_len} bytes"},
                    {"label": f"Flags: {flags_str}"},
                    {"label": f"Window Size: {getattr(tcp, 'window', 0)}"},
                    {"label": f"Checksum: {chksum_val}"}
                ]
            })
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            udp_chksum = hex(udp.chksum) if getattr(udp, 'chksum', None) is not None else "0x0"
            tree.append({
                "label": f"User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}",
                "children": [
                    {"label": f"Source Port: {udp.sport}"},
                    {"label": f"Destination Port: {udp.dport}"},
                    {"label": f"Length: {getattr(udp, 'len', 0)}"},
                    {"label": f"Checksum: {udp_chksum}"}
                ]
            })
        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            ptype_val = hex(arp.ptype) if getattr(arp, 'ptype', None) is not None else "0x0800"
            tree.append({
                "label": f"Address Resolution Protocol (Opcode {arp.op})",
                "children": [
                    {"label": f"Hardware Type: {arp.hwtype}"},
                    {"label": f"Protocol Type: {ptype_val}"},
                    {"label": f"Opcode: {arp.op}"},
                    {"label": f"Sender MAC: {arp.hwsrc}"},
                    {"label": f"Sender IP: {arp.psrc}"},
                    {"label": f"Target MAC: {arp.hwdst}"},
                    {"label": f"Target IP: {arp.pdst}"}
                ]
            })

        # 5. Application Layer (HTTP / DNS / TLS)
        if http_data:
            children = []
            if http_data.get("is_request"):
                children.append({"label": f"Request Line: {http_data.get('method')} {http_data.get('path')} {http_data.get('version')}"})
                children.append({"label": f"Host: {http_data.get('host')}"})
                children.append({"label": f"User-Agent: {http_data.get('user_agent')}"})
            else:
                children.append({"label": f"Response Line: {http_data.get('version')} {http_data.get('status_code')} {http_data.get('reason')}"})
                children.append({"label": f"Server: {http_data.get('server')}"})

            headers_node = {"label": "Headers", "children": []}
            for hk, hv in http_data.get("headers", {}).items():
                headers_node["children"].append({"label": f"{hk}: {hv}"})
            children.append(headers_node)

            if http_data.get("body"):
                children.append({"label": f"Payload Body ({len(http_data['body'])} chars)"})

            tree.append({
                "label": "Hypertext Transfer Protocol (HTTP)",
                "children": children
            })

        elif dns_data:
            dns_id_val = hex(dns_data['id']) if dns_data.get('id') is not None else "0x0"
            children = [
                {"label": f"Transaction ID: {dns_id_val}"},
                {"label": f"Type: {'Query' if dns_data['is_query'] else 'Response'}"},
                {"label": f"Query Domain: {dns_data['qname']}"},
                {"label": f"Query Type: {dns_data['qtype']}"}
            ]
            if dns_data.get("answers"):
                ans_node = {"label": f"Answers ({len(dns_data['answers'])})", "children": []}
                for a in dns_data["answers"]:
                    ans_node["children"].append({"label": f"{a['name']} ({a['type']}) -> {a['rdata']} [TTL: {a['ttl']}]"})
                children.append(ans_node)

            tree.append({
                "label": "Domain Name System (DNS)",
                "children": children
            })

        elif tls_sni:
            tree.append({
                "label": "Transport Layer Security (TLS)",
                "children": [
                    {"label": f"Server Name Indication (SNI): {tls_sni}"}
                ]
            })

        return tree
