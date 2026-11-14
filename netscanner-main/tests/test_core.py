import unittest
import os
import tempfile
from pathlib import Path

from core.oui_lookup import format_mac, lookup_vendor, guess_device_type
from core.network_info import get_active_network_info
from database.db_manager import DatabaseManager
from utils.exporter import Exporter

class TestNetScopeCore(unittest.TestCase):

    def test_oui_lookup(self):
        # Test MAC formatting
        self.assertEqual(format_mac("001124aabbcc"), "00:11:24:AA:BB:CC")
        self.assertEqual(format_mac("00-11-24-aa-bb-cc"), "00:11:24:AA:BB:CC")

        # Test Vendor Lookup
        self.assertEqual(lookup_vendor("00:03:93:11:22:33"), "Apple Inc.")
        self.assertEqual(lookup_vendor("00:0C:29:AA:BB:CC"), "VMware Inc.")
        self.assertEqual(lookup_vendor("FF:FF:FF:FF:FF:FF"), "Unknown")

        # Test Device Type Guessing
        self.assertEqual(guess_device_type("Cisco Systems", "gateway.local"), "Router")
        self.assertEqual(guess_device_type("Canon Inc.", "printer-office"), "Printer")
        self.assertEqual(guess_device_type("Apple Inc.", "MacBook-Pro.local"), "Computer")
        self.assertEqual(guess_device_type("Raspberry Pi Foundation", "raspberrypi"), "IoT Device")

    def test_network_info(self):
        info = get_active_network_info()
        self.assertIn("local_ip", info)
        self.assertIn("mac_address", info)
        self.assertIn("gateway", info)
        self.assertIn("subnet_mask", info)
        self.assertIn("cidr", info)
        self.assertTrue(info["local_ip"].count(".") == 3)

    def test_database_manager(self):
        tmp_dir = tempfile.mkdtemp()
        db_file = Path(tmp_dir) / "test_netscope.db"
        try:
            db = DatabaseManager(db_file)

            test_device = {
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.50",
                "hostname": "Test-PC",
                "vendor": "Dell Inc.",
                "device_type": "Computer",
                "latency": 5.2,
                "status": "Online"
            }

            # Insert
            event1 = db.upsert_device(test_device)
            self.assertEqual(event1, "New Device Joined")

            # Query
            devices = db.get_all_devices()
            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0]["mac"], "00:11:22:33:44:55")
            self.assertEqual(devices[0]["hostname"], "Test-PC")

            # Update notes
            db.update_device_notes("00:11:22:33:44:55", "Test admin note")
            devs_updated = db.get_all_devices()
            self.assertEqual(devs_updated[0]["notes"], "Test admin note")

            # Add Log
            db.add_log("INFO", "TestRunner", "Unit test logging check")
            logs = db.get_logs()
            self.assertTrue(len(logs) >= 1)
            self.assertEqual(logs[0]["message"], "Unit test logging check")

        finally:
            # Force GC / cleanup on temp DB file
            del db
            try:
                if db_file.exists():
                    os.remove(db_file)
                os.rmdir(tmp_dir)
            except Exception:
                pass

    def test_exporters(self):
        dummy_data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router.home",
                "vendor": "Cisco Systems",
                "device_type": "Router",
                "status": "Online",
                "latency": 1.2
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = str(Path(tmpdir) / "test.csv")
            json_path = str(Path(tmpdir) / "test.json")
            excel_path = str(Path(tmpdir) / "test.xlsx")
            pdf_path = str(Path(tmpdir) / "test.pdf")

            self.assertTrue(Exporter.export_csv(csv_path, dummy_data))
            self.assertTrue(os.path.exists(csv_path))

            self.assertTrue(Exporter.export_json(json_path, dummy_data))
            self.assertTrue(os.path.exists(json_path))

            self.assertTrue(Exporter.export_excel(excel_path, dummy_data))
            self.assertTrue(os.path.exists(excel_path))

            self.assertTrue(Exporter.export_pdf(pdf_path, dummy_data))
            self.assertTrue(os.path.exists(pdf_path))

    def test_protocol_parser_and_pcap_analyzer(self):
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from core.protocol_parser import ProtocolParser
        from core.pcap_analyzer import PcapAnalyzer

        # 1. Test Synthetic Packet Creation
        pkt_http_req = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") /
            IP(src="192.168.1.50", dst="93.184.216.34") /
            TCP(sport=54321, dport=80, flags="PA") /
            b"GET /api/v1/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope/1.0\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
        )

        pkt_dns_q = (
            Ether() /
            IP(src="192.168.1.50", dst="8.8.8.8") /
            UDP(sport=53001, dport=53) /
            DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        )

        pkt_arp_alert = (
            Ether(src="00:99:88:77:66:55", dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc="00:99:88:77:66:55", psrc="192.168.1.1", hwdst="00:11:22:33:44:55", pdst="192.168.1.50")
        )

        pkt_arp_orig = (
            Ether(src="00:11:22:33:44:00", dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc="00:11:22:33:44:00", psrc="192.168.1.1", hwdst="00:11:22:33:44:55", pdst="192.168.1.50")
        )

        packets = [pkt_http_req, pkt_dns_q, pkt_arp_alert, pkt_arp_orig]

        # 2. Test ProtocolParser
        parsed_http = ProtocolParser.parse_packet(pkt_http_req, index=1)
        self.assertEqual(parsed_http["protocol"], "HTTP")
        self.assertEqual(parsed_http["src_ip"], "192.168.1.50")
        self.assertEqual(parsed_http["dst_ip"], "93.184.216.34")
        self.assertTrue(parsed_http["http"]["is_request"])
        self.assertEqual(parsed_http["http"]["method"], "GET")
        self.assertEqual(parsed_http["http"]["host"], "example.com")
        self.assertIn("Basic", parsed_http["http"]["authorization"])

        parsed_dns = ProtocolParser.parse_packet(pkt_dns_q, index=2)
        self.assertEqual(parsed_dns["protocol"], "DNS")
        self.assertEqual(parsed_dns["dns"]["qname"], "example.com")
        self.assertEqual(parsed_dns["dns"]["qtype"], "A")

        # 3. Test PcapAnalyzer with Temp PCAP file
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = str(Path(tmpdir) / "test_traffic.pcap")
            scapy.wrpcap(pcap_path, packets)

            analyzer = PcapAnalyzer()
            self.assertTrue(analyzer.load_pcap(pcap_path))

            stats = analyzer.get_summary_stats()
            self.assertEqual(stats["total_packets"], 4)
            self.assertIn("HTTP", stats["protocol_counts"])
            self.assertIn("DNS", stats["protocol_counts"])

            http_logs = analyzer.get_http_logs()
            self.assertEqual(len(http_logs), 1)
            self.assertEqual(http_logs[0]["host"], "example.com")

            dns_logs = analyzer.get_dns_logs()
            self.assertEqual(len(dns_logs), 1)
            self.assertEqual(dns_logs[0]["qname"], "example.com")

            alerts = analyzer.get_security_alerts()
            self.assertTrue(len(alerts) >= 2)  # Should detect cleartext auth + ARP spoofing
            categories = [a["category"] for a in alerts]
            self.assertIn("Cleartext Authentication", categories)
            self.assertIn("ARP Spoofing / Poisoning", categories)

if __name__ == "__main__":
    unittest.main()
