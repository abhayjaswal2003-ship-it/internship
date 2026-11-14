"""
NetScope Pro - Live Packet Capture Engine
Threaded worker for capturing live network packets with BPF filters and PCAP export capability.
"""

from typing import List, Optional
from PyQt6.QtCore import QThread, pyqtSignal
import scapy.all as scapy
from core.protocol_parser import ProtocolParser

class PacketCaptureWorker(QThread):
    """
    Background QThread worker that captures live packets using Scapy's sniff()
    and emits real-time packet dictionaries for the UI.
    """

    packet_captured = pyqtSignal(dict, object)  # (parsed_packet_dict, scapy_raw_packet)
    capture_stopped = pyqtSignal(int)          # total packets captured
    capture_error = pyqtSignal(str)

    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "", max_packets: int = 0):
        super().__init__()
        self.interface = interface if interface else None
        self.bpf_filter = bpf_filter.strip()
        self.max_packets = max_packets
        self._is_running = False
        self.captured_packets: List[scapy.Packet] = []

    def run(self):
        self._is_running = True
        self.captured_packets = []
        packet_counter = 0

        def _packet_callback(pkt: scapy.Packet):
            nonlocal packet_counter
            if not self._is_running:
                return True  # Stop sniffing

            packet_counter += 1
            self.captured_packets.append(pkt)
            
            # Parse packet
            parsed = ProtocolParser.parse_packet(pkt, index=packet_counter)
            self.packet_captured.emit(parsed, pkt)

            if 0 < self.max_packets <= packet_counter:
                return True  # Stop condition reached

        try:
            sniff_kwargs = {
                "prn": _packet_callback,
                "store": False,
                "stop_filter": lambda _: not self._is_running
            }

            if self.interface:
                sniff_kwargs["iface"] = self.interface

            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter

            scapy.sniff(**sniff_kwargs)
            self.capture_stopped.emit(len(self.captured_packets))
        except Exception as e:
            self.capture_error.emit(str(e))
        finally:
            self._is_running = False

    def stop(self):
        """Signals the sniffer thread to terminate."""
        self._is_running = False

    def save_pcap(self, filepath: str) -> bool:
        """Saves captured raw packets to a .pcap file."""
        if not self.captured_packets:
            return False
        try:
            scapy.wrpcap(filepath, self.captured_packets)
            return True
        except Exception as e:
            print(f"Error saving PCAP: {e}")
            return False
