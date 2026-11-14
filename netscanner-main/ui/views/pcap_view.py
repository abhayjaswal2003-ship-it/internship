"""
NetScope Pro - PCAP & Protocol Forensic Analyzer View
3-Pane Wireshark-style interactive packet inspector with deep protocol breakdown,
live packet sniffing, HTTP/DNS forensics, flow conversations, and security anomaly detection.
"""

import os
from typing import Dict, Any, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QTabWidget, QFileDialog,
    QHeaderView, QSplitter, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont

from core.pcap_analyzer import PcapAnalyzer
from core.packet_capture import PacketCaptureWorker
from core.network_info import get_active_network_info
from utils.exporter import Exporter
from utils.logger import log_event


class PcapView(QWidget):
    """
    Complete PCAP & Deep Protocol Analyzer View for NetScope Pro.
    """

    PROTOCOL_COLORS = {
        "HTTP": "#0284C7",        # Cyan/Blue
        "DNS": "#D97706",         # Amber/Yellow
        "TCP": "#2563EB",         # Royal Blue
        "UDP": "#7C3AED",         # Purple
        "ICMP": "#EA580C",        # Orange
        "ARP": "#DC2626",         # Red
        "TLS": "#16A34A",         # Emerald Green
        "TLS/HTTPS": "#16A34A",   # Emerald Green
        "Other": "#64748B"        # Slate Gray
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.analyzer = PcapAnalyzer()
        self.sniff_worker: Optional[PacketCaptureWorker] = None
        self.displayed_packets: List[Dict[str, Any]] = []

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # -------------------------------------------------------------
        # 1. Top Control Bar (PCAP Import / Export / Live Sniff controls)
        # -------------------------------------------------------------
        top_bar = QFrame()
        top_bar.setProperty("class", "StatCard")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(12, 10, 12, 10)
        top_layout.setSpacing(10)

        self.btn_import_pcap = QPushButton("📁 Import PCAP File")
        self.btn_import_pcap.setProperty("class", "PrimaryButton")
        self.btn_import_pcap.clicked.connect(self.import_pcap_dialog)

        self.btn_export_pcap = QPushButton("💾 Export PCAP")
        self.btn_export_pcap.setProperty("class", "SecondaryButton")
        self.btn_export_pcap.clicked.connect(self.export_pcap_dialog)

        self.btn_export_report = QPushButton("📄 Export Forensic Report")
        self.btn_export_report.setProperty("class", "SecondaryButton")
        self.btn_export_report.clicked.connect(self.export_report_dialog)

        # Live Sniff Controls
        top_layout.addWidget(self.btn_import_pcap)
        top_layout.addWidget(self.btn_export_pcap)
        top_layout.addWidget(self.btn_export_report)

        lbl_sep = QLabel("|")
        lbl_sep.setStyleSheet("color: #64748B; font-weight: bold; font-size: 16px;")
        top_layout.addWidget(lbl_sep)

        lbl_iface = QLabel("Adapter:")
        lbl_iface.setStyleSheet("font-weight: bold; color: #94A3B8;")
        top_layout.addWidget(lbl_iface)

        self.combo_iface = QComboBox()
        net_info = get_active_network_info()
        curr_iface = net_info.get("interface", "")
        if curr_iface:
            self.combo_iface.addItem(curr_iface)
        self.combo_iface.addItem("All Interfaces")

        top_layout.addWidget(self.combo_iface)

        lbl_bpf = QLabel("BPF Filter:")
        lbl_bpf.setStyleSheet("font-weight: bold; color: #94A3B8;")
        top_layout.addWidget(lbl_bpf)

        self.txt_bpf = QLineEdit()
        self.txt_bpf.setPlaceholderText("e.g. tcp port 80, dns, icmp")
        self.txt_bpf.setFixedWidth(180)
        top_layout.addWidget(self.txt_bpf)

        self.btn_toggle_sniff = QPushButton("▶️ Start Live Sniff")
        self.btn_toggle_sniff.setProperty("class", "PrimaryButton")
        self.btn_toggle_sniff.clicked.connect(self.toggle_live_sniff)
        top_layout.addWidget(self.btn_toggle_sniff)

        top_layout.addStretch()

        main_layout.addWidget(top_bar)

        # -------------------------------------------------------------
        # 2. Display Filter Bar (Quick Search / Display Filter)
        # -------------------------------------------------------------
        filter_bar = QFrame()
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(8)

        lbl_display = QLabel("🔍 Display Filter:")
        lbl_display.setStyleSheet("font-weight: bold; font-size: 13px;")
        filter_layout.addWidget(lbl_display)

        self.txt_display_filter = QLineEdit()
        self.txt_display_filter.setPlaceholderText("Type protocol (http, dns, tcp, udp) or IP (192.168.1.1) to filter...")
        self.txt_display_filter.textChanged.connect(self.apply_display_filter)
        filter_layout.addWidget(self.txt_display_filter, stretch=1)

        self.lbl_pcap_info = QLabel("No PCAP loaded.")
        self.lbl_pcap_info.setStyleSheet("color: #94A3B8; font-style: italic;")
        filter_layout.addWidget(self.lbl_pcap_info)

        main_layout.addLayout(filter_layout)

        # -------------------------------------------------------------
        # 3. Main Multi-Tab Interface
        # -------------------------------------------------------------
        self.tabs = QTabWidget()

        # Tab 1: 3-Pane Wireshark Packet Inspector
        self.tab_inspector = QWidget()
        self.init_tab_inspector()
        self.tabs.addTab(self.tab_inspector, "🔬 3-Pane Packet Inspector")

        # Tab 2: Forensic Analytics & Flow Dashboard
        self.tab_analytics = QWidget()
        self.init_tab_analytics()
        self.tabs.addTab(self.tab_analytics, "📊 Flow & Forensic Analytics")

        # Tab 3: HTTP Protocol & Web Inspector
        self.tab_http = QWidget()
        self.init_tab_http()
        self.tabs.addTab(self.tab_http, "🌐 HTTP Headers & Web Forensics")

        # Tab 4: DNS Queries & Domain Inspector
        self.tab_dns = QWidget()
        self.init_tab_dns()
        self.tabs.addTab(self.tab_dns, "🔍 DNS Queries & Domains")

        # Tab 5: Forensic Alerts & Anomaly Inspector
        self.tab_alerts = QWidget()
        self.init_tab_alerts()
        self.tabs.addTab(self.tab_alerts, "⚠️ Security Alerts")

        main_layout.addWidget(self.tabs, stretch=1)

    # -----------------------------------------------------------------
    # Tab 1: 3-Pane Packet Inspector Setup
    # -----------------------------------------------------------------
    def init_tab_inspector(self):
        layout = QVBoxLayout(self.tab_inspector)
        layout.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Pane 1: Upper Packet List Table
        self.tbl_packets = QTableWidget()
        self.tbl_packets.setColumnCount(7)
        self.tbl_packets.setHorizontalHeaderLabels(["No.", "Time (s)", "Source", "Destination", "Protocol", "Length", "Info"])
        self.tbl_packets.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.tbl_packets.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_packets.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_packets.setAlternatingRowColors(True)
        self.tbl_packets.itemSelectionChanged.connect(self.on_packet_selected)
        splitter.addWidget(self.tbl_packets)

        # Bottom Splitter (Left: Protocol Tree, Right: Hex/ASCII Dump)
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Pane 2: Middle Protocol Tree
        self.tree_protocol = QTreeWidget()
        self.tree_protocol.setHeaderLabel("Packet Layer Details & Header Dissection")
        bottom_splitter.addWidget(self.tree_protocol)

        # Pane 3: Hex & ASCII Payload Dump Viewer
        self.txt_hexdump = QTextEdit()
        self.txt_hexdump.setReadOnly(True)
        self.txt_hexdump.setFont(QFont("Courier New", 10))
        self.txt_hexdump.setPlaceholderText("Raw Hex and ASCII payload dump will be displayed here...")
        bottom_splitter.addWidget(self.txt_hexdump)

        bottom_splitter.setSizes([450, 450])
        splitter.addWidget(bottom_splitter)
        splitter.setSizes([350, 300])

        layout.addWidget(splitter)

    # -----------------------------------------------------------------
    # Tab 2: Forensic Analytics Setup
    # -----------------------------------------------------------------
    def init_tab_analytics(self):
        layout = QVBoxLayout(self.tab_analytics)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Summary Metric Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.lbl_card_pkts = self._create_stat_card(cards_layout, "Total Packets", "0")
        self.lbl_card_bytes = self._create_stat_card(cards_layout, "Total Volume", "0 B")
        self.lbl_card_duration = self._create_stat_card(cards_layout, "Capture Duration", "0.0s")
        self.lbl_card_rate = self._create_stat_card(cards_layout, "Packet Rate", "0 pkts/s")

        layout.addLayout(cards_layout)

        # Splitter for Flow Tables (Left: Top Talkers, Right: IP Conversations)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Top Talkers Frame
        f_talkers = QFrame()
        f_talkers.setProperty("class", "StatCard")
        l_talkers = QVBoxLayout(f_talkers)
        lbl_t_title = QLabel("🔥 Top IP Talkers (Sources / Destinations)")
        lbl_t_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        l_talkers.addWidget(lbl_t_title)

        self.tbl_talkers = QTableWidget()
        self.tbl_talkers.setColumnCount(4)
        self.tbl_talkers.setHorizontalHeaderLabels(["IP Address", "Type", "Packets", "Total Bytes"])
        self.tbl_talkers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        l_talkers.addWidget(self.tbl_talkers)
        splitter.addWidget(f_talkers)

        # Conversations Frame
        f_convs = QFrame()
        f_convs.setProperty("class", "StatCard")
        l_convs = QVBoxLayout(f_convs)
        lbl_c_title = QLabel("🔄 IP Conversation Matrix (Flows)")
        lbl_c_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        l_convs.addWidget(lbl_c_title)

        self.tbl_convs = QTableWidget()
        self.tbl_convs.setColumnCount(5)
        self.tbl_convs.setHorizontalHeaderLabels(["Host A", "Host B", "Protocol", "Packets", "Bytes"])
        self.tbl_convs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tbl_convs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        l_convs.addWidget(self.tbl_convs)
        splitter.addWidget(f_convs)

        layout.addWidget(splitter, stretch=1)

    def _create_stat_card(self, parent_layout: QHBoxLayout, title: str, init_val: str) -> QLabel:
        card = QFrame()
        card.setProperty("class", "StatCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        lbl_val = QLabel(init_val)
        lbl_val.setProperty("class", "StatValue")
        lbl_t = QLabel(title)
        lbl_t.setProperty("class", "StatTitle")
        cl.addWidget(lbl_val)
        cl.addWidget(lbl_t)
        parent_layout.addWidget(card)
        return lbl_val

    # -----------------------------------------------------------------
    # Tab 3: HTTP Headers & Web Forensics Setup
    # -----------------------------------------------------------------
    def init_tab_http(self):
        layout = QVBoxLayout(self.tab_http)
        layout.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Upper Table: HTTP Requests & Responses
        self.tbl_http = QTableWidget()
        self.tbl_http.setColumnCount(8)
        self.tbl_http.setHorizontalHeaderLabels(["Pkt #", "Source", "Destination", "Type", "Method / Status", "Host / URL", "Content-Type", "Auth Header"])
        self.tbl_http.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tbl_http.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_http.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_http.itemSelectionChanged.connect(self.on_http_selected)
        splitter.addWidget(self.tbl_http)

        # Lower Text Viewer: Full HTTP Headers & Body
        self.txt_http_detail = QTextEdit()
        self.txt_http_detail.setReadOnly(True)
        self.txt_http_detail.setFont(QFont("Courier New", 10))
        self.txt_http_detail.setPlaceholderText("Select an HTTP packet row above to view complete HTTP headers, cookies, and payload body...")
        splitter.addWidget(self.txt_http_detail)

        splitter.setSizes([300, 250])
        layout.addWidget(splitter)

    # -----------------------------------------------------------------
    # Tab 4: DNS Queries Setup
    # -----------------------------------------------------------------
    def init_tab_dns(self):
        layout = QVBoxLayout(self.tab_dns)
        layout.setContentsMargins(8, 8, 8, 8)

        self.tbl_dns = QTableWidget()
        self.tbl_dns.setColumnCount(7)
        self.tbl_dns.setHorizontalHeaderLabels(["Pkt #", "Time (s)", "Client IP", "DNS Server", "Type", "Domain Query", "Resolved Answers / RRs"])
        self.tbl_dns.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tbl_dns.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.tbl_dns.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_dns.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.tbl_dns)

    # -----------------------------------------------------------------
    # Tab 5: Security Alerts Setup
    # -----------------------------------------------------------------
    def init_tab_alerts(self):
        layout = QVBoxLayout(self.tab_alerts)
        layout.setContentsMargins(8, 8, 8, 8)

        self.tbl_alerts = QTableWidget()
        self.tbl_alerts.setColumnCount(5)
        self.tbl_alerts.setHorizontalHeaderLabels(["Severity", "Category", "Alert Title", "Details / Evidence", "Source IP"])
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tbl_alerts.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_alerts.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.tbl_alerts)

    # =================================================================
    # Controller & Data Logic
    # =================================================================

    def import_pcap_dialog(self):
        """Opens file dialog for user to select a .pcap file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import PCAP Capture File", "", "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if file_path:
            self.load_pcap_file(file_path)

    def load_pcap_file(self, filepath: str):
        """Loads and processes PCAP file using PcapAnalyzer."""
        try:
            self.lbl_pcap_info.setText(f"Loading {os.path.basename(filepath)}...")
            self.analyzer.load_pcap(filepath)
            self.lbl_pcap_info.setText(f"Loaded: {os.path.basename(filepath)} ({len(self.analyzer.parsed_packets)} pkts)")

            self.populate_all_views()
            log_event("INFO", "PCAPAnalyzer", f"Successfully loaded PCAP file: {filepath}")
        except Exception as e:
            QMessageBox.critical(self, "PCAP Loading Error", f"Could not load PCAP file:\n{e}")
            self.lbl_pcap_info.setText("Error loading PCAP.")

    def export_pcap_dialog(self):
        """Exports currently loaded or captured raw packets to a .pcap file."""
        if not self.analyzer.packets:
            QMessageBox.warning(self, "Export Error", "No packets available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Capture to PCAP", "capture_export.pcap", "PCAP Files (*.pcap)"
        )
        if file_path:
            try:
                import scapy.all as scapy
                scapy.wrpcap(file_path, self.analyzer.packets)
                QMessageBox.information(self, "Export Success", f"Saved {len(self.analyzer.packets)} packets to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save PCAP file:\n{e}")

    def export_report_dialog(self):
        """Exports forensic summary tables to CSV / JSON / PDF."""
        if not self.analyzer.parsed_packets:
            QMessageBox.warning(self, "Export Warning", "No packet data available to export.")
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export PCAP Forensic Summary", "pcap_forensics.csv",
            "CSV File (*.csv);;JSON File (*.json);;Excel File (*.xlsx);;PDF Report (*.pdf)"
        )
        if not file_path:
            return

        stats = self.analyzer.get_summary_stats()
        http_logs = self.analyzer.get_http_logs()
        alerts = self.analyzer.get_security_alerts()

        summary_rows = [
            {"Metric": "Total Packets", "Value": str(stats["total_packets"])},
            {"Metric": "Total Bytes", "Value": str(stats["total_bytes"])},
            {"Metric": "Duration (s)", "Value": str(stats["duration_sec"])},
            {"Metric": "Packet Rate", "Value": f"{stats['packet_rate']} pkts/s"},
            {"Metric": "HTTP Requests Extracted", "Value": str(len(http_logs))},
            {"Metric": "Security Alerts Triggered", "Value": str(len(alerts))},
        ]

        if file_path.endswith(".csv"):
            Exporter.export_csv(file_path, summary_rows)
        elif file_path.endswith(".json"):
            Exporter.export_json(file_path, {"summary": stats, "http_logs": http_logs, "alerts": alerts})
        elif file_path.endswith(".xlsx"):
            Exporter.export_excel(file_path, summary_rows)
        elif file_path.endswith(".pdf"):
            Exporter.export_pdf(file_path, summary_rows)

        QMessageBox.information(self, "Export Complete", f"Forensic report exported successfully to:\n{file_path}")

    def toggle_live_sniff(self):
        """Starts or stops live packet sniffing worker thread."""
        if self.sniff_worker and self.sniff_worker.isRunning():
            # Stop sniffing
            self.sniff_worker.stop()
            self.btn_toggle_sniff.setText("▶️ Start Live Sniff")
            self.lbl_pcap_info.setText("Live sniffing stopped.")
            return

        # Start sniffing
        iface = self.combo_iface.currentText()
        if iface == "All Interfaces":
            iface = None

        bpf = self.txt_bpf.text()
        self.sniff_worker = PacketCaptureWorker(interface=iface, bpf_filter=bpf)
        self.sniff_worker.packet_captured.connect(self._on_live_packet_captured)
        self.sniff_worker.capture_stopped.connect(self._on_live_capture_stopped)
        self.sniff_worker.capture_error.connect(self._on_live_capture_error)

        self.analyzer.packets = []
        self.analyzer.parsed_packets = []
        self.displayed_packets = []
        self.tbl_packets.setRowCount(0)

        self.sniff_worker.start()
        self.btn_toggle_sniff.setText("⏹️ Stop Sniffing")
        self.lbl_pcap_info.setText("Live packet capture running...")
        log_event("INFO", "PCAPSniffer", f"Started live packet sniffing on {iface or 'default interface'}")

    def _on_live_packet_captured(self, parsed_pkt: dict, raw_pkt):
        self.analyzer.packets.append(raw_pkt)
        self.analyzer.parsed_packets.append(parsed_pkt)
        
        # Check filter
        if self._matches_filter(parsed_pkt, self.txt_display_filter.text()):
            self._append_packet_row(parsed_pkt)

    def _on_live_capture_stopped(self, total: int):
        self.btn_toggle_sniff.setText("▶️ Start Live Sniff")
        self.lbl_pcap_info.setText(f"Live capture stopped. Captured {total} packets.")
        self.analyzer.load_from_raw_packets(self.analyzer.packets)
        self.populate_all_views()

    def _on_live_capture_error(self, err_msg: str):
        self.btn_toggle_sniff.setText("▶️ Start Live Sniff")
        self.lbl_pcap_info.setText(f"Sniff error: {err_msg}")
        QMessageBox.warning(self, "Sniff Error", f"Live packet capture error:\n{err_msg}\n\nNote: Raw packet sniffing requires Administrator privileges.")

    def populate_all_views(self):
        """Refreshes all tabs with current analyzer data."""
        self.apply_display_filter()
        self.update_analytics_tab()
        self.update_http_tab()
        self.update_dns_tab()
        self.update_alerts_tab()

    def apply_display_filter(self):
        """Applies text search / protocol display filter to packet list table."""
        filter_text = self.txt_display_filter.text().strip().lower()
        self.tbl_packets.setRowCount(0)
        self.displayed_packets = []

        for p in self.analyzer.parsed_packets:
            if self._matches_filter(p, filter_text):
                self._append_packet_row(p)

    def _matches_filter(self, p: dict, filter_text: str) -> bool:
        if not filter_text:
            return True

        proto = p.get("protocol", "").lower()
        src = p.get("src_ip", "").lower()
        dst = p.get("dst_ip", "").lower()
        info = p.get("info", "").lower()

        if filter_text in proto or filter_text in src or filter_text in dst or filter_text in info:
            return True
        if filter_text == "http" and p.get("http"):
            return True
        if filter_text == "dns" and p.get("dns"):
            return True

        return False

    def _append_packet_row(self, p: dict):
        row = self.tbl_packets.rowCount()
        self.tbl_packets.insertRow(row)
        self.displayed_packets.append(p)

        items = [
            QTableWidgetItem(str(p["index"])),
            QTableWidgetItem(f"{p['time']:.4f}"),
            QTableWidgetItem(p["src_ip"] or p["src_mac"]),
            QTableWidgetItem(p["dst_ip"] or p["dst_mac"]),
            QTableWidgetItem(p["protocol"]),
            QTableWidgetItem(str(p["length"])),
            QTableWidgetItem(p["info"])
        ]

        # Protocol Color Coding
        proto = p.get("protocol", "Other")
        color_hex = self.PROTOCOL_COLORS.get(proto, "#64748B")
        bg_color = QColor(color_hex)
        bg_color.setAlpha(45)

        for item in items:
            item.setBackground(bg_color)
            self.tbl_packets.setItem(row, items.index(item), item)

    def on_packet_selected(self):
        selected = self.tbl_packets.currentRow()
        if selected < 0 or selected >= len(self.displayed_packets):
            return

        pkt_data = self.displayed_packets[selected]

        # 1. Update Protocol Tree View
        self.tree_protocol.clear()
        for layer in pkt_data.get("tree_structure", []):
            item = QTreeWidgetItem([layer["label"]])
            self._add_tree_children(item, layer.get("children", []))
            self.tree_protocol.addTopLevelItem(item)
            item.setExpanded(True)

        # 2. Update Hex & ASCII Dump View
        self.txt_hexdump.setPlainText(pkt_data.get("hex_dump", ""))

    def _add_tree_children(self, parent_item: QTreeWidgetItem, children: List[Dict]):
        for child in children:
            child_item = QTreeWidgetItem([child["label"]])
            parent_item.addChild(child_item)
            if "children" in child:
                self._add_tree_children(child_item, child["children"])

    # -----------------------------------------------------------------
    # Analytics Tab Updates
    # -----------------------------------------------------------------
    def update_analytics_tab(self):
        stats = self.analyzer.get_summary_stats()
        self.lbl_card_pkts.setText(str(stats["total_packets"]))

        # Format Volume
        vol_bytes = stats["total_bytes"]
        if vol_bytes > 1024 * 1024:
            self.lbl_card_bytes.setText(f"{vol_bytes / (1024*1024):.2f} MB")
        else:
            self.lbl_card_bytes.setText(f"{vol_bytes / 1024:.1f} KB")

        self.lbl_card_duration.setText(f"{stats['duration_sec']}s")
        self.lbl_card_rate.setText(f"{stats['packet_rate']} p/s")

        # Populate Top Talkers
        talkers = self.analyzer.get_top_talkers(top_n=10)
        self.tbl_talkers.setRowCount(0)

        for src_ip, count, nbytes in talkers["top_sources"]:
            r = self.tbl_talkers.rowCount()
            self.tbl_talkers.insertRow(r)
            self.tbl_talkers.setItem(r, 0, QTableWidgetItem(src_ip))
            self.tbl_talkers.setItem(r, 1, QTableWidgetItem("Source"))
            self.tbl_talkers.setItem(r, 2, QTableWidgetItem(str(count)))
            self.tbl_talkers.setItem(r, 3, QTableWidgetItem(f"{nbytes / 1024:.1f} KB"))

        for dst_ip, count, nbytes in talkers["top_destinations"]:
            r = self.tbl_talkers.rowCount()
            self.tbl_talkers.insertRow(r)
            self.tbl_talkers.setItem(r, 0, QTableWidgetItem(dst_ip))
            self.tbl_talkers.setItem(r, 1, QTableWidgetItem("Destination"))
            self.tbl_talkers.setItem(r, 2, QTableWidgetItem(str(count)))
            self.tbl_talkers.setItem(r, 3, QTableWidgetItem(f"{nbytes / 1024:.1f} KB"))

        # Populate Conversations Matrix
        convs = self.analyzer.get_conversations()
        self.tbl_convs.setRowCount(0)
        for c in convs[:20]:
            r = self.tbl_convs.rowCount()
            self.tbl_convs.insertRow(r)
            self.tbl_convs.setItem(r, 0, QTableWidgetItem(c["host_a"]))
            self.tbl_convs.setItem(r, 1, QTableWidgetItem(c["host_b"]))
            self.tbl_convs.setItem(r, 2, QTableWidgetItem(c["protocol"]))
            self.tbl_convs.setItem(r, 3, QTableWidgetItem(str(c["packets"])))
            self.tbl_convs.setItem(r, 4, QTableWidgetItem(f"{c['bytes'] / 1024:.1f} KB"))

    # -----------------------------------------------------------------
    # HTTP Tab Updates
    # -----------------------------------------------------------------
    def update_http_tab(self):
        logs = self.analyzer.get_http_logs()
        self.tbl_http.setRowCount(0)

        for h in logs:
            r = self.tbl_http.rowCount()
            self.tbl_http.insertRow(r)
            self.tbl_http.setItem(r, 0, QTableWidgetItem(str(h["packet_index"])))
            self.tbl_http.setItem(r, 1, QTableWidgetItem(h["src"]))
            self.tbl_http.setItem(r, 2, QTableWidgetItem(h["dst"]))
            self.tbl_http.setItem(r, 3, QTableWidgetItem("Request" if h["is_request"] else "Response"))
            self.tbl_http.setItem(r, 4, QTableWidgetItem(h["method"] if h["is_request"] else str(h["status_code"])))
            self.tbl_http.setItem(r, 5, QTableWidgetItem(h["url"] if h["is_request"] else h["host"]))
            self.tbl_http.setItem(r, 6, QTableWidgetItem(h["content_type"]))
            self.tbl_http.setItem(r, 7, QTableWidgetItem(h["auth"] if h["auth"] else "None"))

    def on_http_selected(self):
        selected = self.tbl_http.currentRow()
        logs = self.analyzer.get_http_logs()
        if selected < 0 or selected >= len(logs):
            return

        h = logs[selected]
        lines = []
        lines.append("="*60)
        if h["is_request"]:
            lines.append(f"HTTP REQUEST (Packet #{h['packet_index']})")
            lines.append(f"URL: {h['url']}")
            lines.append(f"Method: {h['method']} | Host: {h['host']}")
            lines.append(f"User-Agent: {h['user_agent']}")
            if h["auth"]:
                lines.append(f"Authorization Token: {h['auth']}")
            if h["cookie"]:
                lines.append(f"Cookies: {h['cookie']}")
        else:
            lines.append(f"HTTP RESPONSE (Packet #{h['packet_index']})")
            lines.append(f"Status Code: {h['status_code']} | Content-Type: {h['content_type']}")

        lines.append("-" * 60)
        lines.append("HEADERS:")
        for hk, hv in h.get("headers", {}).items():
            lines.append(f"  {hk}: {hv}")

        if h.get("body"):
            lines.append("-" * 60)
            lines.append("PAYLOAD BODY:")
            lines.append(h["body"])

        lines.append("=" * 60)
        self.txt_http_detail.setPlainText("\n".join(lines))

    # -----------------------------------------------------------------
    # DNS Tab Updates
    # -----------------------------------------------------------------
    def update_dns_tab(self):
        logs = self.analyzer.get_dns_logs()
        self.tbl_dns.setRowCount(0)

        for d in logs:
            r = self.tbl_dns.rowCount()
            self.tbl_dns.insertRow(r)
            self.tbl_dns.setItem(r, 0, QTableWidgetItem(str(d["packet_index"])))
            self.tbl_dns.setItem(r, 1, QTableWidgetItem(f"{d['time']:.2f}"))
            self.tbl_dns.setItem(r, 2, QTableWidgetItem(d["src"]))
            self.tbl_dns.setItem(r, 3, QTableWidgetItem(d["dst"]))
            self.tbl_dns.setItem(r, 4, QTableWidgetItem(d["qtype"]))
            self.tbl_dns.setItem(r, 5, QTableWidgetItem(d["qname"]))
            self.tbl_dns.setItem(r, 6, QTableWidgetItem(d["answers"]))

    # -----------------------------------------------------------------
    # Security Alerts Tab Updates
    # -----------------------------------------------------------------
    def update_alerts_tab(self):
        alerts = self.analyzer.get_security_alerts()
        self.tbl_alerts.setRowCount(0)

        for a in alerts:
            r = self.tbl_alerts.rowCount()
            self.tbl_alerts.insertRow(r)

            item_lvl = QTableWidgetItem(a["level"])
            if a["level"] == "CRITICAL":
                item_lvl.setForeground(QColor("#EF4444"))
            elif a["level"] == "HIGH":
                item_lvl.setForeground(QColor("#F59E0B"))

            self.tbl_alerts.setItem(r, 0, item_lvl)
            self.tbl_alerts.setItem(r, 1, QTableWidgetItem(a["category"]))
            self.tbl_alerts.setItem(r, 2, QTableWidgetItem(a["title"]))
            self.tbl_alerts.setItem(r, 3, QTableWidgetItem(a["details"]))
            self.tbl_alerts.setItem(r, 4, QTableWidgetItem(a["src_ip"]))
