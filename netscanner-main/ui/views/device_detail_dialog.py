from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QTextEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QWidget
)
from PyQt6.QtCore import pyqtSignal
from database.db_manager import db_manager

class DeviceDetailDialog(QDialog):
    notes_saved = pyqtSignal(str, str)         # mac, notes
    ping_triggered = pyqtSignal(str)           # ip
    port_scan_triggered = pyqtSignal(str)      # ip

    def __init__(self, device: dict, parent=None):
        super().__init__(parent)
        self.device = device
        self.setWindowTitle(f"Device Profile - {device.get('hostname', 'Host')} ({device.get('ip')})")
        self.resize(650, 520)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header Info Frame
        hdr_frame = QFrame()
        hdr_frame.setProperty("class", "StatCard")
        hdr_layout = QHBoxLayout(hdr_frame)

        icon_lbl = QLabel("💻" if self.device.get("device_type") == "Computer" else ("📱" if self.device.get("device_type") == "Mobile" else "📡"))
        icon_lbl.setStyleSheet("font-size: 32px;")

        hdr_info = QVBoxLayout()
        lbl_title = QLabel(f"<b>{self.device.get('hostname', 'Unknown Host')}</b>")
        lbl_title.setStyleSheet("font-size: 18px;")
        lbl_sub = QLabel(f"IP: {self.device.get('ip')}  |  MAC: {self.device.get('mac')}  |  Vendor: {self.device.get('vendor')}")
        lbl_sub.setStyleSheet("color: #94A3B8;")

        hdr_info.addWidget(lbl_title)
        hdr_info.addWidget(lbl_sub)

        hdr_layout.addWidget(icon_lbl)
        hdr_layout.addLayout(hdr_info, stretch=1)

        # Action Buttons
        btn_ping = QPushButton("⚡ Ping")
        btn_ping.setProperty("class", "SecondaryButton")
        btn_ping.clicked.connect(lambda: (self.accept(), self.ping_triggered.emit(self.device.get("ip"))))

        btn_ports = QPushButton("🔍 Scan Ports")
        btn_ports.setProperty("class", "PrimaryButton")
        btn_ports.clicked.connect(lambda: (self.accept(), self.port_scan_triggered.emit(self.device.get("ip"))))

        hdr_layout.addWidget(btn_ping)
        hdr_layout.addWidget(btn_ports)

        layout.addWidget(hdr_frame)

        # Tabs: Overview, History, Notes
        tabs = QTabWidget()

        # Tab 1: System Specs Overview
        tab_specs = QWidget()
        specs_layout = QVBoxLayout(tab_specs)
        
        tbl_specs = QTableWidget(7, 2)
        tbl_specs.setHorizontalHeaderLabels(["Property", "Value"])
        tbl_specs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tbl_specs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tbl_specs.verticalHeader().setVisible(False)

        specs_data = [
            ("IP Address", self.device.get("ip", "")),
            ("MAC Address", self.device.get("mac", "")),
            ("Manufacturer (Vendor)", self.device.get("vendor", "")),
            ("Device Category", self.device.get("device_type", "")),
            ("Operating System Guess", self.device.get("os_guess", "Unknown")),
            ("Observed Latency", f"{self.device.get('latency', 0.0):.2f} ms"),
            ("First Seen / Connection Count", f"{self.device.get('first_seen', 'N/A')} ({self.device.get('connection_count', 1)} times)"),
        ]

        for i, (k, v) in enumerate(specs_data):
            tbl_specs.setItem(i, 0, QTableWidgetItem(k))
            tbl_specs.setItem(i, 1, QTableWidgetItem(str(v)))

        specs_layout.addWidget(tbl_specs)
        tabs.addTab(tab_specs, "📋 Details")

        # Tab 2: Notes Editor
        tab_notes = QWidget()
        notes_layout = QVBoxLayout(tab_notes)

        self.txt_notes = QTextEdit()
        self.txt_notes.setPlaceholderText("Enter administrator notes or comments regarding this device...")
        self.txt_notes.setPlainText(self.device.get("notes", ""))

        btn_save_notes = QPushButton("💾 Save Notes")
        btn_save_notes.setProperty("class", "PrimaryButton")
        btn_save_notes.clicked.connect(self._save_notes)

        notes_layout.addWidget(self.txt_notes)
        notes_layout.addWidget(btn_save_notes)
        tabs.addTab(tab_notes, "📝 Notes")

        # Tab 3: History Logs
        tab_hist = QWidget()
        hist_layout = QVBoxLayout(tab_hist)

        tbl_hist = QTableWidget(0, 3)
        tbl_hist.setHorizontalHeaderLabels(["Timestamp", "Event", "Details"])
        tbl_hist.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tbl_hist.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tbl_hist.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tbl_hist.verticalHeader().setVisible(False)

        history_rows = db_manager.get_device_history(self.device.get("mac", ""))
        for h in history_rows:
            r = tbl_hist.rowCount()
            tbl_hist.insertRow(r)
            tbl_hist.setItem(r, 0, QTableWidgetItem(h.get("timestamp", "")))
            tbl_hist.setItem(r, 1, QTableWidgetItem(h.get("event_type", "")))
            tbl_hist.setItem(r, 2, QTableWidgetItem(h.get("details", "")))

        hist_layout.addWidget(tbl_hist)
        tabs.addTab(tab_hist, "📜 History Logs")

        layout.addWidget(tabs)

    def _save_notes(self):
        notes = self.txt_notes.toPlainText()
        mac = self.device.get("mac", "")
        db_manager.update_device_notes(mac, notes)
        self.notes_saved.emit(mac, notes)
        self.accept()
