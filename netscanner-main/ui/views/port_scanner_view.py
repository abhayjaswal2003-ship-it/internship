from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar, QFrame
)
from PyQt6.QtCore import pyqtSignal, Qt
from core.port_scanner import PortScanWorker, COMMON_PORTS

class PortScannerView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header Title
        lbl_title = QLabel("🔍 Targeted TCP Port & Service Scanner")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(lbl_title)

        # Safety & Ethics Notice Frame
        notice_frame = QFrame()
        notice_frame.setStyleSheet("""
            background-color: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.4);
            border-radius: 6px;
            padding: 8px 12px;
        """)
        notice_layout = QHBoxLayout(notice_frame)
        notice_lbl = QLabel("⚠️ <b>Security & Ethics Reminder:</b> Port scanning should only be performed on authorized local networks and devices you own. Scans are rate-limited to avoid network degradation.")
        notice_lbl.setStyleSheet("color: #F59E0B; font-size: 12px;")
        notice_layout.addWidget(notice_lbl)
        layout.addWidget(notice_frame)

        # Control Panel Form
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "StatCard")
        ctrl_layout = QHBoxLayout(ctrl_card)
        ctrl_layout.setSpacing(12)

        self.lbl_target = QLabel("Target Host:")
        self.cmb_target = QComboBox()
        self.cmb_target.setEditable(True)
        self.cmb_target.setPlaceholderText("Select IP or enter target...")

        lbl_preset = QLabel("Scan Preset:")
        self.cmb_preset = QComboBox()
        self.cmb_preset.addItems([
            "Common Admin Ports (HTTP, HTTPS, SSH, FTP, RDP, SMB)",
            "Database Services (MySQL, PostgreSQL, MSSQL, MongoDB, Oracle)",
            "Web & Email Ports (80, 443, 8080, 8443, 25, 110, 143, 53)",
            "Top 25 Standard Ports",
            "Custom Range"
        ])
        self.cmb_preset.currentTextChanged.connect(self._on_preset_changed)

        self.txt_custom = QLineEdit("80, 443, 22, 445, 3389")
        self.txt_custom.setPlaceholderText("e.g. 80,443,8080 or 1-100")
        self.txt_custom.setEnabled(False)

        self.btn_start = QPushButton("🚀 Start Scan")
        self.btn_start.setProperty("class", "PrimaryButton")
        self.btn_start.clicked.connect(self.start_scan)

        self.btn_cancel = QPushButton("⏹️ Cancel")
        self.btn_cancel.setProperty("class", "SecondaryButton")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_scan)

        ctrl_layout.addWidget(self.lbl_target)
        ctrl_layout.addWidget(self.cmb_target, stretch=2)
        ctrl_layout.addWidget(lbl_preset)
        ctrl_layout.addWidget(self.cmb_preset, stretch=2)
        ctrl_layout.addWidget(self.txt_custom, stretch=2)
        ctrl_layout.addWidget(self.btn_start)
        ctrl_layout.addWidget(self.btn_cancel)

        layout.addWidget(ctrl_card)

        # Progress Bar & Status
        self.lbl_status = QLabel("Ready to scan.")
        self.lbl_status.setStyleSheet("color: #94A3B8; font-style: italic;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        prog_layout = QHBoxLayout()
        prog_layout.addWidget(self.lbl_status, stretch=1)
        prog_layout.addWidget(self.progress_bar, stretch=2)
        layout.addLayout(prog_layout)

        # Results Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Port", "Protocol", "Service Name", "Description", "State", "Latency"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self.table)

    def populate_target_hosts(self, devices: list):
        self.cmb_target.clear()
        for d in devices:
            self.cmb_target.addItem(f"{d.get('ip')} ({d.get('hostname', 'Host')})", d.get("ip"))

    def set_target_ip(self, ip: str):
        index = self.cmb_target.findData(ip)
        if index >= 0:
            self.cmb_target.setCurrentIndex(index)
        else:
            self.cmb_target.setCurrentText(ip)

    def _on_preset_changed(self, text: str):
        self.txt_custom.setEnabled("Custom" in text)

    def _parse_ports(self) -> list:
        return []

    def start_scan(self):
        target = self.cmb_target.currentData() or self.cmb_target.currentText().split()[0].strip()
        if not target:
            self.lbl_status.setText("Please select or enter a valid target IP address.")
            return

        preset = self.cmb_preset.currentText()
        ports = []

        if "Common Admin" in preset:
            ports = [21, 22, 23, 80, 135, 139, 443, 445, 3389]
        elif "Database Services" in preset:
            ports = [1433, 1521, 3306, 5432, 27017]
        elif "Web & Email" in preset:
            ports = [25, 53, 80, 110, 143, 443, 8080, 8443]
        elif "Top 25" in preset:
            ports = list(COMMON_PORTS.keys())
        else: # Custom
            raw = self.txt_custom.text()
            try:
                for part in raw.split(","):
                    part = part.strip()
                    if "-" in part:
                        start, end = map(int, part.split("-"))
                        ports.extend(range(start, min(end + 1, 65535)))
                    elif part.isdigit():
                        ports.append(int(part))
            except Exception:
                ports = [80, 443, 22]

        self.table.setRowCount(0)
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)

        self.worker = PortScanWorker(target, ports)
        self.worker.port_progress.connect(self._on_progress)
        self.worker.port_found.connect(self._on_port_found)
        self.worker.scan_finished.connect(self._on_finished)
        self.worker.start()

    def cancel_scan(self):
        if self.worker:
            self.worker.cancel()
            self.lbl_status.setText("Scan cancellation requested...")

    def _on_progress(self, percent: int, msg: str):
        self.progress_bar.setValue(percent)
        self.lbl_status.setText(msg)

    def _on_port_found(self, port_info: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(port_info["port"])))
        self.table.setItem(row, 1, QTableWidgetItem(port_info["protocol"]))
        self.table.setItem(row, 2, QTableWidgetItem(port_info["service"]))
        self.table.setItem(row, 3, QTableWidgetItem(port_info["description"]))
        
        state_item = QTableWidgetItem(port_info["state"])
        state_item.setForeground(Qt.GlobalColor.green)
        self.table.setItem(row, 4, state_item)
        self.table.setItem(row, 5, QTableWidgetItem(f"{port_info['response_time']} ms"))

    def _on_finished(self, open_ports: list, duration: float):
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setValue(100)
        self.lbl_status.setText(f"Scan finished in {duration}s. Discovered {len(open_ports)} open TCP ports.")
