from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QLabel
)
from PyQt6.QtCore import pyqtSignal, Qt
from ui.components.status_badge import StatusBadge

class DevicesView(QWidget):
    device_selected = pyqtSignal(dict)
    ping_requested = pyqtSignal(str)
    port_scan_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.raw_devices = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Search and Filter Toolbar
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(10)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Search by IP, Hostname, MAC, or Vendor...")
        self.txt_search.textChanged.connect(self.apply_filters)

        self.cmb_type = QComboBox()
        self.cmb_type.addItems(["All Device Types", "Router", "Computer", "Mobile", "Printer", "Smart TV", "IoT Device", "Unknown Device"])
        self.cmb_type.currentTextChanged.connect(self.apply_filters)

        self.cmb_status = QComboBox()
        self.cmb_status.addItems(["All Statuses", "Online", "Offline"])
        self.cmb_status.currentTextChanged.connect(self.apply_filters)

        self.btn_reset_filters = QPushButton("🔄 Reset Filters")
        self.btn_reset_filters.setProperty("class", "SecondaryButton")
        self.btn_reset_filters.clicked.connect(self.reset_filters)

        self.lbl_count = QLabel("Devices: 0")
        self.lbl_count.setStyleSheet("font-weight: bold; font-size: 13px;")

        filter_layout.addWidget(self.txt_search, stretch=3)
        filter_layout.addWidget(self.cmb_type, stretch=1)
        filter_layout.addWidget(self.cmb_status, stretch=1)
        filter_layout.addWidget(self.btn_reset_filters)
        filter_layout.addWidget(self.lbl_count)

        layout.addLayout(filter_layout)

        # Device Table
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Hostname", "Vendor", "Device Type", "Latency", "Status", "Last Seen", "Actions"
        ])
        
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)

        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.table)

    def set_devices(self, devices: list):
        self.raw_devices = devices
        self.apply_filters()

    def reset_filters(self):
        self.txt_search.clear()
        self.cmb_type.setCurrentIndex(0)
        self.cmb_status.setCurrentIndex(0)
        self.apply_filters()

    def set_category_filter(self, category_title: str):
        self.reset_filters()
        if category_title == "Online Devices":
            self.cmb_status.setCurrentText("Online")
        elif category_title == "Offline Devices":
            self.cmb_status.setCurrentText("Offline")
        elif category_title == "Routers / GW":
            self.cmb_type.setCurrentText("Router")
        elif category_title == "Computers":
            self.cmb_type.setCurrentText("Computer")
        elif category_title == "Mobile":
            self.cmb_type.setCurrentText("Mobile")
        elif category_title == "IoT Devices":
            self.cmb_type.setCurrentText("IoT Device")
        self.apply_filters()

    def apply_filters(self):
        query = self.txt_search.text().lower().strip()
        selected_type = self.cmb_type.currentText()
        selected_status = self.cmb_status.currentText()

        filtered = []
        for dev in self.raw_devices:
            ip = str(dev.get("ip", "")).lower()
            mac = str(dev.get("mac", "")).lower()
            host = str(dev.get("hostname", "")).lower()
            vendor = str(dev.get("vendor", "")).lower()
            dev_type = str(dev.get("device_type", ""))
            status = str(dev.get("status", ""))

            # Query match
            if query and not (query in ip or query in mac or query in host or query in vendor):
                continue
            # Type match
            if selected_type != "All Device Types" and dev_type != selected_type:
                continue
            # Status match
            if selected_status != "All Statuses" and status != selected_status:
                continue

            filtered.append(dev)

        self._populate_table(filtered)

    def _populate_table(self, devices: list):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.lbl_count.setText(f"Devices: {len(devices)}")

        for dev in devices:
            row = self.table.rowCount()
            self.table.insertRow(row)

            item_ip = QTableWidgetItem(dev.get("ip", ""))
            item_ip.setData(Qt.ItemDataRole.UserRole, dev)
            
            item_mac = QTableWidgetItem(dev.get("mac", ""))
            item_host = QTableWidgetItem(dev.get("hostname", "Unknown"))
            item_vendor = QTableWidgetItem(dev.get("vendor", "Unknown"))
            item_type = QTableWidgetItem(dev.get("device_type", "Unknown"))
            item_lat = QTableWidgetItem(f"{dev.get('latency', 0.0):.1f} ms")
            item_seen = QTableWidgetItem(dev.get("last_seen", ""))

            self.table.setItem(row, 0, item_ip)
            self.table.setItem(row, 1, item_mac)
            self.table.setItem(row, 2, item_host)
            self.table.setItem(row, 3, item_vendor)
            self.table.setItem(row, 4, item_type)
            self.table.setItem(row, 5, item_lat)

            # Status Badge Cell
            badge = StatusBadge(dev.get("status", "Online"))
            self.table.setCellWidget(row, 6, badge)
            self.table.setItem(row, 7, item_seen)

            # Action Buttons Layout Cell
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setSpacing(4)

            btn_profile = QPushButton("📋 Profile")
            btn_profile.setProperty("class", "SecondaryButton")
            btn_profile.setStyleSheet("padding: 3px 8px; font-size: 11px;")
            btn_profile.clicked.connect(lambda _, d=dev: self.device_selected.emit(d))

            btn_ping = QPushButton("⚡ Ping")
            btn_ping.setProperty("class", "SecondaryButton")
            btn_ping.setStyleSheet("padding: 3px 8px; font-size: 11px;")
            btn_ping.clicked.connect(lambda _, ip=dev.get("ip"): self.ping_requested.emit(ip))

            btn_scan = QPushButton("🔍 Ports")
            btn_scan.setProperty("class", "PrimaryButton")
            btn_scan.setStyleSheet("padding: 3px 8px; font-size: 11px;")
            btn_scan.clicked.connect(lambda _, ip=dev.get("ip"): self.port_scan_requested.emit(ip))

            action_layout.addWidget(btn_profile)
            action_layout.addWidget(btn_ping)
            action_layout.addWidget(btn_scan)
            self.table.setCellWidget(row, 8, action_widget)

        self.table.setSortingEnabled(True)

    def _on_item_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        item_ip = self.table.item(row, 0)
        if item_ip:
            dev_data = item_ip.data(Qt.ItemDataRole.UserRole)
            if dev_data:
                self.device_selected.emit(dev_data)
