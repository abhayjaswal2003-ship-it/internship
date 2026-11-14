from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt, pyqtSignal
from ui.components.stat_card import StatCard
from ui.components.traffic_chart import TrafficChartWidget

class DashboardView(QWidget):
    stat_card_clicked = pyqtSignal(str)          # Emits card category title
    event_double_clicked = pyqtSignal(dict)       # Emits event data dict

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Active Network Information Card Header
        self.net_info_frame = QFrame()
        self.net_info_frame.setProperty("class", "StatCard")
        net_layout = QHBoxLayout(self.net_info_frame)
        net_layout.setContentsMargins(16, 12, 16, 12)

        self.lbl_ip = QLabel("Local IP: Detecting...")
        self.lbl_ip.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.lbl_gateway = QLabel("Gateway: Detecting...")
        self.lbl_mac = QLabel("MAC: Detecting...")
        self.lbl_interface = QLabel("Adapter: Detecting...")
        self.lbl_range = QLabel("Subnet: Detecting...")

        net_layout.addWidget(self.lbl_ip)
        net_layout.addWidget(self.lbl_gateway)
        net_layout.addWidget(self.lbl_mac)
        net_layout.addWidget(self.lbl_interface)
        net_layout.addWidget(self.lbl_range)
        layout.addWidget(self.net_info_frame)

        # Overview Stats Grid (Clickable Cards)
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.card_total = StatCard("Total Devices", "0", "Discovered hosts", "🌐")
        self.card_online = StatCard("Online Devices", "0", "Active on network", "🟢")
        self.card_offline = StatCard("Offline Devices", "0", "Inactive records", "🔴")
        self.card_routers = StatCard("Routers / GW", "0", "Network gateways", "📡")
        self.card_computers = StatCard("Computers", "0", "Desktops & Laptops", "💻")
        self.card_mobile = StatCard("Mobile", "0", "Smartphones & Tablets", "📱")
        self.card_iot = StatCard("IoT Devices", "0", "Smart & Embedded", "🔌")

        cards = [self.card_total, self.card_online, self.card_offline, self.card_routers, self.card_computers, self.card_mobile, self.card_iot]
        for card in cards:
            card.clicked.connect(lambda category: self.stat_card_clicked.emit(category))
            stats_layout.addWidget(card)

        layout.addLayout(stats_layout)

        # Traffic Chart & Recent Events Feed Split
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(16)

        # Chart
        self.chart_widget = TrafficChartWidget("Live Bandwidth Utilization")
        mid_layout.addWidget(self.chart_widget, stretch=3)

        # Recent Activity Table (Double clickable)
        activity_frame = QFrame()
        activity_frame.setProperty("class", "StatCard")
        act_layout = QVBoxLayout(activity_frame)
        act_layout.setContentsMargins(12, 12, 12, 12)

        lbl_act_header = QLabel("⚡ Recent Network Events (Double-click to inspect)")
        lbl_act_header.setStyleSheet("font-weight: bold; font-size: 13px; margin-bottom: 6px;")
        act_layout.addWidget(lbl_act_header)

        self.tbl_activity = QTableWidget(0, 3)
        self.tbl_activity.setHorizontalHeaderLabels(["Time", "Event", "Details"])
        self.tbl_activity.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_activity.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_activity.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl_activity.verticalHeader().setVisible(False)
        self.tbl_activity.setAlternatingRowColors(True)
        self.tbl_activity.itemDoubleClicked.connect(self._on_event_double_clicked)

        act_layout.addWidget(self.tbl_activity)
        mid_layout.addWidget(activity_frame, stretch=2)

        layout.addLayout(mid_layout)

    def update_network_info(self, info: dict):
        self.lbl_ip.setText(f"Local IP: <b>{info.get('local_ip')}</b>")
        self.lbl_gateway.setText(f"Gateway: <b>{info.get('gateway')}</b>")
        self.lbl_mac.setText(f"MAC: <b>{info.get('mac_address')}</b>")
        self.lbl_interface.setText(f"Adapter: <b>{info.get('interface')}</b>")
        self.lbl_range.setText(f"Range: <b>{info.get('network_range')}</b>")

    def update_stats(self, devices: list):
        total = len(devices)
        online = sum(1 for d in devices if d.get("status") == "Online")
        offline = total - online
        routers = sum(1 for d in devices if d.get("device_type") == "Router")
        computers = sum(1 for d in devices if d.get("device_type") == "Computer")
        mobiles = sum(1 for d in devices if d.get("device_type") == "Mobile")
        iot = sum(1 for d in devices if d.get("device_type") == "IoT Device")

        self.card_total.set_value(total)
        self.card_online.set_value(online)
        self.card_offline.set_value(offline)
        self.card_routers.set_value(routers)
        self.card_computers.set_value(computers)
        self.card_mobile.set_value(mobiles)
        self.card_iot.set_value(iot)

    def update_events(self, events: list):
        self.tbl_activity.setRowCount(0)
        for ev in events[:30]:
            row = self.tbl_activity.rowCount()
            self.tbl_activity.insertRow(row)
            
            item_time = QTableWidgetItem(ev.get("timestamp", ""))
            item_time.setData(Qt.ItemDataRole.UserRole, ev)

            self.tbl_activity.setItem(row, 0, item_time)
            self.tbl_activity.setItem(row, 1, QTableWidgetItem(ev.get("event_type", "")))
            self.tbl_activity.setItem(row, 2, QTableWidgetItem(ev.get("details", "")))

    def _on_event_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        item_time = self.tbl_activity.item(row, 0)
        if item_time:
            ev_data = item_time.data(Qt.ItemDataRole.UserRole)
            if ev_data:
                self.event_double_clicked.emit(ev_data)
