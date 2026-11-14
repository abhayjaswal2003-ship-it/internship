import time
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QFrame, QPushButton,
    QLabel, QStackedWidget, QProgressBar, QButtonGroup, QLineEdit, QSystemTrayIcon
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QIcon

from config import config_manager, APP_NAME, APP_VERSION
from ui.styles import ThemeManager
from ui.views.dashboard_view import DashboardView
from ui.views.devices_view import DevicesView
from ui.views.device_detail_dialog import DeviceDetailDialog
from ui.views.network_map_view import NetworkMapView
from ui.views.port_scanner_view import PortScannerView
from ui.views.ping_view import PingView
from ui.views.history_view import HistoryView
from ui.views.logs_view import LogsView
from ui.views.settings_view import SettingsView
from ui.views.pcap_view import PcapView

from core.network_info import get_active_network_info
from core.scanner import HostDiscoveryWorker
from core.monitor import NetworkMonitorWorker
from database.db_manager import db_manager
from utils.notifier import get_notifier
from utils.logger import log_event

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} - Network Analyzer & Device Discovery")
        self.resize(1280, 800)

        self.net_info = get_active_network_info()
        self.current_devices = []
        self.scan_worker = None
        self.notifier = get_notifier()

        self.init_ui()
        self.apply_theme(config_manager.get("theme", "Dark Mode"))

        # Initialize Real-Time Network IO Traffic Monitor Thread
        self.monitor_worker = NetworkMonitorWorker(sample_interval=1.0)
        self.monitor_worker.traffic_updated.connect(self._on_traffic_updated)
        self.monitor_worker.start()

        # Rescan Auto Timer
        self.rescan_timer = QTimer(self)
        self.rescan_timer.timeout.connect(self.trigger_scan)
        interval_ms = config_manager.get("scan_interval", 30) * 1000
        self.rescan_timer.start(interval_ms)

        # Initial Network Scan
        QTimer.singleShot(500, self.trigger_scan)

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Left Sidebar Navigation Frame
        sidebar = QFrame()
        sidebar.setObjectName("SidebarFrame")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(6)

        # App Brand Header
        lbl_brand = QLabel(f"⚡ {APP_NAME}")
        lbl_brand.setObjectName("SidebarHeader")
        sidebar_layout.addWidget(lbl_brand)

        lbl_sub = QLabel("Pro Network Discovery")
        lbl_sub.setStyleSheet("color: #94A3B8; font-size: 11px; margin-left: 15px; margin-bottom: 15px;")
        sidebar_layout.addWidget(lbl_sub)

        # Navigation Buttons
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_items = [
            ("📊 Dashboard", 0),
            ("💻 Devices Inventory", 1),
            ("🌐 Network Topology Map", 2),
            ("🔍 Port Scanner", 3),
            ("⚡ Ping Utility", 4),
            ("📜 History & Export", 5),
            ("📑 System Logs", 6),
            ("⚙️ Settings", 7),
            ("🔬 PCAP Analyzer", 8),
        ]

        self.nav_buttons = []
        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setProperty("class", "NavButton")
            btn.setCheckable(True)
            if index == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda _, idx=index: self.switch_page(idx))
            self.nav_group.addButton(btn, index)
            self.nav_buttons.append(btn)
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()

        # Active Adapter Status Badge at Bottom Sidebar
        self.lbl_adapter_badge = QLabel(f"Adapter: {self.net_info.get('interface')}\nIP: {self.net_info.get('local_ip')}")
        self.lbl_adapter_badge.setStyleSheet("""
            background-color: rgba(56, 189, 248, 0.1);
            color: #38BDF8;
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 6px;
            padding: 8px;
            font-size: 11px;
        """)
        sidebar_layout.addWidget(self.lbl_adapter_badge)

        main_layout.addWidget(sidebar, stretch=0)

        # 2. Main Content Area (Top Bar + QStackedWidget Views)
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Top Bar
        top_bar = QFrame()
        top_bar.setObjectName("TopHeaderBar")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(16, 10, 16, 10)

        self.btn_rescan = QPushButton("🔄 Rescan Network")
        self.btn_rescan.setProperty("class", "PrimaryButton")
        self.btn_rescan.clicked.connect(self.trigger_scan)

        self.scan_progress = QProgressBar()
        self.scan_progress.setFixedHeight(16)
        self.scan_progress.setValue(0)

        self.lbl_status = QLabel("Ready.")
        self.lbl_status.setStyleSheet("color: #94A3B8; font-style: italic;")

        top_layout.addWidget(self.btn_rescan)
        top_layout.addWidget(self.scan_progress, stretch=2)
        top_layout.addWidget(self.lbl_status, stretch=3)

        content_layout.addWidget(top_bar)

        # Stacked Views
        self.stacked_widget = QStackedWidget()

        self.view_dashboard = DashboardView()
        self.view_devices = DevicesView()
        self.view_netmap = NetworkMapView()
        self.view_ports = PortScannerView()
        self.view_ping = PingView()
        self.view_history = HistoryView()
        self.view_logs = LogsView()
        self.view_settings = SettingsView()
        self.view_pcap = PcapView()

        # Connect interactive signals
        self.view_dashboard.stat_card_clicked.connect(self.on_dashboard_card_clicked)
        self.view_dashboard.event_double_clicked.connect(self.on_event_double_clicked)
        
        self.view_devices.device_selected.connect(self.show_device_detail)
        self.view_devices.ping_requested.connect(self.navigate_to_ping)
        self.view_devices.port_scan_requested.connect(self.navigate_to_port_scan)
        
        self.view_netmap.node_clicked.connect(self.show_device_detail)
        self.view_history.history_item_clicked.connect(self.on_history_item_clicked)
        self.view_settings.theme_changed.connect(self.apply_theme)

        self.stacked_widget.addWidget(self.view_dashboard)
        self.stacked_widget.addWidget(self.view_devices)
        self.stacked_widget.addWidget(self.view_netmap)
        self.stacked_widget.addWidget(self.view_ports)
        self.stacked_widget.addWidget(self.view_ping)
        self.stacked_widget.addWidget(self.view_history)
        self.stacked_widget.addWidget(self.view_logs)
        self.stacked_widget.addWidget(self.view_settings)
        self.stacked_widget.addWidget(self.view_pcap)

        content_layout.addWidget(self.stacked_widget)
        main_layout.addLayout(content_layout, stretch=1)

        # Initialize network info on dashboard
        self.view_dashboard.update_network_info(self.net_info)

    def switch_page(self, index: int):
        self.stacked_widget.setCurrentIndex(index)
        if index == 5:
            self.view_history.refresh_history()
        elif index == 6:
            self.view_logs.refresh_logs()

    def apply_theme(self, theme_name: str):
        qss = ThemeManager.get_qss(theme_name)
        self.setStyleSheet(qss)

    def on_dashboard_card_clicked(self, category_title: str):
        self.view_devices.set_category_filter(category_title)
        self.nav_buttons[1].setChecked(True)
        self.switch_page(1)

    def on_event_double_clicked(self, ev_data: dict):
        details = ev_data.get("details", "")
        # Extract IP from details string e.g. "IP: 192.168.1.43"
        dev = None
        for d in self.current_devices:
            if d.get("ip") and d.get("ip") in details:
                dev = d
                break
        if dev:
            self.show_device_detail(dev)

    def on_history_item_clicked(self, mac: str):
        dev = next((d for d in self.current_devices if d.get("mac") == mac), None)
        if dev:
            self.show_device_detail(dev)

    def trigger_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            return

        self.btn_rescan.setEnabled(False)
        self.scan_progress.setValue(5)
        self.lbl_status.setText("Scanning network hosts...")

        net_range = self.net_info.get("network_range", "192.168.1.0/24")
        local_ip = self.net_info.get("local_ip", "127.0.0.1")
        local_mac = self.net_info.get("mac_address", "00:00:00:00:00:00")
        timeout = config_manager.get("ping_timeout", 1.5)

        self.scan_worker = HostDiscoveryWorker(net_range, local_ip, local_mac, timeout=timeout)
        self.scan_worker.scan_progress.connect(self._on_scan_progress)
        self.scan_worker.scan_completed.connect(self._on_scan_completed)
        self.scan_worker.scan_failed.connect(self._on_scan_failed)
        self.scan_worker.start()

        log_event("INFO", "Scanner", f"Initiated discovery scan on {net_range}")

    def _on_scan_progress(self, percent: int, msg: str):
        self.scan_progress.setValue(percent)
        self.lbl_status.setText(msg)

    def _on_scan_completed(self, discovered_devices: list, elapsed: float):
        self.btn_rescan.setEnabled(True)
        self.scan_progress.setValue(100)
        self.lbl_status.setText(f"Scan complete. {len(discovered_devices)} active devices found in {elapsed}s.")

        active_ips = []
        for dev in discovered_devices:
            ip = dev.get("ip")
            if ip:
                active_ips.append(ip)
                event = db_manager.upsert_device(dev)
                if event:
                    if "Joined" in event and config_manager.get("notify_on_new_device", True):
                        self.notifier.notify("🟢 Device Online", f"Host {dev.get('hostname')} ({dev.get('ip')}) joined/online.")
                    log_event("INFO", "DeviceTracker", f"{event}: {dev.get('ip')} ({dev.get('hostname')})")

        newly_offline = db_manager.mark_offline_devices(active_ips)
        for off_dev in newly_offline:
            if config_manager.get("notify_on_disconnect", True):
                self.notifier.notify("🔴 Device Disconnected", f"Host {off_dev.get('hostname')} ({off_dev.get('ip')}) is now offline.")
            log_event("WARNING", "DeviceTracker", f"Device Disconnected: {off_dev.get('ip')} ({off_dev.get('hostname')})")
        self.current_devices = db_manager.get_all_devices()

        # Update all views with new device data
        self.view_dashboard.update_stats(self.current_devices)
        self.view_dashboard.update_events(db_manager.get_all_history(30))
        self.view_devices.set_devices(self.current_devices)
        self.view_netmap.set_devices(self.current_devices, self.net_info.get("gateway"))
        self.view_ports.populate_target_hosts(self.current_devices)
        self.view_ping.populate_target_hosts(self.current_devices)

    def _on_scan_failed(self, error_msg: str):
        self.btn_rescan.setEnabled(True)
        self.scan_progress.setValue(0)
        self.lbl_status.setText(f"Scan failed: {error_msg}")
        log_event("ERROR", "Scanner", f"Scan error: {error_msg}")

    def _on_traffic_updated(self, metrics: dict):
        # Update Dashboard Bandwidth Chart
        up_kb = metrics["upload_speed_bytes"] / 1024.0
        down_kb = metrics["download_speed_bytes"] / 1024.0
        self.view_dashboard.chart_widget.update_data(up_kb, down_kb)

    def show_device_detail(self, device_data: dict):
        dlg = DeviceDetailDialog(device_data, self)
        dlg.ping_triggered.connect(self.navigate_to_ping)
        dlg.port_scan_triggered.connect(self.navigate_to_port_scan)
        dlg.exec()
        self.current_devices = db_manager.get_all_devices()
        self.view_devices.set_devices(self.current_devices)

    def navigate_to_ping(self, target_ip: str):
        self.view_ping.set_target_ip(target_ip)
        self.nav_buttons[4].setChecked(True)
        self.switch_page(4)

    def navigate_to_port_scan(self, target_ip: str):
        self.view_ports.set_target_ip(target_ip)
        self.nav_buttons[3].setChecked(True)
        self.switch_page(3)

    def closeEvent(self, event):
        if hasattr(self, 'monitor_worker') and self.monitor_worker:
            self.monitor_worker.stop()
            self.monitor_worker.wait(1000)
        event.accept()
