from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QFrame
)
from PyQt6.QtCore import pyqtSignal, Qt
import pyqtgraph as pg
from core.ping_tool import PingWorker
from ui.components.stat_card import StatCard

class PingView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header Title
        lbl_title = QLabel("⚡ Continuous Latency & Response Ping Diagnostics")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(lbl_title)

        # Controls Panel
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "StatCard")
        ctrl_layout = QHBoxLayout(ctrl_card)
        ctrl_layout.setSpacing(12)

        lbl_target = QLabel("Target Host IP:")
        self.cmb_target = QComboBox()
        self.cmb_target.setEditable(True)
        self.cmb_target.setPlaceholderText("Select host or enter IP...")

        lbl_count = QLabel("Ping Count:")
        self.cmb_count = QComboBox()
        self.cmb_count.addItems(["10 Packets", "25 Packets", "50 Packets", "Continuous (Infinite)"])

        self.btn_start = QPushButton("⚡ Start Ping")
        self.btn_start.setProperty("class", "PrimaryButton")
        self.btn_start.clicked.connect(self.start_ping)

        self.btn_stop = QPushButton("⏹️ Stop")
        self.btn_stop.setProperty("class", "SecondaryButton")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_ping)

        ctrl_layout.addWidget(lbl_target)
        ctrl_layout.addWidget(self.cmb_target, stretch=2)
        ctrl_layout.addWidget(lbl_count)
        ctrl_layout.addWidget(self.cmb_count, stretch=1)
        ctrl_layout.addWidget(self.btn_start)
        ctrl_layout.addWidget(self.btn_stop)

        layout.addWidget(ctrl_card)

        # Stats Cards Grid
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.card_sent = StatCard("Packets Sent", "0", "Total ICMP probes", "📤")
        self.card_received = StatCard("Packets Received", "0", "Replies received", "📥")
        self.card_loss = StatCard("Packet Loss", "0%", "Dropped packets", "⚠️")
        self.card_min = StatCard("Min Latency", "0 ms", "Fastest response", "🚀")
        self.card_max = StatCard("Max Latency", "0 ms", "Slowest response", "🐢")
        self.card_avg = StatCard("Avg Latency", "0 ms", "Mean roundtrip", "📊")

        stats_layout.addWidget(self.card_sent)
        stats_layout.addWidget(self.card_received)
        stats_layout.addWidget(self.card_loss)
        stats_layout.addWidget(self.card_min)
        stats_layout.addWidget(self.card_max)
        stats_layout.addWidget(self.card_avg)

        layout.addLayout(stats_layout)

        # Chart & Logs Split
        split_layout = QHBoxLayout()
        split_layout.setSpacing(16)

        # Pyqtgraph Latency Curve Chart
        pg.setConfigOption('background', '#1E293B')
        pg.setConfigOption('foreground', '#94A3B8')

        self.plot_widget = pg.PlotWidget(title="Response Latency (ms)")
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setLabel('left', 'Latency', units='ms')
        self.plot_widget.setLabel('bottom', 'Sequence', units='#')

        self.curve = self.plot_widget.plot(pen=pg.mkPen(color='#38BDF8', width=2), symbol='o', symbolSize=6, symbolBrush='#0284C7')
        self.latency_data = []

        split_layout.addWidget(self.plot_widget, stretch=3)

        # Ping Log Table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Seq #", "Target IP", "Latency", "Status", "Timestamp"])
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        split_layout.addWidget(self.table, stretch=2)
        layout.addLayout(split_layout)

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

    def start_ping(self):
        target = self.cmb_target.currentData() or self.cmb_target.currentText().split()[0].strip()
        if not target:
            return

        cnt_str = self.cmb_count.currentText()
        count = 10
        if "25" in cnt_str:
            count = 25
        elif "50" in cnt_str:
            count = 50
        elif "Continuous" in cnt_str:
            count = 0

        self.table.setRowCount(0)
        self.latency_data.clear()
        self.curve.setData([])

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self.worker = PingWorker(target, count=count)
        self.worker.ping_result.connect(self._on_ping_result)
        self.worker.ping_stats.connect(self._on_ping_stats)
        self.worker.ping_finished.connect(self._on_ping_finished)
        self.worker.start()

    def stop_ping(self):
        if self.worker:
            self.worker.stop()

    def _on_ping_result(self, res: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(res["seq"])))
        self.table.setItem(row, 1, QTableWidgetItem(res["ip"]))

        lat_val = res["latency"]
        if lat_val is not None:
            self.table.setItem(row, 2, QTableWidgetItem(f"{lat_val} ms"))
            self.latency_data.append(lat_val)
            self.curve.setData(self.latency_data)
            
            st_item = QTableWidgetItem(res["status"])
            st_item.setForeground(Qt.GlobalColor.green)
            self.table.setItem(row, 3, st_item)
        else:
            self.table.setItem(row, 2, QTableWidgetItem("N/A"))
            st_item = QTableWidgetItem(res["status"])
            st_item.setForeground(Qt.GlobalColor.red)
            self.table.setItem(row, 3, st_item)

        self.table.setItem(row, 4, QTableWidgetItem(res["timestamp"]))
        self.table.scrollToBottom()

    def _on_ping_stats(self, stats: dict):
        self.card_sent.set_value(stats["sent"])
        self.card_received.set_value(stats["received"])
        self.card_loss.set_value(f"{stats['loss_percent']}%")
        self.card_min.set_value(f"{stats['min']} ms")
        self.card_max.set_value(f"{stats['max']} ms")
        self.card_avg.set_value(f"{stats['avg']} ms")

    def _on_ping_finished(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
