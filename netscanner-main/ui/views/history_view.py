from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QFrame, QMessageBox
)
from PyQt6.QtCore import pyqtSignal, Qt
from database.db_manager import db_manager
from utils.exporter import Exporter
from config import config_manager

class HistoryView(QWidget):
    history_item_clicked = pyqtSignal(str) # Emits MAC address on double click

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header & Export Toolbar
        hdr_layout = QHBoxLayout()
        lbl_title = QLabel("📜 Historical Records & Report Exporter")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 16px;")

        btn_csv = QPushButton("📄 Export CSV")
        btn_csv.setProperty("class", "SecondaryButton")
        btn_csv.clicked.connect(lambda: self._export_format("csv"))

        btn_json = QPushButton("📦 Export JSON")
        btn_json.setProperty("class", "SecondaryButton")
        btn_json.clicked.connect(lambda: self._export_format("json"))

        btn_excel = QPushButton("📊 Export Excel")
        btn_excel.setProperty("class", "SecondaryButton")
        btn_excel.clicked.connect(lambda: self._export_format("excel"))

        btn_pdf = QPushButton("📕 Export PDF Report")
        btn_pdf.setProperty("class", "PrimaryButton")
        btn_pdf.clicked.connect(lambda: self._export_format("pdf"))

        btn_clear = QPushButton("🗑️ Clear History")
        btn_clear.setProperty("class", "SecondaryButton")
        btn_clear.setStyleSheet("color: #EF4444;")
        btn_clear.clicked.connect(self._clear_history)

        hdr_layout.addWidget(lbl_title)
        hdr_layout.addStretch()
        hdr_layout.addWidget(btn_csv)
        hdr_layout.addWidget(btn_json)
        hdr_layout.addWidget(btn_excel)
        hdr_layout.addWidget(btn_pdf)
        hdr_layout.addWidget(btn_clear)

        layout.addLayout(hdr_layout)

        # History Records Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "MAC Address", "Event Type", "Event Details / Timestamps"])
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)

        layout.addWidget(self.table)
        self.refresh_history()

    def refresh_history(self):
        records = db_manager.get_all_history(200)
        self.table.setRowCount(0)
        for r in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            item_mac = QTableWidgetItem(r.get("mac", ""))
            item_mac.setData(Qt.ItemDataRole.UserRole, r)

            self.table.setItem(row, 0, QTableWidgetItem(str(r.get("id", ""))))
            self.table.setItem(row, 1, item_mac)
            self.table.setItem(row, 2, QTableWidgetItem(r.get("event_type", "")))
            self.table.setItem(row, 3, QTableWidgetItem(f"{r.get('timestamp')} | {r.get('details', '')}"))

    def _on_item_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        item_mac = self.table.item(row, 1)
        if item_mac:
            rec = item_mac.data(Qt.ItemDataRole.UserRole)
            if rec and rec.get("mac"):
                self.history_item_clicked.emit(rec.get("mac"))

    def _clear_history(self):
        res = QMessageBox.question(self, "Clear History", "Are you sure you want to clear all historical event records?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if res == QMessageBox.StandardButton.Yes:
            db_manager.clear_all_history()
            self.refresh_history()

    def _export_format(self, fmt: str):
        devices = db_manager.get_all_devices()
        if not devices:
            QMessageBox.information(self, "No Data", "No device records available to export.")
            return

        default_dir = config_manager.get("export_directory", ".")
        filename = f"netscope_report_{fmt}.{fmt}" if fmt != "excel" else "netscope_report.xlsx"
        save_path, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()} Report", f"{default_dir}/{filename}")

        if not save_path:
            return

        success = False
        if fmt == "csv":
            success = Exporter.export_csv(save_path, devices)
        elif fmt == "json":
            success = Exporter.export_json(save_path, devices)
        elif fmt == "excel":
            success = Exporter.export_excel(save_path, devices)
        elif fmt == "pdf":
            success = Exporter.export_pdf(save_path, devices)

        if success:
            QMessageBox.information(self, "Export Complete", f"Successfully exported report to:\n{save_path}")
        else:
            QMessageBox.critical(self, "Export Failed", f"Failed to generate {fmt.upper()} report.")
