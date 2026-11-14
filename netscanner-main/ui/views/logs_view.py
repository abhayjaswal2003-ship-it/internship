from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox
)
from database.db_manager import db_manager

class LogsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Toolbar
        hdr_layout = QHBoxLayout()
        lbl_title = QLabel("📑 Live Application Event & System Logs")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 16px;")

        self.cmb_level = QComboBox()
        self.cmb_level.addItems(["All Levels", "INFO", "WARNING", "ERROR"])
        self.cmb_level.currentTextChanged.connect(self.refresh_logs)

        btn_refresh = QPushButton("🔄 Refresh Logs")
        btn_refresh.setProperty("class", "SecondaryButton")
        btn_refresh.clicked.connect(self.refresh_logs)

        hdr_layout.addWidget(lbl_title)
        hdr_layout.addStretch()
        hdr_layout.addWidget(QLabel("Filter:"))
        hdr_layout.addWidget(self.cmb_level)
        hdr_layout.addWidget(btn_refresh)

        layout.addLayout(hdr_layout)

        # Logs Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Level", "Source", "Message"])
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)
        self.refresh_logs()

    def refresh_logs(self):
        logs = db_manager.get_logs(200)
        filter_lvl = self.cmb_level.currentText()

        self.table.setRowCount(0)
        for log in logs:
            lvl = log.get("level", "INFO")
            if filter_lvl != "All Levels" and lvl != filter_lvl:
                continue

            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(log.get("timestamp", "")))
            self.table.setItem(row, 1, QTableWidgetItem(lvl))
            self.table.setItem(row, 2, QTableWidgetItem(log.get("source", "")))
            self.table.setItem(row, 3, QTableWidgetItem(log.get("message", "")))
