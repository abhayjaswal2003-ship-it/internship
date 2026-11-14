from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QCheckBox, QSpinBox, QDoubleSpinBox, QFileDialog, QFrame, QMessageBox
)
from PyQt6.QtCore import pyqtSignal
from config import config_manager
import psutil

class SettingsView(QWidget):
    theme_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Header Title
        lbl_title = QLabel("⚙️ Application Preferences & Configuration")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(lbl_title)

        # Settings Form Card
        card = QFrame()
        card.setProperty("class", "StatCard")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(14)

        # 1. Theme Selector
        row_theme = QHBoxLayout()
        row_theme.addWidget(QLabel("🎨 Color Theme Palette:"), stretch=2)
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItems(["Dark Mode", "Light Mode", "Blue Cyber", "Green Hacker"])
        self.cmb_theme.setCurrentText(config_manager.get("theme", "Dark Mode"))
        self.cmb_theme.currentTextChanged.connect(self._on_theme_selected)
        row_theme.addWidget(self.cmb_theme, stretch=3)
        card_layout.addLayout(row_theme)

        # 2. Auto Scan Interval
        row_interval = QHBoxLayout()
        row_interval.addWidget(QLabel("⏱️ Automatic Rescan Interval (seconds):"), stretch=2)
        self.spn_interval = QSpinBox()
        self.spn_interval.setRange(5, 3600)
        self.spn_interval.setValue(config_manager.get("scan_interval", 30))
        row_interval.addWidget(self.spn_interval, stretch=3)
        card_layout.addLayout(row_interval)

        # 3. Timeout
        row_timeout = QHBoxLayout()
        row_timeout.addWidget(QLabel("🎯 Host Ping Probe Timeout (seconds):"), stretch=2)
        self.spn_timeout = QDoubleSpinBox()
        self.spn_timeout.setRange(0.2, 10.0)
        self.spn_timeout.setSingleStep(0.2)
        self.spn_timeout.setValue(config_manager.get("ping_timeout", 1.5))
        row_timeout.addWidget(self.spn_timeout, stretch=3)
        card_layout.addLayout(row_timeout)

        # 4. Preferred Network Interface
        row_iface = QHBoxLayout()
        row_iface.addWidget(QLabel("📡 Preferred Network Adapter:"), stretch=2)
        self.cmb_iface = QComboBox()
        self.cmb_iface.addItem("Auto-Detect Active Interface", "")
        for iface in psutil.net_if_addrs().keys():
            self.cmb_iface.addItem(iface, iface)
        pref_iface = config_manager.get("preferred_interface", "")
        idx = self.cmb_iface.findData(pref_iface)
        if idx >= 0:
            self.cmb_iface.setCurrentIndex(idx)
        row_iface.addWidget(self.cmb_iface, stretch=3)
        card_layout.addLayout(row_iface)

        # 5. Notifications
        self.chk_notify_new = QCheckBox("🔔 Notify when new unknown device joins network")
        self.chk_notify_new.setChecked(config_manager.get("notify_on_new_device", True))
        card_layout.addWidget(self.chk_notify_new)

        self.chk_notify_left = QCheckBox("🔔 Notify when existing device disconnects")
        self.chk_notify_left.setChecked(config_manager.get("notify_on_disconnect", True))
        card_layout.addWidget(self.chk_notify_left)

        # 6. Export Location
        row_export = QHBoxLayout()
        row_export.addWidget(QLabel("📁 Default Export Save Folder:"), stretch=2)
        self.txt_export_path = QLineEdit(config_manager.get("export_directory", ""))
        btn_browse = QPushButton("📁 Browse")
        btn_browse.setProperty("class", "SecondaryButton")
        btn_browse.clicked.connect(self._browse_folder)
        row_export.addWidget(self.txt_export_path, stretch=3)
        row_export.addWidget(btn_browse)
        card_layout.addLayout(row_export)

        layout.addWidget(card)

        # Action Save Button
        btn_save = QPushButton("💾 Save Settings")
        btn_save.setProperty("class", "PrimaryButton")
        btn_save.setStyleSheet("padding: 10px 24px; font-size: 14px;")
        btn_save.clicked.connect(self.save_settings)

        layout.addWidget(btn_save)
        layout.addStretch()

    def _on_theme_selected(self, theme_name: str):
        config_manager.set("theme", theme_name)
        self.theme_changed.emit(theme_name)

    def _browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Export Directory", self.txt_export_path.text())
        if folder:
            self.txt_export_path.setText(folder)

    def save_settings(self):
        config_manager.set("scan_interval", self.spn_interval.value())
        config_manager.set("ping_timeout", self.spn_timeout.value())
        config_manager.set("preferred_interface", self.cmb_iface.currentData())
        config_manager.set("notify_on_new_device", self.chk_notify_new.isChecked())
        config_manager.set("notify_on_disconnect", self.chk_notify_left.isChecked())
        config_manager.set("export_directory", self.txt_export_path.text())
        QMessageBox.information(self, "Settings Saved", "Application settings successfully saved.")
