from PyQt6.QtWidgets import QLabel
from PyQt6.QtCore import Qt

class StatusBadge(QLabel):
    def __init__(self, status: str = "Online", parent=None):
        super().__init__(parent)
        self.set_status(status)

    def set_status(self, status: str):
        self.setText(status.upper())
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if status.lower() == "online":
            self.setStyleSheet("""
                background-color: rgba(34, 197, 94, 0.2);
                color: #22C55E;
                font-weight: bold;
                font-size: 11px;
                border-radius: 10px;
                padding: 4px 10px;
                border: 1px solid rgba(34, 197, 94, 0.4);
            """)
        else:
            self.setStyleSheet("""
                background-color: rgba(239, 68, 68, 0.2);
                color: #EF4444;
                font-weight: bold;
                font-size: 11px;
                border-radius: 10px;
                padding: 4px 10px;
                border: 1px solid rgba(239, 68, 68, 0.4);
            """)
