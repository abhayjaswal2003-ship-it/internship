from PyQt6.QtWidgets import QFrame, QVBoxLayout, QLabel, QHBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal

class StatCard(QFrame):
    clicked = pyqtSignal(str) # Emits card title on click

    def __init__(self, title: str, value: str = "0", subtext: str = "", icon_str: str = "📊", parent=None):
        super().__init__(parent)
        self.title = title
        self.setObjectName("StatCard")
        self.setProperty("class", "StatCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        top_layout = QHBoxLayout()
        self.lbl_title = QLabel(title)
        self.lbl_title.setProperty("class", "StatTitle")
        
        self.lbl_icon = QLabel(icon_str)
        self.lbl_icon.setStyleSheet("font-size: 18px;")

        top_layout.addWidget(self.lbl_title)
        top_layout.addStretch()
        top_layout.addWidget(self.lbl_icon)

        self.lbl_value = QLabel(value)
        self.lbl_value.setProperty("class", "StatValue")

        self.lbl_subtext = QLabel(subtext)
        self.lbl_subtext.setStyleSheet("font-size: 11px; color: #94A3B8;")

        layout.addLayout(top_layout)
        layout.addWidget(self.lbl_value)
        layout.addWidget(self.lbl_subtext)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.title)
        super().mousePressEvent(event)

    def set_value(self, val: str):
        self.lbl_value.setText(str(val))

    def set_subtext(self, text: str):
        self.lbl_subtext.setText(text)
