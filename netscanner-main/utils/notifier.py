from PyQt6.QtWidgets import QSystemTrayIcon, QStyle, QApplication
from PyQt6.QtGui import QIcon
from config import config_manager

class SystemNotifier:
    def __init__(self, app_icon: QIcon = None):
        self.tray = None
        if QApplication.instance():
            self.tray = QSystemTrayIcon()
            if app_icon and not app_icon.isNull():
                self.tray.setIcon(app_icon)
            else:
                standard_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
                self.tray.setIcon(standard_icon)
            self.tray.show()

    def notify(self, title: str, message: str, icon_type=QSystemTrayIcon.MessageIcon.Information):
        if not config_manager.get("notifications_enabled", True):
            return
        if self.tray and QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.showMessage(title, message, icon_type, 3000)

notifier = None
def get_notifier(app_icon: QIcon = None) -> SystemNotifier:
    global notifier
    if notifier is None:
        notifier = SystemNotifier(app_icon)
    return notifier
