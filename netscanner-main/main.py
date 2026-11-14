import sys
import os
from pathlib import Path

# Add project directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from ui.main_window import MainWindow
from utils.logger import log_event

def main():
    # Enable High DPI scaling for crisp rendering on high-res screens
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    app = QApplication(sys.argv)
    app.setApplicationName("NetScope Pro")
    app.setOrganizationName("NetScope Security")

    log_event("INFO", "System", "Starting NetScope Pro Network Analyzer...")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
