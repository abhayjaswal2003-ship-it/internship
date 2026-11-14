import os
import json
from pathlib import Path

APP_NAME = "NetScope Pro"
APP_VERSION = "1.0.0"

# Directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

CONFIG_FILE = DATA_DIR / "config.json"
DB_FILE = DATA_DIR / "netscope.db"
LOG_FILE = DATA_DIR / "app.log"
EXPORT_DIR = DATA_DIR / "exports"
EXPORT_DIR.mkdir(exist_ok=True)

DEFAULT_CONFIG = {
    "scan_interval": 30,         # Seconds
    "ping_timeout": 1.5,         # Seconds
    "max_threads": 50,           # Max concurrent host discovery threads
    "preferred_interface": "",   # Auto-detect if empty
    "theme": "Dark Mode",        # Options: "Dark Mode", "Light Mode", "Blue Cyber", "Green Hacker"
    "notifications_enabled": True,
    "notify_on_new_device": True,
    "notify_on_disconnect": True,
    "export_directory": str(EXPORT_DIR),
    "port_scan_timeout": 1.0,
    "port_scan_delay": 0.05,     # Delay between port probes for rate-limiting
}

class ConfigManager:
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()

    def load_config(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.config.update(data)
            except Exception as e:
                print(f"Error loading config: {e}")
        else:
            self.save_config()

    def save_config(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save_config()

config_manager = ConfigManager()
