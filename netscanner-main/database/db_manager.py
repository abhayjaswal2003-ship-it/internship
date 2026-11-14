import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from config import DB_FILE

class DatabaseManager:
    def __init__(self, db_path=DB_FILE):
        self.db_path = str(db_path)
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Devices table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT UNIQUE NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    os_guess TEXT,
                    status TEXT DEFAULT 'Online',
                    latency REAL,
                    first_seen TEXT,
                    last_seen TEXT,
                    notes TEXT DEFAULT '',
                    connection_count INTEGER DEFAULT 1
                )
            """)

            # Device History table (IP changes, status transitions, custom notes)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    timestamp TEXT NOT NULL
                )
            """)

            # Event Logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.commit()

    def upsert_device(self, device_data: Dict[str, Any]) -> str:
        """Insert or update a device based on MAC/IP address. Returns event type if status changed."""
        mac = device_data.get("mac")
        ip = device_data.get("ip")
        
        # Fallback to synthetic MAC key if ARP couldn't resolve MAC hardware address
        if not mac or mac == "00:00:00:00:00:00":
            mac = f"SYN-{ip}"

        hostname = device_data.get("hostname", "Unknown")
        vendor = device_data.get("vendor", "Unknown")
        device_type = device_data.get("device_type", "Unknown")
        os_guess = device_data.get("os_guess", "Unknown")
        latency = device_data.get("latency", 0.0)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        event_triggered = None

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mac, ip, status, connection_count FROM devices WHERE mac = ? OR ip = ?", (mac, ip))
            row = cursor.fetchone()

            if row:
                existing_mac = row["mac"]
                old_ip = row["ip"]
                old_status = row["status"]
                conn_count = row["connection_count"]

                if old_status == "Offline":
                    event_triggered = "Joined"
                    conn_count += 1
                elif old_ip != ip:
                    event_triggered = "IP Changed"

                cursor.execute("""
                    UPDATE devices
                    SET mac = ?, ip = ?, hostname = COALESCE(NULLIF(?, 'Unknown'), hostname),
                        vendor = COALESCE(NULLIF(?, 'Unknown'), vendor),
                        device_type = ?, os_guess = ?, status = 'Online',
                        latency = ?, last_seen = ?, connection_count = ?
                    WHERE mac = ? OR ip = ?
                """, (mac, ip, hostname, vendor, device_type, os_guess, latency, now_str, conn_count, existing_mac, ip))
            else:
                event_triggered = "New Device Joined"
                cursor.execute("""
                    INSERT INTO devices (mac, ip, hostname, vendor, device_type, os_guess, status, latency, first_seen, last_seen, connection_count)
                    VALUES (?, ?, ?, ?, ?, ?, 'Online', ?, ?, ?, 1)
                """, (mac, ip, hostname, vendor, device_type, os_guess, latency, now_str, now_str))

            if event_triggered:
                details = f"IP: {ip}, Host: {hostname}, Vendor: {vendor}"
                if event_triggered == "IP Changed":
                    details = f"IP changed from {row['ip']} to {ip}"
                cursor.execute("""
                    INSERT INTO device_history (mac, event_type, details, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (mac, event_triggered, details, now_str))

            conn.commit()
        return event_triggered

    def mark_offline_devices(self, active_ips: List[str]) -> List[Dict[str, Any]]:
        """Mark devices not present in current active IPs list as Offline and record history."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        offline_list = []
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if active_ips:
                placeholders = ",".join("?" for _ in active_ips)
                cursor.execute(f"SELECT mac, ip, hostname FROM devices WHERE status = 'Online' AND ip NOT IN ({placeholders})", active_ips)
                offline = cursor.fetchall()
                for dev in offline:
                    d_dict = dict(dev)
                    offline_list.append(d_dict)
                    cursor.execute("""
                        INSERT INTO device_history (mac, event_type, details, timestamp)
                        VALUES (?, 'Left', ?, ?)
                    """, (dev["mac"], f"Device {dev['hostname']} ({dev['ip']}) went offline", now_str))
                cursor.execute(f"UPDATE devices SET status = 'Offline' WHERE ip NOT IN ({placeholders})", active_ips)
            conn.commit()
        return offline_list

    def get_all_devices(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY status DESC, ip ASC")
            return [dict(row) for row in cursor.fetchall()]

    def get_device_by_ip_or_mac(self, query: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE ip = ? OR mac = ?", (query, query))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_device_notes(self, mac: str, notes: str):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE devices SET notes = ? WHERE mac = ?", (notes, mac))
            cursor.execute("""
                INSERT INTO device_history (mac, event_type, details, timestamp)
                VALUES (?, 'Notes Updated', ?, ?)
            """, (mac, f"Updated notes: {notes[:40]}...", now_str))
            conn.commit()

    def get_device_history(self, mac: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM device_history WHERE mac = ? ORDER BY id DESC", (mac,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_history(self, limit: int = 150) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM device_history ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def clear_all_history(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM device_history")
            conn.commit()

    def add_log(self, level: str, source: str, message: str):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs (level, source, message, timestamp) VALUES (?, ?, ?, ?)",
                           (level, source, message, now_str))
            conn.commit()

    def get_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

db_manager = DatabaseManager()
