import socket
import time
from typing import List, Dict, Any
from PyQt6.QtCore import QThread, pyqtSignal

# Well-known TCP services dictionary
COMMON_PORTS = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted text communications"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol"),
    135: ("RPC", "Microsoft RPC EPMAP"),
    139: ("NetBIOS", "NetBIOS Session Service"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "HTTP Secure (SSL/TLS)"),
    445: ("SMB", "Microsoft Directory Services / Samba"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "Virtual Network Computing"),
    8080: ("HTTP-Proxy", "HTTP Alternate / Proxy"),
    8443: ("HTTPS-Alt", "HTTPS Alternate"),
    27017: ("MongoDB", "MongoDB Database"),
}

class PortScanWorker(QThread):
    """
    Threaded TCP port scanner with rate-limiting and progress tracking.
    """
    port_progress = pyqtSignal(int, str)       # progress percentage, current status text
    port_found = pyqtSignal(dict)              # open port info dict
    scan_finished = pyqtSignal(list, float)    # list of open ports, duration in seconds

    def __init__(self, ip: str, ports: List[int], timeout: float = 1.0, delay: float = 0.05):
        super().__init__()
        self.ip = ip
        self.ports = sorted(ports)
        self.timeout = timeout
        self.delay = delay
        self.is_cancelled = False

    def cancel(self):
        self.is_cancelled = True

    def run(self):
        start_time = time.time()
        open_ports = []
        total_ports = len(self.ports)

        for idx, port in enumerate(self.ports, start=1):
            if self.is_cancelled:
                break

            service_name, desc = COMMON_PORTS.get(port, ("Unknown", "Custom Application"))
            percent = int((idx / total_ports) * 100)
            self.port_progress.emit(percent, f"Testing port {port} ({service_name})...")

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                t0 = time.time()
                res = s.connect_ex((self.ip, port))
                t1 = time.time()
                s.close()

                if res == 0:
                    port_info = {
                        "port": port,
                        "protocol": "TCP",
                        "service": service_name,
                        "description": desc,
                        "state": "Open",
                        "response_time": round((t1 - t0) * 1000, 2),
                    }
                    open_ports.append(port_info)
                    self.port_found.emit(port_info)

            except Exception as e:
                print(f"Error scanning port {port}: {e}")

            # Rate-limiting delay to prevent aggressive scanning
            if self.delay > 0:
                time.sleep(self.delay)

        duration = round(time.time() - start_time, 2)
        self.port_progress.emit(100, f"Port scan complete. Found {len(open_ports)} open ports.")
        self.scan_finished.emit(open_ports, duration)
