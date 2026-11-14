import re
import socket
import time
import subprocess
from typing import Optional
from PyQt6.QtCore import QThread, pyqtSignal

class PingWorker(QThread):
    """
    Continuous or count-based Ping worker emitting live response latency and stats.
    """
    ping_result = pyqtSignal(dict)             # sequence, latency_ms, status, timestamp
    ping_stats = pyqtSignal(dict)              # min, max, avg, sent, received, loss_percent
    ping_finished = pyqtSignal()

    def __init__(self, target_ip: str, count: int = 10, interval: float = 1.0, timeout: float = 1.0):
        super().__init__()
        self.target_ip = target_ip
        self.count = count                      # 0 for continuous
        self.interval = interval
        self.timeout = timeout
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        seq = 0
        latencies = []
        sent = 0
        received = 0

        while self.is_running and (self.count == 0 or seq < self.count):
            seq += 1
            sent += 1
            start = time.time()
            latency = self._ping_once(self.target_ip)
            timestamp = time.strftime("%H:%M:%S")

            if latency is not None:
                received += 1
                latencies.append(latency)
                status = "Success"
                res_dict = {
                    "seq": seq,
                    "ip": self.target_ip,
                    "latency": round(latency, 2),
                    "status": status,
                    "timestamp": timestamp
                }
            else:
                status = "Request Timed Out"
                res_dict = {
                    "seq": seq,
                    "ip": self.target_ip,
                    "latency": None,
                    "status": status,
                    "timestamp": timestamp
                }

            self.ping_result.emit(res_dict)

            # Compute running stats
            min_lat = min(latencies) if latencies else 0.0
            max_lat = max(latencies) if latencies else 0.0
            avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
            loss_pct = round(((sent - received) / sent) * 100, 1)

            stats = {
                "sent": sent,
                "received": received,
                "lost": sent - received,
                "loss_percent": loss_pct,
                "min": round(min_lat, 2),
                "max": round(max_lat, 2),
                "avg": round(avg_lat, 2)
            }
            self.ping_stats.emit(stats)

            # Wait interval before next ping
            if self.is_running and (self.count == 0 or seq < self.count):
                time.sleep(self.interval)

        self.ping_finished.emit()

    def _ping_once(self, ip: str) -> Optional[float]:
        """Perform single ping probe with stdout validation to prevent Windows ping false positives."""
        start = time.time()
        try:
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 0.5)
            out = (res.stdout or "").lower()

            if "bytes=" in out or "ttl=" in out:
                if "unreachable" not in out and "timed out" not in out and "failure" not in out and "could not find host" not in out:
                    match = re.search(r"time[=<]\s*(\d+)ms", out)
                    if match:
                        return float(match.group(1))
                    return max(0.5, (time.time() - start) * 1000)
        except Exception:
            pass

        # Fallback socket probe
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            t0 = time.time()
            ret = s.connect_ex((ip, 80))
            t1 = time.time()
            s.close()
            if ret == 0:
                return (t1 - t0) * 1000
        except Exception:
            pass

        return None
