import time
import psutil
from PyQt6.QtCore import QThread, pyqtSignal

class NetworkMonitorWorker(QThread):
    """
    Background worker that samples network I/O counters every second
    to compute upload/download speed (KB/s or MB/s), packet rates, and total traffic.
    """
    traffic_updated = pyqtSignal(dict)  # speed & packet metrics dictionary

    def __init__(self, sample_interval: float = 1.0):
        super().__init__()
        self.sample_interval = sample_interval
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        last_io = psutil.net_io_counters()
        last_time = time.time()

        while self.is_running:
            time.sleep(self.sample_interval)
            current_io = psutil.net_io_counters()
            current_time = time.time()

            time_delta = current_time - last_time
            if time_delta <= 0:
                time_delta = 1.0

            bytes_sent_delta = current_io.bytes_sent - last_io.bytes_sent
            bytes_recv_delta = current_io.bytes_recv - last_io.bytes_recv

            upload_speed_bps = bytes_sent_delta / time_delta
            download_speed_bps = bytes_recv_delta / time_delta

            packets_sent_delta = current_io.packets_sent - last_io.packets_sent
            packets_recv_delta = current_io.packets_recv - last_io.packets_recv

            total_bytes = current_io.bytes_sent + current_io.bytes_recv
            total_packets = current_io.packets_sent + current_io.packets_recv

            metrics = {
                "upload_speed_bytes": upload_speed_bps,
                "download_speed_bytes": download_speed_bps,
                "upload_speed_fmt": self._format_speed(upload_speed_bps),
                "download_speed_fmt": self._format_speed(download_speed_bps),
                "upload_packets_per_sec": int(packets_sent_delta / time_delta),
                "download_packets_per_sec": int(packets_recv_delta / time_delta),
                "total_bytes_sent": current_io.bytes_sent,
                "total_bytes_recv": current_io.bytes_recv,
                "total_traffic_fmt": self._format_size(total_bytes),
                "total_packets": total_packets,
                "timestamp": time.strftime("%H:%M:%S")
            }

            self.traffic_updated.emit(metrics)

            last_io = current_io
            last_time = current_time

    def _format_speed(self, bps: float) -> str:
        if bps >= 1024 * 1024:
            return f"{bps / (1024 * 1024):.2f} MB/s"
        elif bps >= 1024:
            return f"{bps / 1024:.1f} KB/s"
        else:
            return f"{int(bps)} B/s"

    def _format_size(self, num_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} PB"
