import re
import socket
import subprocess
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional
from PyQt6.QtCore import QThread, pyqtSignal

from core.oui_lookup import lookup_vendor, guess_device_type

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class HostDiscoveryWorker(QThread):
    """
    Background thread that scans the subnet using ARP (if Scapy is available & privileged)
    or concurrent ICMP / Socket ping probes as graceful fallback.
    """
    scan_progress = pyqtSignal(int, str)           # percentage, status message
    device_discovered = pyqtSignal(dict)           # individual device dictionary
    scan_completed = pyqtSignal(list, float)        # list of devices, total scan duration seconds
    scan_failed = pyqtSignal(str)                  # error string

    def __init__(self, network_range: str, local_ip: str, local_mac: str, timeout: float = 1.5, max_threads: int = 50):
        super().__init__()
        self.network_range = network_range
        self.local_ip = local_ip
        self.local_mac = local_mac
        self.timeout = timeout
        self.max_threads = max_threads
        self.is_cancelled = False

    def cancel(self):
        self.is_cancelled = True

    def run(self):
        start_time = time.time()
        discovered_devices = []

        try:
            net = ipaddress.IPv4Network(self.network_range, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            total_hosts = len(hosts)

            if total_hosts == 0:
                hosts = [self.local_ip]
                total_hosts = 1

            self.scan_progress.emit(5, f"Starting discovery on {self.network_range} ({total_hosts} hosts)...")

            # Try Scapy ARP scan first
            scapy_success = False
            if SCAPY_AVAILABLE:
                try:
                    self.scan_progress.emit(10, "Attempting ARP hardware discovery...")
                    scapy_results = self._scapy_arp_scan(hosts)
                    if scapy_results:
                        discovered_devices.extend(scapy_results)
                        scapy_success = True
                except Exception as e:
                    print(f"Scapy scan failed/unprivileged: {e}")

            # Fallback to ICMP ping / Socket probing if Scapy wasn't available or yielded 0 hosts
            if not scapy_success and not self.is_cancelled:
                self.scan_progress.emit(15, "Performing multi-threaded ICMP/Socket host discovery...")
                discovered_devices = self._socket_ping_scan(hosts)

            # Ensure local machine is in results
            has_local = any(d["ip"] == self.local_ip for d in discovered_devices)
            if not has_local and not self.is_cancelled:
                local_dev = {
                    "ip": self.local_ip,
                    "mac": self.local_mac,
                    "hostname": self._resolve_hostname(self.local_ip),
                    "vendor": lookup_vendor(self.local_mac),
                    "latency": 0.1,
                    "status": "Online",
                }
                local_dev["device_type"] = guess_device_type(local_dev["vendor"], local_dev["hostname"])
                local_dev["os_guess"] = "Local Host OS"
                discovered_devices.append(local_dev)
                self.device_discovered.emit(local_dev)

            elapsed = round(time.time() - start_time, 2)
            self.scan_progress.emit(100, f"Scan finished in {elapsed}s. Discovered {len(discovered_devices)} active devices.")
            self.scan_completed.emit(discovered_devices, elapsed)

        except Exception as e:
            self.scan_failed.emit(str(e))

    def _scapy_arp_scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
        devices = []
        try:
            arp = ARP(pdst=self.network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=self.timeout, verbose=0)[0]

            for sent, received in result:
                if self.is_cancelled:
                    break
                ip = received.psrc
                mac = received.hwsrc.upper()
                hostname = self._resolve_hostname(ip)
                vendor = lookup_vendor(mac)
                dev_type = guess_device_type(vendor, hostname)

                dev_info = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": dev_type,
                    "os_guess": "Unknown",
                    "latency": round((received.time - sent.sent_time) * 1000, 2),
                    "status": "Online",
                }
                devices.append(dev_info)
                self.device_discovered.emit(dev_info)

        except Exception as e:
            print(f"Scapy ARP scan exception: {e}")
        return devices

    def _socket_ping_scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
        devices = []
        total = len(hosts)
        processed = 0

        def check_host(ip):
            if self.is_cancelled:
                return None
            latency = self._ping_host(ip)
            if latency is not None:
                mac = self._get_mac_from_arp(ip) if ip != self.local_ip else self.local_mac
                hostname = self._resolve_hostname(ip)
                vendor = lookup_vendor(mac)
                dev_type = guess_device_type(vendor, hostname)
                return {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": dev_type,
                    "os_guess": "Unknown",
                    "latency": round(latency, 2),
                    "status": "Online",
                }
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {executor.submit(check_host, ip): ip for ip in hosts}
            for future in as_completed(future_to_ip):
                if self.is_cancelled:
                    break
                processed += 1
                progress = int(15 + (processed / total) * 80)
                self.scan_progress.emit(progress, f"Scanning {processed}/{total} hosts...")

                res = future.result()
                if res:
                    devices.append(res)
                    self.device_discovered.emit(res)

        return devices

    def _ping_host(self, ip: str) -> Optional[float]:
        """
        Accurate Ping probe parser for Windows/Linux/macOS.
        Fixes Windows ping glitch where Destination Host Unreachable returned exit code 0.
        """
        start = time.time()
        try:
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 0.5)
            out = (res.stdout or "").lower()

            # Must contain active reply and NOT contain unreachable/timed out indicators
            if "bytes=" in out or "ttl=" in out:
                if "unreachable" not in out and "timed out" not in out and "failure" not in out and "could not find host" not in out:
                    match = re.search(r"time[=<]\s*(\d+)ms", out)
                    if match:
                        return float(match.group(1))
                    return max(0.5, (time.time() - start) * 1000)
        except Exception:
            pass

        # Precise Socket probe fallback (only count true open connections)
        for port in [80, 443, 445, 135, 22]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                start_s = time.time()
                ret = s.connect_ex((ip, port))
                s.close()
                if ret == 0:
                    return (time.time() - start_s) * 1000
            except Exception:
                pass
        return None

    def _get_mac_from_arp(self, ip: str) -> str:
        """Query local ARP table for MAC address on Windows/Linux."""
        try:
            output = subprocess.check_output(f"arp -a {ip}", shell=True, text=True)
            for line in output.splitlines():
                if ip in line and "invalid" not in line.lower() and "unreachable" not in line.lower():
                    parts = line.split()
                    for p in parts:
                        clean_p = p.replace("-", ":").upper()
                        if len(clean_p) == 17 and clean_p.count(":") == 5:
                            return clean_p
        except Exception:
            pass
        return f"SYN-{ip}"

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return f"host-{ip.split('.')[-1]}"
