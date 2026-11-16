"""Local monitoring and optional packet-probe detection services."""

import os
import threading
import time
from collections import defaultdict, deque

from .database import get_db, log_event, now
from .network import ping


def run_monitoring_cycle():
    """Ping every inventoried device and persist measurements and alerts."""
    db = get_db()
    devices = db.execute("SELECT * FROM devices").fetchall()
    timestamp = now()
    checked = 0
    for device in devices:
        result = ping(device["ip_address"])
        status = "Up" if result["reachable"] else "Down"
        db.execute(
            "INSERT INTO measurements (device_id, checked_at, reachable, latency_ms, packet_loss_pct) VALUES (?, ?, ?, ?, ?)",
            (device["id"], timestamp, int(result["reachable"]), result["latency_ms"], result["packet_loss_pct"]),
        )
        db.execute(
            "UPDATE devices SET status=?, last_seen=? WHERE id=?",
            (status, timestamp if result["reachable"] else device["last_seen"], device["id"]),
        )
        recent = db.execute(
            "SELECT reachable FROM measurements WHERE device_id=? ORDER BY id DESC LIMIT ?",
            (device["id"], int(__import__("flask").current_app.config["DOWN_FAILURE_THRESHOLD"])),
        ).fetchall()
        if len(recent) == int(__import__("flask").current_app.config["DOWN_FAILURE_THRESHOLD"]) and not any(row["reachable"] for row in recent):
            _create_alert_once(db, device["id"], "high", "Device outage", f"{device['ip_address']} failed {len(recent)} consecutive monitoring checks.")
        elif result["latency_ms"] is not None and result["latency_ms"] > __import__("flask").current_app.config["HIGH_LATENCY_THRESHOLD_MS"]:
            _create_alert_once(db, device["id"], "medium", "High latency", f"{device['ip_address']} latency was {result['latency_ms']} ms (threshold: {__import__('flask').current_app.config['HIGH_LATENCY_THRESHOLD_MS']} ms).")
        elif result["packet_loss_pct"] >= __import__("flask").current_app.config["PACKET_LOSS_THRESHOLD_PCT"]:
            _create_alert_once(db, device["id"], "medium", "Packet loss", f"{device['ip_address']} packet loss was {result['packet_loss_pct']}% (threshold: {__import__('flask').current_app.config['PACKET_LOSS_THRESHOLD_PCT']}%).")
        checked += 1
    db.commit()
    if checked:
        log_event("Monitoring", f"Monitoring cycle completed for {checked} device(s).")
    return checked


def _create_alert_once(db, device_id, severity, rule_name, message):
    active = db.execute("SELECT id FROM alerts WHERE device_id=? AND rule_name=? AND acknowledged=0", (device_id, rule_name)).fetchone()
    if not active:
        db.execute("INSERT INTO alerts (device_id, created_at, severity, rule_name, message) VALUES (?, ?, ?, ?, ?)", (device_id, now(), severity, rule_name, message))


class MonitorScheduler:
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="netwatch-monitor", daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        # Wait one interval before the first automatic cycle; manual monitoring remains immediate.
        while not self.stop_event.wait(self.app.config["MONITOR_INTERVAL_SECONDS"]):
            with self.app.app_context():
                try:
                    run_monitoring_cycle()
                except Exception as error:  # keep the dashboard usable if a host command fails
                    log_event("Monitoring error", f"Automatic monitoring could not complete: {error}")


def start_monitoring(app):
    if app.extensions.get("netwatch_monitor") is None:
        scheduler = MonitorScheduler(app)
        app.extensions["netwatch_monitor"] = scheduler
        scheduler.start()


class PacketProbeDetector:
    """Detect many distinct TCP SYN ports from one source within a time window."""
    def __init__(self, app, port_threshold=10, window_seconds=60):
        self.app = app
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self.stop_event = threading.Event()
        self.thread = None
        self.observations = defaultdict(deque)
        self.fired_sources = set()
        self.error = None

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        if self.running:
            return
        self.stop_event.clear()
        self.error = None
        self.thread = threading.Thread(target=self._run, name="netwatch-packet-capture", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _run(self):
        try:
            from scapy.all import IP, TCP, sniff
        except ImportError:
            self.error = "Scapy is not installed. Run: pip install -r requirements.txt"
            return

        def process(packet):
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return
            tcp = packet[TCP]
            # New TCP connection attempt: SYN set, ACK not set.
            if not (int(tcp.flags) & 0x02) or (int(tcp.flags) & 0x10):
                return
            source = packet[IP].src
            current_time = time.monotonic()
            entries = self.observations[source]
            entries.append((current_time, int(tcp.dport)))
            while entries and entries[0][0] < current_time - self.window_seconds:
                entries.popleft()
            ports = {port for _, port in entries}
            if len(ports) >= self.port_threshold and source not in self.fired_sources:
                self.fired_sources.add(source)
                with self.app.app_context():
                    db = get_db()
                    device = db.execute("SELECT id FROM devices WHERE ip_address=?", (source,)).fetchone()
                    db.execute("INSERT INTO alerts (device_id, created_at, severity, rule_name, message) VALUES (?, ?, 'high', 'Port-probing pattern', ?)",
                               (device["id"] if device else None, now(), f"{source} attempted {len(ports)} distinct TCP ports within {self.window_seconds} seconds."))
                    db.commit()
                    log_event("Packet detection", f"Port-probing alert created for source {source}.")

        try:
            while not self.stop_event.is_set():
                sniff(filter="tcp", prn=process, store=False, timeout=1)
        except Exception as error:
            self.error = f"Packet capture failed: {error}"


def packet_detector(app):
    detector = app.extensions.get("packet_detector")
    if detector is None:
        detector = PacketProbeDetector(app)
        app.extensions["packet_detector"] = detector
    return detector
