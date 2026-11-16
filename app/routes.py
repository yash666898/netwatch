import csv
import io
import json
from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for

from .database import get_db, log_event, now
from .monitoring import packet_detector, run_monitoring_cycle
from .network import NetworkToolError, discover, ping, port_scan, subnet_from_router

web = Blueprint("web", __name__)


def require_authorization():
    if request.form.get("authorized") != "yes":
        raise NetworkToolError("Confirm that you own the target network or have explicit permission before running this action.")


@web.get("/")
def dashboard():
    db = get_db()
    devices = db.execute("""SELECT d.*, m.checked_at AS checked_at, m.latency_ms AS latency_ms,
                                  m.packet_loss_pct AS packet_loss_pct, m.reachable AS last_reachable
                           FROM devices d
                           LEFT JOIN measurements m ON m.id = (
                               SELECT id FROM measurements WHERE device_id = d.id ORDER BY id DESC LIMIT 1
                           )
                           ORDER BY d.ip_address""").fetchall()
    alerts = db.execute("SELECT alerts.*, devices.ip_address FROM alerts LEFT JOIN devices ON devices.id = alerts.device_id WHERE acknowledged = 0 ORDER BY created_at DESC LIMIT 6").fetchall()
    events = db.execute("SELECT * FROM events ORDER BY created_at DESC LIMIT 8").fetchall()
    summary = {
        "total": len(devices),
        "up": sum(device["status"] == "Up" for device in devices),
        "down": sum(device["status"] == "Down" for device in devices),
        "alerts": len(alerts),
    }
    detector = packet_detector(__import__("flask").current_app)
    return render_template("dashboard.html", devices=devices, alerts=alerts, events=events, summary=summary, detector=detector)


@web.post("/discover")
def run_discovery():
    try:
        require_authorization()
        router_ip = request.form.get("router_ip", "").strip()
        target = request.form.get("target", "").strip()
        if router_ip:
            target = subnet_from_router(router_ip, request.form.get("prefix_length", "24"))
        hosts = discover(target)
        db = get_db()
        timestamp = now()
        for host in hosts:
            db.execute("""INSERT INTO devices (ip_address, hostname, mac_address, status, last_seen, created_at)
                VALUES (?, ?, ?, 'Up', ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET hostname=excluded.hostname, mac_address=COALESCE(excluded.mac_address, devices.mac_address), status='Up', last_seen=excluded.last_seen""",
                (host["ip_address"], host["hostname"], host["mac_address"], timestamp, timestamp))
        db.commit()
        log_event("Discovery", f"Discovery completed for {target}: {len(hosts)} active host(s) found.")
        flash(f"Discovery complete: {len(hosts)} active host(s) added or updated.", "success")
    except NetworkToolError as error:
        flash(str(error), "danger")
    return redirect(url_for("web.dashboard"))


@web.get("/api/dashboard")
def dashboard_status():
    rows = get_db().execute("""SELECT d.id, d.status, d.last_seen, m.checked_at, m.latency_ms,
                                      m.packet_loss_pct, m.reachable
                               FROM devices d
                               LEFT JOIN measurements m ON m.id = (
                                   SELECT id FROM measurements WHERE device_id = d.id ORDER BY id DESC LIMIT 1
                               )""").fetchall()
    return jsonify({str(row["id"]): {
        "status": row["status"], "last_seen": row["last_seen"], "checked_at": row["checked_at"],
        "latency_ms": row["latency_ms"], "packet_loss_pct": row["packet_loss_pct"],
        "reachable": bool(row["reachable"]) if row["reachable"] is not None else None,
    } for row in rows})


@web.post("/monitor")
def monitor_all():
    checked = run_monitoring_cycle()
    flash(f"Monitoring cycle completed for {checked} device(s).", "success")
    return redirect(url_for("web.dashboard"))


@web.post("/inventory/clear")
def clear_inventory():
    """Archive the current workspace, then clear it for the next network."""
    db = get_db()
    devices = db.execute("SELECT * FROM devices ORDER BY ip_address").fetchall()
    device_count = len(devices)
    if device_count:
        archive = {
            "devices": [dict(row) for row in devices],
            "measurements": [dict(row) for row in db.execute("SELECT * FROM measurements ORDER BY checked_at").fetchall()],
            "port_scans": [dict(row) for row in db.execute("SELECT * FROM port_scans ORDER BY scanned_at, port").fetchall()],
            "alerts": [dict(row) for row in db.execute("SELECT * FROM alerts ORDER BY created_at").fetchall()],
        }
        archive_name = f"Network snapshot - {now()}"
        db.execute(
            "INSERT INTO inventory_archives (name, created_at, device_count, contents_json) VALUES (?, ?, ?, ?)",
            (archive_name, now(), device_count, json.dumps(archive)),
        )
    db.execute("DELETE FROM port_scans")
    db.execute("DELETE FROM measurements")
    db.execute("DELETE FROM alerts")
    db.execute("DELETE FROM devices")
    db.commit()
    log_event("Inventory archived", f"Saved and cleared {device_count} device(s) and their associated records.")
    flash(f"Saved {device_count} device(s) to Saved scans and cleared this workspace for a new network.", "success")
    return redirect(url_for("web.dashboard"))


@web.get("/saved-scans")
def saved_scans():
    archives = get_db().execute("SELECT id, name, created_at, device_count FROM inventory_archives ORDER BY id DESC").fetchall()
    return render_template("saved_scans.html", archives=archives)


@web.get("/saved-scans/<int:archive_id>")
def saved_scan_detail(archive_id):
    archive = get_db().execute("SELECT * FROM inventory_archives WHERE id=?", (archive_id,)).fetchone()
    if archive is None:
        flash("Saved scan not found.", "danger")
        return redirect(url_for("web.saved_scans"))
    contents = json.loads(archive["contents_json"])
    measurements_by_device = {}
    for measurement in contents["measurements"]:
        measurements_by_device.setdefault(measurement["device_id"], []).append(measurement)
    latest_measurements = {
        device_id: sorted(items, key=lambda item: item["checked_at"])[-1]
        for device_id, items in measurements_by_device.items()
    }
    return render_template("saved_scan_detail.html", archive=archive, contents=contents, latest_measurements=latest_measurements)


@web.post("/packet-capture/start")
def start_packet_capture():
    try:
        require_authorization()
        detector = packet_detector(__import__("flask").current_app)
        detector.start()
        log_event("Packet detection", "Optional packet-probe detection was started.")
        flash("Packet-probe detection started. On Windows, Npcap and administrator permission may be required.", "success")
    except NetworkToolError as error:
        flash(str(error), "danger")
    return redirect(url_for("web.dashboard"))


@web.post("/packet-capture/stop")
def stop_packet_capture():
    detector = packet_detector(__import__("flask").current_app)
    detector.stop()
    log_event("Packet detection", "Optional packet-probe detection was stopped.")
    flash("Packet-probe detection stopped.", "secondary")
    return redirect(url_for("web.dashboard"))


@web.post("/devices/<int:device_id>/scan")
def scan_device(device_id):
    try:
        require_authorization()
        db = get_db()
        device = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if device is None:
            flash("Device not found.", "danger")
            return redirect(url_for("web.dashboard"))
        ports = port_scan(device["ip_address"])
        timestamp = now()
        db.execute("DELETE FROM port_scans WHERE device_id=?", (device_id,))
        db.executemany("INSERT INTO port_scans (device_id, scanned_at, port, protocol, state, service) VALUES (?, ?, ?, ?, ?, ?)",
                       [(device_id, timestamp, p["port"], p["protocol"], p["state"], p["service"]) for p in ports])
        db.commit()
        log_event("Port scan", f"Port scan completed for {device['ip_address']}: {len(ports)} open port(s).")
        flash(f"Scan complete: {len(ports)} open port(s) found on {device['ip_address']}.", "success")
    except NetworkToolError as error:
        flash(str(error), "danger")
    return redirect(url_for("web.device_detail", device_id=device_id))


@web.get("/devices/<int:device_id>")
def device_detail(device_id):
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if device is None:
        return redirect(url_for("web.dashboard"))
    scans = db.execute("SELECT * FROM port_scans WHERE device_id=? ORDER BY port", (device_id,)).fetchall()
    measurements = db.execute("SELECT * FROM measurements WHERE device_id=? ORDER BY checked_at DESC LIMIT 30", (device_id,)).fetchall()
    return render_template("device.html", device=device, scans=scans, measurements=measurements)


@web.get("/api/devices/<int:device_id>/history")
def history(device_id):
    rows = get_db().execute("SELECT checked_at, latency_ms, reachable FROM measurements WHERE device_id=? ORDER BY checked_at ASC LIMIT 100", (device_id,)).fetchall()
    return jsonify([{ "checked_at": row["checked_at"], "latency_ms": row["latency_ms"], "reachable": bool(row["reachable"]) } for row in rows])


@web.post("/alerts/<int:alert_id>/acknowledge")
def acknowledge_alert(alert_id):
    db = get_db()
    db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    db.commit()
    return redirect(url_for("web.dashboard"))


@web.get("/export.csv")
def export_csv():
    db = get_db()
    rows = db.execute("""SELECT d.ip_address, d.hostname, d.status, m.checked_at, m.reachable, m.latency_ms, m.packet_loss_pct
                         FROM devices d LEFT JOIN measurements m ON m.device_id=d.id ORDER BY d.ip_address, m.checked_at DESC""").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP address", "Hostname", "Current status", "Checked at", "Reachable", "Latency (ms)", "Packet loss (%)"])
    writer.writerows([[row["ip_address"], row["hostname"] or "", row["status"], row["checked_at"] or "", row["reachable"] if row["reachable"] is not None else "", row["latency_ms"] or "", row["packet_loss_pct"] or ""] for row in rows])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=netwatch-report.csv"})
