import os
import platform
import re
import shutil
import socket
import subprocess
from ipaddress import ip_address, ip_network


class NetworkToolError(RuntimeError):
    pass


def validate_target(target):
    try:
        return str(ip_network(target, strict=False))
    except ValueError as error:
        raise NetworkToolError("Enter a valid IP address or CIDR subnet, such as 192.168.1.0/24.") from error


def subnet_from_router(router_ip, prefix_length):
    """Derive the local network to scan from an authorised router address."""
    try:
        address = ip_address(router_ip)
        prefix_length = int(prefix_length)
        if address.version != 4 or not 8 <= prefix_length <= 30:
            raise ValueError
        return str(ip_network(f"{address}/{prefix_length}", strict=False))
    except ValueError as error:
        raise NetworkToolError("Enter a valid IPv4 router address and choose a network size between /8 and /30.") from error


def require_nmap():
    """Return Nmap's executable, including common Windows install locations.

    A desktop-launched Python process can retain an older PATH after Nmap is
    installed. Checking the official default folders keeps the app usable in
    that situation without requiring a system restart.
    """
    executable = shutil.which("nmap")
    if executable:
        return executable

    if platform.system().lower() == "windows":
        candidates = (
            r"C:\\Program Files\\Nmap\\nmap.exe",
            r"C:\\Program Files (x86)\\Nmap\\nmap.exe",
        )
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate

    raise NetworkToolError("Nmap was not found. Install it and ensure its folder is in PATH, then restart the app.")


def run_command(command, timeout=120):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise NetworkToolError("The network command timed out.") from error
    except OSError as error:
        raise NetworkToolError(f"Unable to start the network command: {error}") from error


def discover(target):
    target = validate_target(target)
    nmap = require_nmap()
    # -R asks Nmap to resolve hostnames where DNS or the local network permits it.
    result = run_command([nmap, "-sn", "-R", "-oG", "-", target])
    if result.returncode not in (0, 1):
        raise NetworkToolError(result.stderr.strip() or "Nmap discovery failed.")
    hosts = []
    for line in result.stdout.splitlines():
        if not line.startswith("Host:") or "Status: Up" not in line:
            continue
        match = re.match(r"Host:\s+(\S+)\s*(?:\(([^)]*)\))?", line)
        if not match:
            continue
        mac = re.search(r"MAC:\s+([0-9A-F:]+)", line, re.I)
        hostname = (match.group(2) or "").strip() or None
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(match.group(1))[0]
            except (socket.herror, socket.gaierror, OSError):
                pass
        hosts.append({"ip_address": match.group(1), "hostname": hostname, "mac_address": mac.group(1) if mac else None})
    return hosts


def ping(ip_address):
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    result = run_command(["ping", flag, "3", ip_address], timeout=20)
    output = (result.stdout or "") + (result.stderr or "")
    latency = re.search(r"(?:Average =|avg =).*?(\d+(?:\.\d+)?)\s*ms", output, re.I)
    if not latency:
        latency = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", output, re.I)
    loss = re.search(r"(?:\((\d+)%\s*loss\)|([0-9.]+)%\s*packet loss)", output, re.I)
    loss_pct = float(next((part for part in loss.groups() if part is not None), 100)) if loss else (0 if result.returncode == 0 else 100)
    return {"reachable": result.returncode == 0, "latency_ms": float(latency.group(1)) if latency else None, "packet_loss_pct": loss_pct}


def port_scan(ip_address):
    nmap = require_nmap()
    result = run_command([nmap, "-sT", "-sV", "--top-ports", "100", "-oG", "-", ip_address])
    if result.returncode not in (0, 1):
        raise NetworkToolError(result.stderr.strip() or "Nmap port scan failed.")
    ports = []
    for line in result.stdout.splitlines():
        if "Ports:" not in line:
            continue
        for item in line.split("Ports:", 1)[1].split(","):
            fields = item.strip().split("/")
            if len(fields) >= 5 and fields[1] == "open":
                ports.append({"port": int(fields[0]), "state": fields[1], "protocol": fields[2], "service": fields[4] or "unknown"})
    return ports
