# NetWatch

NetWatch is a local Flask prototype for monitoring networks you own or are explicitly authorised to assess.

## Features

- Authorisation-gated device discovery using Nmap
- Device inventory with automatic periodic ICMP reachability, latency, and packet-loss checks
- Optional TCP port/service scans for a selected device
- SQLite-backed monitoring history, alerts, and event log
- Dashboard charts and CSV export
- Optional Scapy-based port-probing alerts (requires Npcap and administrator access on Windows)

## Run locally (Windows)

1. Install Python 3.10+ and [Nmap](https://nmap.org/download.html).
2. From this directory, create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Start the application:

   ```powershell
   python run.py
   ```

4. Visit `http://127.0.0.1:5000`.

The app deliberately requires the authorisation checkbox for discovery and port scans. Start with `127.0.0.1` or a lab subnet you control.66

For packet-probe detection on Windows, install [Npcap](https://npcap.com/) and run the terminal as Administrator. This feature observes only local traffic visible to your machine; use it solely on an authorised network.
python run.py