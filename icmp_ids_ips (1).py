#!/usr/bin/env python3
"""
Live ICMP IDS/IPS
------------------
Monitors ICMP traffic to a protected host in real time. The moment ANY
source IP crosses THRESHOLD pings, that IP is immediately blocked with
iptables and an alert is generated/sent — independently for every
attacking IP, not just the first one seen.

Requirements:
  - Linux host (uses iptables)
  - Run as root (needed for raw packet capture + iptables)
  - pip install scapy requests --break-system-packages

Usage:
  sudo python3 icmp_ids_ips.py
  (Ctrl+C to stop monitoring; see unblock_ips.py to remove blocks afterward)
"""

import os
import sys
import json
import uuid
import subprocess
import threading
from collections import defaultdict
from datetime import datetime, timezone

import requests
from scapy.all import sniff, IP, ICMP

# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

INTERFACE = "eth0"              # Change to your interface (check with: ip a)
THRESHOLD = 40                  # Pings allowed before instant block
DESTINATION_HOST = "Internal-server"
DESTINATION_IP = "192.168.0.206"  # Host being protected

ALERT_LOG_FILE = "alerts.json"           # Running log of every alert generated
BLOCKED_IPS_FILE = "blocked_ips.json"    # Running log of every blocked IP (for unblock_ips.py)

# ---- Airia Webhook ----
AIRIA_API_URL = "INSERT AIRIA API URL HERE"
AIRIA_API_KEY = "INSERT AIRIA API KEY HERE"

# ------------------------------------------------
# STATE
# ------------------------------------------------

ip_counts = defaultdict(int)     # per-source-IP packet counter
blocked_ips = set()              # IPs already blocked this run
lock = threading.Lock()          # protects shared state since sniff callback runs per-packet


# ------------------------------------------------
# IPTABLES BLOCKING
# ------------------------------------------------

def block_ip(ip: str) -> bool:
    """Insert a DROP rule for this source IP. Returns True if newly blocked."""
    with lock:
        if ip in blocked_ips:
            return False
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            blocked_ips.add(ip)
            _append_blocked_ip(ip)
            print(f"[BLOCKED] {ip} -> iptables DROP rule inserted")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to block {ip}: {e}")
            return False
        except FileNotFoundError:
            print("[ERROR] iptables not found. Are you on Linux with iptables installed?")
            return False


def _append_blocked_ip(ip: str):
    record = {"ip": ip, "blocked_at": datetime.now(timezone.utc).isoformat()}
    existing = []
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            existing = []
    existing.append(record)
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(existing, f, indent=2)


# ------------------------------------------------
# ALERTING
# ------------------------------------------------

def generate_alert(ip: str, count: int) -> dict:
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"
    alert = {
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "Suspicious Network Volume",
        "indicator_type": "ip",
        "indicator_value": ip,
        "source_host": ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "protocol": "ICMP",
        "evidence": {
            "packet_count": count,
            "threshold": THRESHOLD,
            "time_window_seconds": None  # continuous monitoring, not fixed-window
        },
        "action_taken": "blocked",
        "analyst_question": "Is this expected activity or suspicious scanning/noise?"
    }

    _append_alert(alert)
    return alert


def _append_alert(alert: dict):
    existing = []
    if os.path.exists(ALERT_LOG_FILE):
        try:
            with open(ALERT_LOG_FILE) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            existing = []
    existing.append(alert)
    with open(ALERT_LOG_FILE, "w") as f:
        json.dump(existing, f, indent=2)


def send_to_airia(alert: dict):
    if "INSERT AIRIA" in AIRIA_API_URL or "INSERT AIRIA" in AIRIA_API_KEY:
        print("[!] Airia URL/key not configured — skipping send, alert saved locally only.")
        return

    headers = {"Content-Type": "application/json", "X-API-KEY": AIRIA_API_KEY}
    payload = {"userInput": json.dumps(alert), "asyncOutput": False}

    try:
        response = requests.post(AIRIA_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        print(f"[+] Alert {alert['alert_id']} sent to Airia (status {response.status_code})")
    except requests.RequestException as e:
        print(f"[!] Failed to send alert {alert['alert_id']} to Airia: {e}")


# ------------------------------------------------
# PACKET HANDLER (fires per packet, in real time)
# ------------------------------------------------

def packet_callback(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return
    if pkt[IP].dst != DESTINATION_IP:
        return

    # Only count echo-requests (type 8) so reply traffic doesn't double count
    if pkt[ICMP].type != 8:
        return

    src = pkt[IP].src

    with lock:
        ip_counts[src] += 1
        count = ip_counts[src]

    print(f"[ICMP] {src} -> {DESTINATION_IP}  (count={count}/{THRESHOLD})")

    # Instant block the moment this specific IP crosses the threshold.
    # Each source IP is tracked independently, so a multi-machine attack
    # blocks EVERY offending IP, not just the first one detected.
    if count > THRESHOLD and src not in blocked_ips:
        print(f"[!] THRESHOLD EXCEEDED by {src} ({count} pings > {THRESHOLD}) — blocking now")
        newly_blocked = block_ip(src)
        if newly_blocked:
            alert = generate_alert(src, count)
            # Send on a background thread so a slow/unreachable Airia endpoint
            # never delays detection or blocking of OTHER attacking IPs that
            # arrive while this HTTP call is in flight.
            threading.Thread(target=send_to_airia, args=(alert,), daemon=True).start()


# ------------------------------------------------
# MAIN
# ------------------------------------------------

def main():
    if os.geteuid() != 0:
        print("[!] This script needs root privileges for packet capture and iptables.")
        print("    Run it with: sudo python3 icmp_ids_ips.py")
        sys.exit(1)

    print(f"[+] Live ICMP IDS/IPS starting on interface '{INTERFACE}'")
    print(f"[+] Protecting: {DESTINATION_HOST} ({DESTINATION_IP})")
    print(f"[+] Auto-block threshold: {THRESHOLD} ICMP echo-requests per source IP")
    print("[+] Press Ctrl+C to stop.\n")

    bpf_filter = f"icmp and dst host {DESTINATION_IP}"

    try:
        sniff(iface=INTERFACE, filter=bpf_filter, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"[!] Capture error (check INTERFACE name with 'ip a'): {e}")
        sys.exit(1)

    print("\n[+] Monitoring stopped.")
    if blocked_ips:
        print(f"[+] Blocked IPs this session ({len(blocked_ips)}):")
        for ip in sorted(blocked_ips):
            print(f"    - {ip}  ({ip_counts[ip]} pings)")
    else:
        print("[+] No IPs were blocked this session.")
    print(f"[+] Full alert history: {ALERT_LOG_FILE}")
    print(f"[+] Full block history: {BLOCKED_IPS_FILE}")


if __name__ == "__main__":
    main()
