#!/usr/bin/env python3
"""
Manage IPs blocked by icmp_ids_ips.py

Usage:
  sudo python3 unblock_ips.py --list             # show currently blocked IPs
  sudo python3 unblock_ips.py --unblock 1.2.3.4  # remove block for one IP
  sudo python3 unblock_ips.py --unblock-all       # remove all blocks logged
"""

import argparse
import json
import os
import subprocess
import sys

BLOCKED_IPS_FILE = "blocked_ips.json"


def load_blocked():
    if not os.path.exists(BLOCKED_IPS_FILE):
        return []
    with open(BLOCKED_IPS_FILE) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def list_blocked():
    records = load_blocked()
    if not records:
        print("[+] No blocked IPs on record.")
        return
    print(f"[+] {len(records)} block record(s):")
    for r in records:
        print(f"    {r['ip']}  (blocked at {r['blocked_at']})")


def unblock_ip(ip: str):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[+] Unblocked {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Could not unblock {ip} (rule may not exist): {e}")


def unblock_all():
    records = load_blocked()
    seen = set()
    for r in records:
        ip = r["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        unblock_ip(ip)
    print(f"[+] Done. Attempted to unblock {len(seen)} unique IP(s).")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Run with sudo (iptables requires root).")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true")
    group.add_argument("--unblock", metavar="IP")
    group.add_argument("--unblock-all", action="store_true")
    args = parser.parse_args()

    if args.list:
        list_blocked()
    elif args.unblock:
        unblock_ip(args.unblock)
    elif args.unblock_all:
        unblock_all()
