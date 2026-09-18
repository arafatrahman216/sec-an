#!/usr/bin/env python3
"""
Phase 5 - Evidence Collection (Design Report Section 4 / Section 5).

Thin start/stop wrapper around tcpdump so the baseline (normal session) and
attack (ARP poison + hijack) traffic get saved to separate .pcap files for
the report's screenshots (poisoned ARP tables, accepted injected segment,
unauthorized HTTP response all come from opening these in Wireshark).

Run on the ATTACKER VM (192.168.56.30):
    python3 attacker/capture.py start --name baseline --iface eth1 \
        --hosts 192.168.56.10 192.168.56.20
    ... perform the normal login + telnet session ...
    python3 attacker/capture.py stop --name baseline

    python3 attacker/capture.py start --name attack --iface eth1 \
        --hosts 192.168.56.10 192.168.56.20
    ... run arp_spoof.py, tcp_hijack.py, cookie_replay.py ...
    python3 attacker/capture.py stop --name attack
"""

import argparse
import os
import signal
import subprocess
import sys
import time

from common import require_lab_targets, setup_logging

log = setup_logging("capture")

CAPTURE_DIR = "captures"


def pidfile_path(name):
    return os.path.join(CAPTURE_DIR, f"{name}.pid")


def pcap_path(name):
    return os.path.join(CAPTURE_DIR, f"{name}.pcap")


def cmd_start(args):
    os.makedirs(CAPTURE_DIR, exist_ok=True)

    if args.hosts:
        require_lab_targets(*args.hosts)
        host_filter = " or ".join(f"host {h}" for h in args.hosts)
        bpf_filter = f"({host_filter})"
    else:
        bpf_filter = args.filter or ""

    if os.path.exists(pidfile_path(args.name)):
        sys.exit(f"[ERROR] Capture '{args.name}' already running (found {pidfile_path(args.name)}).")

    pcap = pcap_path(args.name)
    tcpdump_cmd = ["tcpdump", "-i", args.iface, "-s", "0", "-w", pcap]
    if bpf_filter:
        tcpdump_cmd.append(bpf_filter)

    log_path = os.path.join(CAPTURE_DIR, f"{args.name}.log")
    with open(log_path, "wb") as logfile:
        proc = subprocess.Popen(tcpdump_cmd, stdout=logfile, stderr=logfile)

    time.sleep(0.5)
    if proc.poll() is not None:
        sys.exit(f"[ERROR] tcpdump exited immediately (see {log_path}). Are you root?")

    with open(pidfile_path(args.name), "w") as f:
        f.write(str(proc.pid))

    log.info("Capture '%s' started (pid %d) -> %s", args.name, proc.pid, pcap)
    if bpf_filter:
        log.info("Filter: %s", bpf_filter)


def cmd_stop(args):
    pf = pidfile_path(args.name)
    if not os.path.exists(pf):
        sys.exit(f"[ERROR] No running capture named '{args.name}' (missing {pf}).")

    with open(pf) as f:
        pid = int(f.read().strip())

    try:
        os.kill(pid, signal.SIGTERM)
        log.info("Sent SIGTERM to tcpdump (pid %d)", pid)
    except ProcessLookupError:
        log.warning("Process %d was already gone", pid)

    time.sleep(0.5)
    os.remove(pf)

    pcap = pcap_path(args.name)
    if os.path.exists(pcap):
        size = os.path.getsize(pcap)
        log.info("Capture '%s' stopped -> %s (%d bytes)", args.name, pcap, size)
    else:
        log.warning("Expected pcap %s not found", pcap)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    start_p = sub.add_parser("start", help="start a tcpdump capture")
    start_p.add_argument("--name", required=True, help="e.g. baseline or attack")
    start_p.add_argument("--iface", required=True)
    start_p.add_argument("--hosts", nargs="*", help="restrict capture to these lab IPs")
    start_p.add_argument("--filter", help="raw BPF filter, used only if --hosts is omitted")
    start_p.set_defaults(func=cmd_start)

    stop_p = sub.add_parser("stop", help="stop a running capture")
    stop_p.add_argument("--name", required=True)
    stop_p.set_defaults(func=cmd_stop)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
