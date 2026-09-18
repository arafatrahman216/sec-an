"""
Shared helpers for the attacker-side scripts (Design Report Section 4, Phases 2-5).

Every attacker script imports require_lab_targets() first and refuses to run
against anything outside the course's isolated lab segment. This is a hard
safety guard, not a suggestion -- do not remove it or widen the allowed range.
"""

import ipaddress
import logging
import subprocess
import sys
import time

# The isolated host-only/internal-network segment for this lab
# (Design Report Section 2.1: client .10, server .20, attacker .30).
LAB_NETWORK = ipaddress.ip_network("192.168.56.0/24")

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def setup_logging(name):
    """Console logger with timestamps, so log lines line up against Wireshark's
    capture-time column when correlating evidence."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(name)s: %(message)s", "%H:%M:%S")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


_log = setup_logging("common")


def require_lab_targets(*ip_addresses):
    """Abort immediately if any target IP falls outside the lab's /24.

    This is the guard called out in the design report's non-functional
    requirements: it stops these scripts from ever being pointed at a real,
    non-lab network, by accident or otherwise.
    """
    for ip in ip_addresses:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            sys.exit(f"[SAFETY] '{ip}' is not a valid IPv4 address. Aborting.")
        if addr not in LAB_NETWORK:
            sys.exit(
                f"[SAFETY] {ip} is outside the lab network {LAB_NETWORK}. "
                "This tool only runs against the isolated course lab segment. Aborting."
            )
    _log.info("Safety check passed: all targets inside %s", LAB_NETWORK)


def get_mac(ip_address, iface=None, timeout=3):
    """Resolve a lab-segment IP's real MAC address with a genuine ARP request.

    Used before poisoning starts so arp_spoof.py can later restore the
    correct Sender MAC/IP mapping (Section 3.2) on exit.
    """
    from scapy.all import ARP, Ether, srp

    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    kwargs = {"timeout": timeout, "verbose": False}
    if iface:
        kwargs["iface"] = iface

    answered, _ = srp(packet, **kwargs)
    if not answered:
        sys.exit(f"[ERROR] No ARP reply from {ip_address}; is it up and reachable?")
    return answered[0][1].hwsrc


def set_ip_forwarding(enabled):
    """Toggle IPv4 forwarding on the attacker VM.

    Required so client<->server traffic keeps flowing once ARP tables are
    poisoned (Design Report Section 2.2: 'the victim notices nothing while
    the attacker reads it'); disabling it again on exit stops silently
    black-holing traffic after the demo ends.
    """
    value = "1" if enabled else "0"
    try:
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.ip_forward={value}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            with open(IP_FORWARD_PATH, "w") as f:
                f.write(value)
        except OSError as exc:
            _log.warning("Could not set IP forwarding=%s: %s", value, exc)
            return
    _log.info("IP forwarding %s", "ENABLED" if enabled else "disabled")


def get_ip_forwarding():
    try:
        with open(IP_FORWARD_PATH) as f:
            return f.read().strip() == "1"
    except OSError:
        return None


class RateLimiter:
    """Small helper so poisoning loops can sleep a fixed interval without
    every script re-implementing the same time.sleep() bookkeeping."""

    def __init__(self, interval_seconds):
        self.interval_seconds = interval_seconds

    def wait(self):
        time.sleep(self.interval_seconds)
