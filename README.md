# HTTP / TCP Session Hijacking via ARP Spoofing

CSE 406 — Sessional (Cybersecurity), BUET
Team: Samiul Hasan Nihal (2105105), Arnab Sarker (2105099)

Implementation of the approved design report
`HTTP_TCP_Session_Hijacking_Design_Report.docx`. Runs **only** inside an
isolated 3-VM lab network the team controls — never against a network you
don't own. Every attacker script hard-refuses to run against any IP outside
`192.168.56.0/24` (see `attacker/common.py::require_lab_targets`).

## Lab topology (Design Report Section 2.1)

| Host             | IP              | Role |
|------------------|-----------------|------|
| Client (victim)  | 192.168.56.10   | Logs into the web app over HTTP; opens a telnet session |
| Server           | 192.168.56.20   | Runs `server/app.py` (HTTP login) and `server/telnet_service.py` |
| Attacker         | 192.168.56.30   | Runs everything under `attacker/` |

All three VMs sit on one VirtualBox/VMware **internal or host-only network**
(a real Layer-2 switch works too) — a shared segment is what makes ARP
spoofing meaningful.

## Repo layout

```
server/
  app.py               Phase 1 — plaintext HTTP login app (cookie session)
  telnet_service.py     Phase 1 — unauthenticated plaintext TCP service
attacker/
  common.py             shared safety guard, MAC resolution, IP forwarding toggle
  arp_spoof.py           Phase 2 — MITM positioning
  tcp_hijack.py          Phase 3 — TCP session hijack (supports --trials, logs CSV)
  cookie_replay.py       Phase 4 — HTTP session hijack (supports --trials, logs CSV)
  capture.py             Phase 5 — tcpdump start/stop helper
  plot_results.py        Phase 5 — renders results/*.csv into plots/*.png
requirements.txt
```

`results/` (CSV evidence), `plots/` (PNG charts), and `captures/` (pcaps)
are all generated at run time and gitignored — see [RUN.md](RUN.md).

## Phase 1 — Lab setup

On the **attacker VM**, confirm the toolchain:

```bash
sudo apt install -y tcpdump wireshark python3-pip
pip3 install -r requirements.txt      # scapy, flask, requests
```

- `arp_spoof.py` toggles `/proc/sys/net/ipv4/ip_forward` itself (via `sysctl`
  or a direct write) — no manual step needed, but you can check it with
  `cat /proc/sys/net/ipv4/ip_forward`.
- Wireshark/tcpdump must be run as root (or with capture capabilities) to
  sniff on the interface.

On the **server VM**:

```bash
pip3 install flask
python3 server/app.py --port 8080                 # HTTP login app (no root needed above port 1024)
python3 server/telnet_service.py --port 2323       # plaintext TCP service
```
`app.py` defaults to `--port 80`, which requires root (and, if you're in a
venv, `sudo` won't see packages installed only inside it — see the
troubleshooting note below). Using `--port 8080` sidesteps both problems;
the design and the attack are identical either way, just point the client
and `cookie_replay.py --port` at 8080 instead of 80.

> **`sudo: ModuleNotFoundError: No module named 'flask'`?** `sudo` resets
> your shell environment, so it runs the *system* Python, not your venv's.
> Either run `sudo ./venv/bin/python3 server/app.py --port 80` (points sudo
> at the venv interpreter directly), or just use `--port 8080` and skip
> `sudo` entirely — recommended for this lab.

On the **client VM**: nothing to install beyond curl and netcat
(`sudo apt install curl netcat-openbsd`).

## Run order

See **[RUN.md](RUN.md)** for the exact, copy-pasteable command sequence
across all three VMs — including running each hijack multiple times
(`--trials`) so `results/*.csv` and `plots/*.png` come out ready to drop
into the report.

## What to screenshot (Design Report Section 5 — Expected Outcome)

Open `captures/attack.pcap` in Wireshark for all of these:

1. **Poisoned ARP tables** — `arp -n` output on client and server while
   `arp_spoof.py` is running, showing the attacker's MAC against the peer's IP.
2. **Accepted injected TCP segment** — the injected packet in Wireshark
   (source = client IP, correct SEQ/ACK) followed by the server's ACK
   advancing with **no RST**; compare against `tcp_hijack.py`'s own
   RESULT log line.
3. **Real client's connection disrupted** — if `--send-rst` was used, the
   RST arriving at the client, or otherwise the duplicate-ACK/stall
   behavior once its SEQ view has diverged from the server's.
4. **Unauthorized HTTP response** — the `GET /account` request/response in
   `cookie_replay.py`'s output (HTTP 200 with the protected page, sourced
   from the attacker's IP, no credentials sent), plus the `Cookie:` /
   `Set-Cookie:` header pair in `captures/baseline.pcap` or `attack.pcap`.

Also include the quantitative evidence from a `--trials` run (see
[RUN.md](RUN.md)): `results/tcp_hijack_results.csv`,
`results/cookie_replay_results.csv`, and the five charts in `plots/`
(injection outcome counts, live SEQ progression, injection/replay latency,
and cookie-replay success rate).

## Defenses (Design Report Section 6) — not implemented here on purpose

This lab intentionally ships the *vulnerable* stack so the attack is
demonstrable. A hardened version would add, per Section 6:

- **Transport/network**: TLS for the login app; IPsec/VPN between hosts;
  rely on (but don't solely trust) OS-level TCP sequence-number randomization.
- **Session/cookie**: `Secure`, `HttpOnly`, `SameSite` cookie attributes;
  short-lived sessions; regenerate the session ID after login; optionally
  bind sessions to IP/User-Agent.
- **Layer-2/ARP**: static ARP entries or Dynamic ARP Inspection on managed
  switches; `arpwatch`/`XArp`-style spoof detection.
- **Detection**: IDS/IPS rules for duplicate IP–MAC bindings, unexpected
  RSTs, and duplicate-ACK storms.
- **Application**: step-up re-authentication for sensitive actions even
  within an already-authenticated session.

## Safety guard

Every attacker script calls `require_lab_targets()` before doing anything
else and exits immediately if any target IP falls outside
`192.168.56.0/24`. Do not widen this range or remove the check.
