#!/usr/bin/env python3
"""
Phase 5 - Evidence Collection (Design Report Section 4 / Section 5).

Reads the CSVs produced by running tcp_hijack.py and cookie_replay.py with
--trials, and renders the plots referenced in the report:
  - TCP hijack verdicts (accepted / rejected / inconclusive) per trial
  - TCP hijack SEQ progression across trials (shows the numbers were read
    live off the wire, not guessed)
  - TCP hijack detection latency per trial
  - HTTP cookie-replay latency per trial, colored by success
  - HTTP cookie-replay success rate

Run on the ATTACKER VM (or copy results/*.csv to any machine with
matplotlib) from the repo root, after at least one of the two scripts has
been run with --trials:
    python3 attacker/plot_results.py
"""

import argparse
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def plot_tcp_hijack(rows, out_dir):
    if not rows:
        print(f"[plot] no TCP hijack rows found, skipping TCP plots")
        return

    trials = [int(r["trial"]) for r in rows]
    verdicts = [r["verdict"] for r in rows]
    latencies = [float(r["latency_ms"]) for r in rows]
    seqs = [int(r["captured_seq"]) for r in rows]

    # 1. Verdict counts
    counts = {"accepted": 0, "rejected": 0, "inconclusive": 0}
    for v in verdicts:
        counts[v] = counts.get(v, 0) + 1
    fig, ax = plt.subplots(figsize=(5, 4))
    colors = {"accepted": "#2ca02c", "rejected": "#d62728", "inconclusive": "#7f7f7f"}
    ax.bar(counts.keys(), counts.values(), color=[colors[k] for k in counts])
    ax.set_title("TCP segment injection outcomes")
    ax.set_ylabel("Number of trials")
    for i, (k, v) in enumerate(counts.items()):
        ax.text(i, v, str(v), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "tcp_hijack_verdicts.png"), dpi=150)
    plt.close(fig)

    # 2. SEQ progression across trials
    fig, ax = plt.subplots(figsize=(6, 4))
    point_colors = [colors.get(v, "#7f7f7f") for v in verdicts]
    ax.plot(trials, seqs, color="#1f77b4", linewidth=1, zorder=1)
    ax.scatter(trials, seqs, c=point_colors, zorder=2)
    ax.set_title("Captured client SEQ number per trial\n(monotonic -> read live off the wire, not guessed)")
    ax.set_xlabel("Trial")
    ax.set_ylabel("Captured SEQ")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "tcp_hijack_seq_progression.png"), dpi=150)
    plt.close(fig)

    # 3. Detection latency per trial
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(trials, latencies, color=point_colors)
    ax.set_title("Time from injected segment to accept/reject verdict")
    ax.set_xlabel("Trial")
    ax.set_ylabel("Latency (ms)")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "tcp_hijack_latency.png"), dpi=150)
    plt.close(fig)

    print(f"[plot] TCP hijack: {len(rows)} trials -> {counts}")


def plot_cookie_replay(rows, out_dir):
    if not rows:
        print(f"[plot] no cookie replay rows found, skipping HTTP plots")
        return

    trials = [int(r["trial"]) for r in rows]
    latencies = [float(r["latency_ms"]) for r in rows]
    successes = [r["success"] == "True" for r in rows]
    colors = ["#2ca02c" if s else "#d62728" for s in successes]

    # 1. Latency per trial, colored by success
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(trials, latencies, color=colors)
    ax.set_title("GET /account latency per replayed-cookie trial")
    ax.set_xlabel("Trial")
    ax.set_ylabel("Latency (ms)")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "cookie_replay_latency.png"), dpi=150)
    plt.close(fig)

    # 2. Success rate
    success_count = sum(successes)
    fail_count = len(successes) - success_count
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(
        [success_count, fail_count],
        labels=[f"200 OK ({success_count})", f"other ({fail_count})"],
        colors=["#2ca02c", "#d62728"],
        autopct=lambda p: f"{p:.0f}%" if p > 0 else "",
        startangle=90,
    )
    ax.set_title("Cookie-replay success rate\nacross all trials")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "cookie_replay_success_rate.png"), dpi=150)
    plt.close(fig)

    print(f"[plot] cookie replay: {len(rows)} trials, {success_count} succeeded, {fail_count} failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tcp-csv", default="results/tcp_hijack_results.csv")
    parser.add_argument("--cookie-csv", default="results/cookie_replay_results.csv")
    parser.add_argument("--out-dir", default="plots")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    plot_tcp_hijack(read_csv(args.tcp_csv), args.out_dir)
    plot_cookie_replay(read_csv(args.cookie_csv), args.out_dir)

    print(f"[plot] PNGs written to {args.out_dir}/")


if __name__ == "__main__":
    main()
