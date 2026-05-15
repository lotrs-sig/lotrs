#!/usr/bin/env python3
"""
plot_bench.py -- Parse `examples/bench` output and emit CSV + paper plots.

Inputs
------
A Markdown report produced by `cargo run --release --example bench`
(see the "Benchmarks" section of lotrs-rs/README.md). The report is
parsed from a file path argument or from stdin.

Outputs
-------
Files are written next to the input file when a path is given,
or into the current working directory when reading from stdin:

  data.csv                 one row per (N, T) cell
  summary.md               Markdown table sorted by (N, T) for the paper
  sign-vs-T.pdf            log-log plot: Sign / Verify time vs threshold T
                           (threshold cells only; excludes edge rows)
  sigsize-vs-T.pdf         linear plot: signature size (KiB) vs T
  breakdown-vs-T.pdf       Sign decomposition: Sign_DualMS vs Sign_RS vs T
  rs-alone-vs-N.pdf        T=1 sweep: RS-alone Sign / Verify / sig vs N
  dualms-alone-vs-T.pdf    N=1 sweep: DualMS-alone Sign_DualMS / Verify_DualMS vs T

Usage
-----
  # generate a consolidated grid (threshold + RS-alone + DualMS-alone):
  cargo run --release --example bench -- \\
      --grid "32,1:4:8:16:32;100,1:5:10:25:50;1,2:4:8:16" \\
      > bench-out/grid-d128.md 2>&1

  # parse + plot:
  python3 lotrs-rs/scripts/plot_bench.py bench-out/grid-d128.md

  # or via stdin:
  cat bench-out/grid-d128.md | python3 lotrs-rs/scripts/plot_bench.py

Requirements
------------
  pip install matplotlib

The script accepts the bench binary's default Markdown output verbatim;
it ignores any prelude / postscript text and pulls only the three tables
("Primitive timings" / breakdown / "Key / signature sizes") via regex.
If new columns are added to those tables in `examples/bench.rs`, the
regexes here must be updated to match.
"""

import csv
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# Primitive timings: | name | d | N | T | samples | KeyGen | KAgg | Sign | Verify |
HEAD = re.compile(r"^\| `([^`]+)` \| (\d+) \| (\d+) \| (\d+) \| (\d+) "
                  r"\| ([^|]+?) \| ([^|]+?) \| ([^|]+?) \| ([^|]+?) \|$")

# Breakdown: | name | attempts | Sign_DualMS | Sign_RS | Sign | Verify_DualMS | Verify_RS | Verify |
BREAK = re.compile(r"^\| `([^`]+)` \| ([\d.]+) "
                   r"\| ([^|]+?) \| ([^|]+?) \| ([^|]+?) "
                   r"\| ([^|]+?) \| ([^|]+?) \| ([^|]+?) \|$")

# Sign stats: | name | Sign std | Sign median | DualMS std | DualMS median |
#             | RS std | RS median | attempts std | attempts median |
SIGN_STATS = re.compile(r"^\| `([^`]+)` "
                        r"\| ([^|]+?) \| ([^|]+?) \| ([^|]+?) \| ([^|]+?) "
                        r"\| ([^|]+?) \| ([^|]+?) \| ([\d.]+) \| ([\d.]+) \|$")

# Verify stats: | name | Verify std | Verify median | DualMS std | DualMS median |
#               | RS std | RS median |
VERIFY_STATS = re.compile(r"^\| `([^`]+)` "
                          r"\| ([^|]+?) \| ([^|]+?) \| ([^|]+?) \| ([^|]+?) "
                          r"\| ([^|]+?) \| ([^|]+?) \|$")

# Sizes: | name | sk | pk | ring | sig |
SIZE = re.compile(r"^\| `([^`]+)` \| ([^|]+?) \| ([^|]+?) "
                  r"\| ([^|]+?) \| ([^|]+?) \|$")


def parse_ms(s):
    s = s.strip()
    if s.endswith(" s"):
        return float(s[:-2]) * 1000.0
    if s.endswith(" ms"):
        return float(s[:-3])
    raise ValueError(s)


def parse_bytes(s):
    s = s.strip()
    units = [("MiB", 1024 ** 2), ("KiB", 1024), (" B", 1)]
    for u, k in units:
        if s.endswith(u):
            return int(round(float(s[:-len(u)]) * k))
    raise ValueError(s)


def parse_report(text):
    rows = {}
    for line in text.splitlines():
        m = HEAD.match(line)
        if m:
            name, d, N, T, samples, kg, ka, sg, vf = m.groups()
            rows.setdefault(name, {"name": name})
            rows[name].update({
                "d": int(d), "N": int(N), "T": int(T),
                "samples": int(samples),
                "keygen_ms": parse_ms(kg),
                "kagg_ms": parse_ms(ka),
                "sign_ms": parse_ms(sg),
                "verify_ms": parse_ms(vf),
            })
            continue
        m = BREAK.match(line)
        if m:
            name, attempts, sd, sr, sg, vd, vr, vf = m.groups()
            rows.setdefault(name, {"name": name})
            rows[name].update({
                "attempts": float(attempts),
                "sign_dualms_ms": parse_ms(sd),
                "sign_rs_ms": parse_ms(sr),
                "sign_total_ms": parse_ms(sg),
                "verify_dualms_ms": parse_ms(vd),
                "verify_rs_ms": parse_ms(vr),
                "verify_total_ms": parse_ms(vf),
            })
            continue
        m = SIGN_STATS.match(line)
        if m:
            (name, s_std, s_med, dm_std, dm_med,
             rs_std, rs_med, att_std, att_med) = m.groups()
            rows.setdefault(name, {"name": name})
            rows[name].update({
                "sign_std_ms": parse_ms(s_std),
                "sign_median_ms": parse_ms(s_med),
                "sign_dualms_std_ms": parse_ms(dm_std),
                "sign_dualms_median_ms": parse_ms(dm_med),
                "sign_rs_std_ms": parse_ms(rs_std),
                "sign_rs_median_ms": parse_ms(rs_med),
                "attempts_std": float(att_std),
                "attempts_median": float(att_med),
            })
            continue
        m = VERIFY_STATS.match(line)
        if m:
            (name, v_std, v_med, dm_std, dm_med, rs_std, rs_med) = m.groups()
            rows.setdefault(name, {"name": name})
            rows[name].update({
                "verify_std_ms": parse_ms(v_std),
                "verify_median_ms": parse_ms(v_med),
                "verify_dualms_std_ms": parse_ms(dm_std),
                "verify_dualms_median_ms": parse_ms(dm_med),
                "verify_rs_std_ms": parse_ms(rs_std),
                "verify_rs_median_ms": parse_ms(rs_med),
            })
            continue
        m = SIZE.match(line)
        if m:
            name, sk, pk, ring, sig = m.groups()
            rows.setdefault(name, {"name": name})
            rows[name].update({
                "sk_bytes": parse_bytes(sk),
                "pk_bytes": parse_bytes(pk),
                "ring_bytes": parse_bytes(ring),
                "sig_bytes": parse_bytes(sig),
            })
    return list(rows.values())


def write_csv(rows, path):
    cols = ["name", "d", "N", "T", "samples",
            "attempts", "attempts_std", "attempts_median",
            "keygen_ms", "kagg_ms",
            "sign_ms", "sign_std_ms", "sign_median_ms",
            "sign_dualms_ms", "sign_dualms_std_ms", "sign_dualms_median_ms",
            "sign_rs_ms", "sign_rs_std_ms", "sign_rs_median_ms",
            "verify_ms", "verify_std_ms", "verify_median_ms",
            "verify_dualms_ms", "verify_dualms_std_ms", "verify_dualms_median_ms",
            "verify_rs_ms", "verify_rs_std_ms", "verify_rs_median_ms",
            "sk_bytes", "pk_bytes", "ring_bytes", "sig_bytes"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in sorted(rows, key=lambda r: (r.get("N", 0), r.get("T", 0))):
            w.writerow({k: r.get(k, "") for k in cols})


# ---------------------------------------------------------------------------
# Row classifiers — the consolidated grid mixes three regimes.
#  - threshold:   T >= 2 and N >= 2  (the LoTRS combined protocol)
#  - rs_alone:    T == 1 and N >= 2  (one signer, ring of N)
#  - dualms_alone: N == 1 and T >= 2 (multi-sig, no ring hiding)
# ---------------------------------------------------------------------------

def is_threshold(r):
    return r.get("N", 0) >= 2 and r.get("T", 0) >= 2


def is_rs_alone(r):
    return r.get("T", 0) == 1 and r.get("N", 0) >= 2


def is_dualms_alone(r):
    return r.get("N", 0) == 1 and r.get("T", 0) >= 2


def split_by_N(rows):
    out = {}
    for r in rows:
        out.setdefault(r["N"], []).append(r)
    for N in out:
        out[N].sort(key=lambda r: r["T"])
    return out


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------

def plot_combined(rows, path):
    """Sign + Verify vs T for the threshold-protocol rows."""
    grouped = split_by_N([r for r in rows if is_threshold(r)])
    if not grouped:
        return
    fig, ax = plt.subplots(figsize=(5.5, 3.8))
    for N, group in sorted(grouped.items()):
        T = [r["T"] for r in group]
        sg = [r["sign_ms"] / 1000.0 for r in group]
        vf = [r["verify_ms"] / 1000.0 for r in group]
        ax.plot(T, sg, marker="o", linewidth=1.4,
                label=f"Sign,   N={N}")
        ax.plot(T, vf, marker="s", linewidth=1.0, linestyle="--",
                label=f"Verify, N={N}")
    ax.set_xlabel("threshold $T$")
    ax.set_ylabel("time per call (s)")
    ax.set_title("LoTRS primitive timings (Rust, rayon multi-threaded)")
    ax.set_yscale("log")
    ax.set_xscale("log")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(fontsize="small", framealpha=0.9, loc="upper left")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_breakdown(rows, path):
    """Sign decomposition as stacked bars (per-signature wall-clock).

    Three stacks per (N, T) cell, bottom to top:

    * ``Sign_DualMS`` — sign1 (T-fold commitments) + sign2 minus the
      binary proof + sagg.  At PRODUCTION this is ≈ 99% sign1 — the
      DualMS multi-sig is essentially the per-signer round-1 work.
    * ``Sign_RS`` — `sign_bin`, the binary ring proof.  Run once per
      rejection-sampling attempt now that `pi` is broadcast.
    * ``Context / setup`` — `Sign − Sign_DualMS − Sign_RS`.  One-shot
      per sign call: matrix expansion (A/B/G + NTT prep), PK-table
      digest, and the α_u precompute.  Independent of attempts.

    Bar heights carry the geometric attempt-count variance (μ ≈ 6,
    σ ≈ μ) — see `data.csv :: attempts` for the per-cell mean.
    """
    cells = sorted([r for r in rows if is_threshold(r)
                    and "sign_dualms_ms" in r],
                   key=lambda r: (r["N"], r["T"]))
    if not cells:
        return

    labels = [f"N={r['N']}\nT={r['T']}" for r in cells]
    x = list(range(len(cells)))

    dm = [r["sign_dualms_ms"] / 1000.0 for r in cells]
    rs = [r["sign_rs_ms"] / 1000.0 for r in cells]
    # Context = total Sign minus the two attributed components.  Clamp
    # to 0 in case a single noisy cell happened to undershoot the sum
    # (rare but possible under attempt-variance + timer jitter).
    ctx = [max(0.0, r["sign_ms"] / 1000.0 - d - s)
           for r, d, s in zip(cells, dm, rs)]
    # Standard error of the mean for total Sign per cell — drawn as a
    # symmetric ±1 SE error bar on the top of the stack.  SE = σ/√n
    # measures the uncertainty in the displayed mean (which is what a
    # bar chart of means should communicate), not the spread of
    # individual observations (which is ~σ ≈ μ for geometric attempt
    # counts and would visually overwhelm the bar).
    import math
    sign_se = [(r.get("sign_std_ms", 0.0) / 1000.0) /
               math.sqrt(max(1, r.get("samples", 1)))
               for r in cells]
    # Stack tops, where the error bars hang.
    stack_top = [c + d + s for c, d, s in zip(ctx, dm, rs)]

    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    dm_color = "#3b6ec0"  # blue
    rs_color = "#e3a23a"  # amber
    ctx_color = "#9aa3ad"  # neutral grey — signals "overhead, not protocol"

    # Stack order (bottom → top): Context / setup → DualMS → RS.
    # Context goes at the bottom because it's the one-shot setup
    # foundation; DualMS and RS sit on top as per-attempt work.
    # (Note: Context is not constant — it scales with N (G matrix
    # columns ≈ 2N + 19), with N·T (pk_table_hash), and with T (α_u).)
    ax.bar(x, ctx, color=ctx_color,
           label="Context / setup (A·G·B expand + pk_hash + α_u)")
    ax.bar(x, dm, bottom=ctx, color=dm_color,
           label=r"Sign$_\mathrm{DualMS}$ (multi-sig)")
    ax.bar(x, rs, bottom=[c + d for c, d in zip(ctx, dm)], color=rs_color,
           label=r"Sign$_\mathrm{RS}$ (binary proof)")
    # ±1 SE error bars on the stack total — pinned at stack_top so the
    # caps land on the visible bar height.  Geometric attempt-count
    # variance dominates the underlying spread, but SE = σ/√n shrinks
    # that to the uncertainty on the *mean* (≈ 9% at N=100, CV ≈ 0.9).
    if any(s > 0 for s in sign_se):
        sample_n = cells[0].get("samples", 0)
        ax.errorbar(x, stack_top, yerr=sign_se, fmt="none",
                    ecolor="black", elinewidth=0.9, capsize=3,
                    label=f"±1 SE on Sign mean (σ/√n, n = {sample_n})")

    # Light vertical separator between N-groups so the eye can read
    # "T sweep within fixed N" without juggling the x-tick labels.
    n_values = [r["N"] for r in cells]
    for i in range(1, len(cells)):
        if n_values[i] != n_values[i - 1]:
            ax.axvline(i - 0.5, color="0.7", linewidth=0.8, linestyle=":")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize="x-small")
    ax.set_ylabel("time per signature (s)")
    sample_n = cells[0].get("samples", 0)
    ax.set_title(
        f"Sign: DualMS + binary proof + setup "
        f"(average of n = {sample_n} runs)"
    )
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", fontsize="small", framealpha=0.9)

    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_sigsize(rows, path):
    """Signature size vs T for threshold rows."""
    grouped = split_by_N([r for r in rows if is_threshold(r)])
    if not grouped:
        return
    fig, ax = plt.subplots(figsize=(5.5, 3.6))
    for N, group in sorted(grouped.items()):
        T = [r["T"] for r in group]
        sz = [r["sig_bytes"] / 1024.0 for r in group]
        ax.plot(T, sz, marker="o", linewidth=1.4, label=f"N = {N}")
    ax.set_xlabel("threshold $T$")
    ax.set_ylabel("signature size (KiB)")
    ax.set_title("LoTRS signature size vs threshold")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize="small", framealpha=0.9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_rs_alone(rows, path):
    """T=1 sweep: RS-alone Sign / Verify / sig-size vs ring size N."""
    rs_rows = sorted([r for r in rows if is_rs_alone(r)],
                     key=lambda r: r["N"])
    if not rs_rows:
        return
    fig, (ax_t, ax_s) = plt.subplots(1, 2, figsize=(8.4, 3.4))
    N = [r["N"] for r in rs_rows]
    sg = [r["sign_ms"] / 1000.0 for r in rs_rows]
    vf = [r["verify_ms"] for r in rs_rows]
    sz = [r["sig_bytes"] / 1024.0 for r in rs_rows]
    ax_t.plot(N, sg, marker="o", linewidth=1.5, label="Sign (s)")
    ax_t.plot(N, vf, marker="s", linewidth=1.2, linestyle="--",
              label="Verify (ms)")
    ax_t.set_xlabel("ring size $N$")
    ax_t.set_ylabel("time")
    ax_t.set_title("RS-alone (T=1): time vs N")
    ax_t.set_yscale("log")
    ax_t.set_xscale("log")
    ax_t.grid(True, which="both", alpha=0.3)
    ax_t.legend(fontsize="small", framealpha=0.9)
    ax_s.plot(N, sz, marker="o", linewidth=1.5)
    ax_s.set_xlabel("ring size $N$")
    ax_s.set_ylabel("signature size (KiB)")
    ax_s.set_title("RS-alone (T=1): sig size vs N")
    ax_s.set_xscale("log")
    ax_s.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_dualms_alone(rows, path):
    """N=1 sweep: DualMS-alone Sign_DualMS / Verify_DualMS vs T.

    Reads the DualMS-only sub-times to exclude phantom β=1 binary-proof
    overhead from the headline numbers.
    """
    dm_rows = sorted([r for r in rows if is_dualms_alone(r)
                      and "sign_dualms_ms" in r],
                     key=lambda r: r["T"])
    if not dm_rows:
        return
    fig, ax = plt.subplots(figsize=(5.5, 3.6))
    T = [r["T"] for r in dm_rows]
    sg = [r["sign_dualms_ms"] / 1000.0 for r in dm_rows]
    vf = [r["verify_dualms_ms"] for r in dm_rows]
    ax.plot(T, sg, marker="o", linewidth=1.5, label="Sign$_\\mathrm{DualMS}$ (s)")
    ax.plot(T, vf, marker="s", linewidth=1.2, linestyle="--",
            label="Verify$_\\mathrm{DualMS}$ (ms)")
    ax.set_xlabel("number of signers $T$")
    ax.set_ylabel("time")
    ax.set_title("DualMS-alone (N=1): time vs T")
    ax.set_yscale("log")
    ax.set_xscale("log")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(fontsize="small", framealpha=0.9, loc="upper left")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def emit_summary_table(rows, path):
    """Threshold-protocol cells in one table; standalone cells split out."""
    rows_sorted = sorted(rows, key=lambda r: (r.get("N", 0), r.get("T", 0)))
    threshold = [r for r in rows_sorted if is_threshold(r)]
    rs_alone = [r for r in rows_sorted if is_rs_alone(r)]
    dualms_alone = [r for r in rows_sorted if is_dualms_alone(r)]
    with open(path, "w") as f:
        f.write("# LoTRS benchmark summary (release build, rayon multi-threaded)\n\n")

        if threshold:
            f.write("## LoTRS combined protocol (threshold ring sig)\n\n")
            f.write("| N | T | Sign (s) | Verify (ms) | KAgg (ms) "
                    "| sig (KiB) | single pk (KiB) | ring PK (MiB) |\n")
            f.write("|---:|---:|---:|---:|---:|---:|---:|---:|\n")
            for r in threshold:
                ring_mib = r["ring_bytes"] / (1024 ** 2)
                f.write(f"| {r['N']} | {r['T']} | "
                        f"{r['sign_ms']/1000:.2f} | "
                        f"{r['verify_ms']:.0f} | "
                        f"{r['kagg_ms']:.0f} | "
                        f"{r['sig_bytes']/1024:.2f} | "
                        f"{r['pk_bytes']/1024:.2f} | "
                        f"{ring_mib:.2f} |\n")
            f.write("\n")

        if rs_alone:
            f.write("## RS-alone (T=1)\n\n")
            f.write("Plain ring signature: one signer, ring of N keys.  "
                    "Numbers are the LoTRS protocol at T=1, *not* re-tuned "
                    "(φ=22·T is small at T=1, so attempt counts are "
                    "inflated relative to a properly-tuned standalone RS).\n\n")
            f.write("| N | Sign (s) | Verify (ms) | sig (KiB) | attempts |\n")
            f.write("|---:|---:|---:|---:|---:|\n")
            for r in rs_alone:
                f.write(f"| {r['N']} | "
                        f"{r['sign_ms']/1000:.2f} | "
                        f"{r['verify_ms']:.0f} | "
                        f"{r['sig_bytes']/1024:.2f} | "
                        f"{r.get('attempts', float('nan')):.1f} |\n")
            f.write("\n")

        if dualms_alone:
            f.write("## DualMS-alone (N=1)\n\n")
            f.write("Plain multi-signature, no ring hiding.  "
                    "`Sign_DualMS` / `Verify_DualMS` are read from the "
                    "breakdown columns to exclude the phantom β=1 binary "
                    "proof overhead that still runs in this implementation.\n\n")
            f.write("| T | Sign$_\\mathrm{DualMS}$ (ms) "
                    "| Verify$_\\mathrm{DualMS}$ (ms) "
                    "| sig (KiB) | attempts |\n")
            f.write("|---:|---:|---:|---:|---:|\n")
            for r in dualms_alone:
                f.write(f"| {r['T']} | "
                        f"{r['sign_dualms_ms']:.0f} | "
                        f"{r['verify_dualms_ms']:.1f} | "
                        f"{r['sig_bytes']/1024:.2f} | "
                        f"{r.get('attempts', float('nan')):.1f} |\n")
            f.write("\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text()
    else:
        text = sys.stdin.read()
    rows = parse_report(text)
    if not rows:
        print("no data parsed", file=sys.stderr)
        sys.exit(2)
    out = Path(sys.argv[1]).parent if len(sys.argv) > 1 else Path(".")
    out.mkdir(exist_ok=True)
    write_csv(rows, out / "data.csv")
    plot_combined(rows, out / "sign-vs-T.pdf")
    plot_sigsize(rows, out / "sigsize-vs-T.pdf")
    plot_breakdown(rows, out / "breakdown-vs-T.pdf")
    plot_rs_alone(rows, out / "rs-alone-vs-N.pdf")
    plot_dualms_alone(rows, out / "dualms-alone-vs-T.pdf")
    emit_summary_table(rows, out / "summary.md")
    print(f"wrote {out}/data.csv, summary.md, "
          f"sign-vs-T.pdf, sigsize-vs-T.pdf, "
          f"breakdown-vs-T.pdf, rs-alone-vs-N.pdf, dualms-alone-vs-T.pdf")
    print(f"parsed {len(rows)} cells: {[r['name'] for r in rows]}")


if __name__ == "__main__":
    main()
