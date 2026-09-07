# LoTRS benchmark summary (release build, rayon multi-threaded)

## LoTRS combined protocol (threshold ring sig)

| N | T | Sign (s) | Verify (ms) | KAgg (ms) | sig (KiB) | single pk (KiB) | ring PK (MiB) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 32 | 4 | 0.10 | 34 | 7 | 41.90 | 9.41 | 1.18 |
| 32 | 8 | 0.12 | 42 | 13 | 42.24 | 9.41 | 2.35 |
| 32 | 16 | 0.15 | 55 | 26 | 42.72 | 9.41 | 4.70 |
| 32 | 32 | 0.27 | 82 | 50 | 43.09 | 9.41 | 9.41 |
| 100 | 5 | 0.23 | 77 | 24 | 51.97 | 9.41 | 4.59 |
| 100 | 10 | 0.27 | 103 | 46 | 52.33 | 9.41 | 9.19 |
| 100 | 25 | 0.38 | 182 | 110 | 53.01 | 9.41 | 22.96 |
| 100 | 50 | 0.92 | 311 | 224 | 53.53 | 9.41 | 45.93 |

## RS-alone (T=1)

Plain ring signature: one signer, ring of N keys.  The run retains the LoTRS lattice and masking policy specified in the input report.

| N | Sign (s) | Verify (ms) | sig (KiB) | attempts |
|---:|---:|---:|---:|---:|
| 32 | 0.08 | 27 | 41.02 | 3.0 |
| 100 | 0.17 | 55 | 51.03 | 2.7 |

## DualMS-alone (N=1)

Plain multi-signature, no ring hiding.  `Sign_DualMS` / `Verify_DualMS` are read from the breakdown columns to exclude the phantom β=1 binary proof overhead that still runs in this implementation.

| T | Sign$_\mathrm{DualMS}$ (ms) | Verify$_\mathrm{DualMS}$ (ms) | sig (KiB) | attempts |
|---:|---:|---:|---:|---:|
| 2 | 21 | 9.3 | 36.82 | 2.5 |
| 4 | 28 | 9.6 | 37.31 | 3.1 |
| 8 | 32 | 10.8 | 37.67 | 2.9 |
| 16 | 38 | 13.0 | 38.17 | 2.9 |

