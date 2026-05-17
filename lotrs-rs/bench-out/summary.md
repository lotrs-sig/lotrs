# LoTRS benchmark summary (release build, rayon multi-threaded)

## LoTRS combined protocol (threshold ring sig)

| N | T | Sign (s) | Verify (ms) | KAgg (ms) | sig (KiB) | single pk (KiB) | ring PK (MiB) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 32 | 4 | 0.12 | 26 | 10 | 23.89 | 7.12 | 0.89 |
| 32 | 8 | 0.14 | 31 | 16 | 24.34 | 7.12 | 1.78 |
| 32 | 16 | 0.15 | 43 | 32 | 24.98 | 7.12 | 3.56 |
| 32 | 32 | 0.28 | 66 | 52 | 25.42 | 7.12 | 7.12 |
| 100 | 5 | 0.42 | 60 | 23 | 34.01 | 7.12 | 3.48 |
| 100 | 10 | 0.44 | 81 | 43 | 34.64 | 7.12 | 6.96 |
| 100 | 25 | 0.57 | 145 | 103 | 35.36 | 7.12 | 17.40 |
| 100 | 50 | 0.79 | 250 | 198 | 35.79 | 7.12 | 34.79 |

## RS-alone (T=1)

Plain ring signature: one signer, ring of N keys.  Numbers are the LoTRS protocol at T=1, *not* re-tuned (φ=22·T is small at T=1, so attempt counts are inflated relative to a properly-tuned standalone RS).

| N | Sign (s) | Verify (ms) | sig (KiB) | attempts |
|---:|---:|---:|---:|---:|
| 32 | 0.11 | 19 | 22.82 | 6.5 |
| 100 | 0.25 | 43 | 32.84 | 5.8 |

## DualMS-alone (N=1)

Plain multi-signature, no ring hiding.  `Sign_DualMS` / `Verify_DualMS` are read from the breakdown columns to exclude the phantom β=1 binary proof overhead that still runs in this implementation.

| T | Sign$_\mathrm{DualMS}$ (ms) | Verify$_\mathrm{DualMS}$ (ms) | sig (KiB) | attempts |
|---:|---:|---:|---:|---:|
| 2 | 27 | 2.6 | 18.70 | 5.8 |
| 4 | 36 | 3.0 | 19.34 | 7.0 |
| 8 | 35 | 4.0 | 19.79 | 5.6 |
| 16 | 45 | 5.9 | 20.42 | 5.7 |

