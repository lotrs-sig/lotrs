# LoTRS benchmark summary (release build, rayon multi-threaded)

## LoTRS combined protocol (threshold ring sig)

| N | T | Sign (s) | Verify (ms) | KAgg (ms) | sig (KiB) | single pk (KiB) | ring PK (MiB) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 32 | 4 | 0.14 | 27 | 9 | 23.90 | 7.12 | 0.89 |
| 32 | 8 | 0.17 | 33 | 15 | 24.36 | 7.12 | 1.78 |
| 32 | 16 | 0.22 | 45 | 27 | 24.99 | 7.12 | 3.56 |
| 32 | 32 | 0.29 | 72 | 55 | 25.41 | 7.12 | 7.12 |
| 100 | 5 | 0.42 | 64 | 23 | 34.01 | 7.12 | 3.48 |
| 100 | 10 | 0.48 | 88 | 45 | 34.64 | 7.12 | 6.96 |
| 100 | 25 | 0.62 | 157 | 101 | 35.35 | 7.12 | 17.40 |
| 100 | 50 | 0.89 | 272 | 210 | 35.79 | 7.12 | 34.79 |

## RS-alone (T=1)

Plain ring signature: one signer, ring of N keys.  Numbers are the LoTRS protocol at T=1, *not* re-tuned (φ=22·T is small at T=1, so attempt counts are inflated relative to a properly-tuned standalone RS).

| N | Sign (s) | Verify (ms) | sig (KiB) | attempts |
|---:|---:|---:|---:|---:|
| 32 | 0.11 | 20 | 22.81 | 6.0 |
| 100 | 0.24 | 46 | 32.84 | 5.5 |

## DualMS-alone (N=1)

Plain multi-signature, no ring hiding.  `Sign_DualMS` / `Verify_DualMS` are read from the breakdown columns to exclude the phantom β=1 binary proof overhead that still runs in this implementation.

| T | Sign$_\mathrm{DualMS}$ (ms) | Verify$_\mathrm{DualMS}$ (ms) | sig (KiB) | attempts |
|---:|---:|---:|---:|---:|
| 2 | 25 | 2.9 | 18.69 | 4.8 |
| 4 | 27 | 3.3 | 19.33 | 5.1 |
| 8 | 29 | 4.2 | 19.78 | 4.6 |
| 16 | 49 | 6.2 | 20.42 | 6.0 |

