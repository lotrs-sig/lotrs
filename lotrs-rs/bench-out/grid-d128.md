LoTRS — primitive benchmarks (release build)
Timings averaged over multiple signing seeds to smooth out
the high-variance rejection-sampling attempt count.

All rows use the shared d=128 lattice:
  d=128, κ=1, k=14, l=20, l'=21, n̂=12, k̂=11, w=31, η=1
  q = 8796093022141 (largest prime < 2^43 with q ≡ 5 mod 8)
  q_hat = 34359737917 (largest prime < 2^35 with q_hat ≡ 5 mod 8)
  phi_a = 24, phi_b = 24, phi = max(22·T,1100)
  K_A = 28, K_B = 5, K_w = 5, eps_tot = 0.01
  mask_sampler = facct, tail_t = 1.2

### Primitive timings

Sign / Verify are arithmetic means over the listed
sample count. Verify repeats the last signature in each cell.
KeyGen averages 4 runs at d=128 (64 at d=32); KAgg is one run.

| parameter set | d | N | T | samples | KeyGen | KAgg | Sign | Verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 128 | 32 | 1 | 100 | 8.54 ms | 3.97 ms | 80.77 ms | 27.01 ms |
| `N=32,T=4` | 128 | 32 | 4 | 100 | 8.45 ms | 7.17 ms | 97.81 ms | 33.95 ms |
| `N=32,T=8` | 128 | 32 | 8 | 100 | 8.38 ms | 13.10 ms | 118.2 ms | 42.36 ms |
| `N=32,T=16` | 128 | 32 | 16 | 100 | 8.21 ms | 25.76 ms | 151.4 ms | 54.56 ms |
| `N=32,T=32` | 128 | 32 | 32 | 100 | 8.33 ms | 49.57 ms | 268.2 ms | 81.88 ms |
| `N=100,T=1` | 128 | 100 | 1 | 100 | 8.35 ms | 5.73 ms | 166.7 ms | 54.86 ms |
| `N=100,T=5` | 128 | 100 | 5 | 100 | 8.26 ms | 24.10 ms | 226.0 ms | 76.56 ms |
| `N=100,T=10` | 128 | 100 | 10 | 100 | 8.24 ms | 45.55 ms | 272.7 ms | 102.7 ms |
| `N=100,T=25` | 128 | 100 | 25 | 100 | 8.28 ms | 110.4 ms | 383.9 ms | 181.8 ms |
| `N=100,T=50` | 128 | 100 | 50 | 100 | 8.64 ms | 224.2 ms | 923.6 ms | 311.0 ms |
| `N=1,T=2` | 128 | 1 | 2 | 100 | 8.51 ms | 0.567 ms | 40.44 ms | 14.56 ms |
| `N=1,T=4` | 128 | 1 | 4 | 100 | 8.11 ms | 1.13 ms | 47.82 ms | 14.15 ms |
| `N=1,T=8` | 128 | 1 | 8 | 100 | 8.11 ms | 2.24 ms | 51.59 ms | 15.47 ms |
| `N=1,T=16` | 128 | 1 | 16 | 100 | 8.33 ms | 4.45 ms | 58.39 ms | 17.99 ms |

### Sign / Verify breakdown — DualMS multi-sig vs RS binary proof

Sign_DualMS = sign1 (T-fold commitments) + sign2 minus the
binary proof + sagg.  Sign_RS = `sign_bin`, the binary ring
proof, run once per rejection-sampling attempt (the shared
`pi` is broadcast to every signer; `sagg` then asserts the
T transcripts agree on it).  Both are wall-clock totals on
the multi-threaded (rayon) implementation, so
Sign_DualMS + Sign_RS ≈ Sign minus the one-shot context
expansion (expand_A/G/B, NTT prep, KAgg α_u).  `attempts` is
the mean attempt count per accepted signature.

Verify_DualMS = z̃/r̃/ẽ bounds + `A·z̃ + B·r̃ + ẽ` reconstruction
+ KAgg + ring-keyed `pk_sum` + w̃₀ recovery + closing FS hash.
Verify_RS = f1/f0/g0/g1 bounds + A_hat_bin reconstruction &
low-bit check.  pk_sum is attributed to DualMS because it's
part of the LHS=RHS multi-sig closing check.

| parameter set | attempts | Sign_DualMS | Sign_RS | Sign | Verify_DualMS | Verify_RS | Verify |
|---|---:|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 2.99 | 43.89 ms | 15.84 ms | 80.77 ms | 11.97 ms | 13.52 ms | 27.01 ms |
| `N=32,T=4` | 2.97 | 57.34 ms | 17.63 ms | 97.81 ms | 16.83 ms | 13.71 ms | 33.95 ms |
| `N=32,T=8` | 2.98 | 73.26 ms | 18.29 ms | 118.2 ms | 23.17 ms | 14.32 ms | 42.36 ms |
| `N=32,T=16` | 3.34 | 97.37 ms | 20.81 ms | 151.4 ms | 34.29 ms | 14.08 ms | 54.56 ms |
| `N=32,T=32` | 4.28 | 194.0 ms | 27.36 ms | 268.2 ms | 56.81 ms | 14.20 ms | 81.88 ms |
| `N=100,T=1` | 2.68 | 89.49 ms | 33.92 ms | 166.7 ms | 16.56 ms | 35.54 ms | 54.86 ms |
| `N=100,T=5` | 2.75 | 136.4 ms | 36.83 ms | 226.0 ms | 34.95 ms | 35.30 ms | 76.56 ms |
| `N=100,T=10` | 2.94 | 166.8 ms | 39.77 ms | 272.7 ms | 56.50 ms | 35.14 ms | 102.7 ms |
| `N=100,T=25` | 3.03 | 240.6 ms | 40.98 ms | 383.9 ms | 121.7 ms | 35.44 ms | 181.8 ms |
| `N=100,T=50` | 5.28 | 684.1 ms | 73.65 ms | 923.6 ms | 230.0 ms | 35.04 ms | 311.0 ms |
| `N=1,T=2` | 2.54 | 21.47 ms | 7.34 ms | 40.44 ms | 9.28 ms | 4.38 ms | 14.56 ms |
| `N=1,T=4` | 3.10 | 27.73 ms | 8.79 ms | 47.82 ms | 9.63 ms | 4.05 ms | 14.15 ms |
| `N=1,T=8` | 2.89 | 31.70 ms | 8.42 ms | 51.59 ms | 10.77 ms | 4.04 ms | 15.47 ms |
| `N=1,T=16` | 2.91 | 38.11 ms | 8.58 ms | 58.39 ms | 12.97 ms | 4.04 ms | 17.99 ms |

### Sign sample statistics

Per-cell sample standard deviation (n-1 denom) and median
over the listed number of signing seeds.  Std deviation is
the noise carried by the headline mean — useful for sizing
error bars on the breakdown figure.  Median sits alongside
the mean as a heavy-tail diagnostic: a large gap between
mean and median usually means a few outlier-high attempt
counts dominated the cell.  `attempts` columns are plain
numbers (counts), not durations.

| parameter set | Sign std | Sign median | DualMS std | DualMS median | RS std | RS median | attempts std | attempts median |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 41.50 ms | 64.37 ms | 31.08 ms | 30.83 ms | 9.82 ms | 12.21 ms | 2.14 | 2.00 |
| `N=32,T=4` | 49.62 ms | 89.92 ms | 38.10 ms | 51.38 ms | 10.89 ms | 16.82 ms | 2.12 | 3.00 |
| `N=32,T=8` | 82.06 ms | 89.11 ms | 67.39 ms | 49.06 ms | 13.99 ms | 13.31 ms | 2.58 | 2.00 |
| `N=32,T=16` | 102.4 ms | 118.7 ms | 84.28 ms | 73.60 ms | 17.18 ms | 14.53 ms | 3.01 | 2.00 |
| `N=32,T=32` | 180.5 ms | 203.5 ms | 157.2 ms | 137.9 ms | 21.29 ms | 21.16 ms | 3.51 | 3.00 |
| `N=100,T=1` | 94.73 ms | 132.9 ms | 70.20 ms | 65.84 ms | 22.94 ms | 25.55 ms | 2.10 | 2.00 |
| `N=100,T=5` | 115.0 ms | 183.9 ms | 91.60 ms | 102.8 ms | 22.17 ms | 28.88 ms | 1.87 | 2.00 |
| `N=100,T=10` | 137.9 ms | 242.7 ms | 113.9 ms | 146.6 ms | 23.34 ms | 35.09 ms | 1.97 | 2.50 |
| `N=100,T=25` | 226.8 ms | 295.8 ms | 194.9 ms | 159.8 ms | 29.87 ms | 28.74 ms | 2.51 | 2.00 |
| `N=100,T=50` | 713.2 ms | 718.7 ms | 638.5 ms | 505.4 ms | 68.77 ms | 50.81 ms | 5.04 | 4.00 |
| `N=1,T=2` | 18.32 ms | 35.58 ms | 13.82 ms | 19.05 ms | 4.63 ms | 5.87 ms | 1.97 | 2.00 |
| `N=1,T=4` | 30.66 ms | 39.65 ms | 23.23 ms | 21.37 ms | 7.48 ms | 6.76 ms | 2.85 | 2.00 |
| `N=1,T=8` | 33.93 ms | 39.69 ms | 26.96 ms | 22.04 ms | 6.89 ms | 5.94 ms | 2.49 | 2.00 |
| `N=1,T=16` | 39.40 ms | 46.25 ms | 32.08 ms | 27.52 ms | 7.20 ms | 6.53 ms | 2.64 | 2.00 |

### Verify sample statistics

| parameter set | Verify std | Verify median | DualMS std | DualMS median | RS std | RS median |
|---|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 1.52 ms | 26.80 ms | 0.854 ms | 11.79 ms | 0.841 ms | 13.40 ms |
| `N=32,T=4` | 1.97 ms | 33.73 ms | 1.15 ms | 16.57 ms | 1.21 ms | 13.50 ms |
| `N=32,T=8` | 5.32 ms | 40.79 ms | 2.60 ms | 22.55 ms | 2.78 ms | 13.39 ms |
| `N=32,T=16` | 3.94 ms | 53.22 ms | 2.69 ms | 33.37 ms | 1.80 ms | 13.51 ms |
| `N=32,T=32` | 5.46 ms | 79.94 ms | 4.69 ms | 55.16 ms | 1.92 ms | 13.68 ms |
| `N=100,T=1` | 4.21 ms | 53.50 ms | 0.846 ms | 16.47 ms | 3.70 ms | 34.22 ms |
| `N=100,T=5` | 4.35 ms | 75.44 ms | 2.19 ms | 34.32 ms | 3.07 ms | 34.18 ms |
| `N=100,T=10` | 3.67 ms | 102.2 ms | 2.22 ms | 56.03 ms | 1.88 ms | 34.57 ms |
| `N=100,T=25` | 7.99 ms | 180.4 ms | 4.74 ms | 121.3 ms | 3.62 ms | 34.23 ms |
| `N=100,T=50` | 11.07 ms | 310.7 ms | 9.57 ms | 229.8 ms | 1.97 ms | 34.46 ms |
| `N=1,T=2` | 2.45 ms | 13.84 ms | 1.52 ms | 8.89 ms | 0.944 ms | 4.06 ms |
| `N=1,T=4` | 1.42 ms | 13.76 ms | 0.933 ms | 9.35 ms | 0.471 ms | 3.95 ms |
| `N=1,T=8` | 2.06 ms | 14.99 ms | 1.50 ms | 10.44 ms | 0.499 ms | 3.94 ms |
| `N=1,T=16` | 1.32 ms | 17.60 ms | 0.721 ms | 12.74 ms | 0.495 ms | 3.94 ms |

### Key / signature sizes

| parameter set | sk | pk (single signer) | ring PK table (N·T·pk) | signature |
|---|---:|---:|---:|---:|
| `N=32,T=1` | 32 B | 9.41 KiB | 301.00 KiB | 41.02 KiB |
| `N=32,T=4` | 32 B | 9.41 KiB | 1.18 MiB | 41.90 KiB |
| `N=32,T=8` | 32 B | 9.41 KiB | 2.35 MiB | 42.24 KiB |
| `N=32,T=16` | 32 B | 9.41 KiB | 4.70 MiB | 42.72 KiB |
| `N=32,T=32` | 32 B | 9.41 KiB | 9.41 MiB | 43.09 KiB |
| `N=100,T=1` | 32 B | 9.41 KiB | 940.62 KiB | 51.03 KiB |
| `N=100,T=5` | 32 B | 9.41 KiB | 4.59 MiB | 51.97 KiB |
| `N=100,T=10` | 32 B | 9.41 KiB | 9.19 MiB | 52.33 KiB |
| `N=100,T=25` | 32 B | 9.41 KiB | 22.96 MiB | 53.01 KiB |
| `N=100,T=50` | 32 B | 9.41 KiB | 45.93 MiB | 53.53 KiB |
| `N=1,T=2` | 32 B | 9.41 KiB | 18.81 KiB | 36.82 KiB |
| `N=1,T=4` | 32 B | 9.41 KiB | 37.62 KiB | 37.31 KiB |
| `N=1,T=8` | 32 B | 9.41 KiB | 75.25 KiB | 37.67 KiB |
| `N=1,T=16` | 32 B | 9.41 KiB | 150.50 KiB | 38.17 KiB |

`sk` is the 32-byte seed the signer stores — the full secret-key
material `s ∈ R_q^{l+k}` is deterministically expanded from it.
