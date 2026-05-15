LoTRS — primitive benchmarks (release build)
Timings averaged over multiple signing seeds to smooth out
the high-variance rejection-sampling attempt count.

All rows use the shared d=128 lattice:
  d=128, κ=1, k=12, l=5, l'=6, n̂=11, k̂=8, w=31, η=1
  q = 274877906837 (largest prime ≤ 2^38 with q ≡ 5 mod 8)
  q_hat = 274877906837 (largest prime < 2^38 with q_hat ≡ 5 mod 8)
  phi_a = 24, phi_b = 4, phi = 22·T
  K_A = 28, K_B = 5, K_w = 5, eps_tot = 0.01
  mask_sampler = facct, tail_t = 1.2

### Primitive timings

Sign / Verify are arithmetic means over the listed
number of signing seeds; KeyGen / KAgg are single-run
(deterministic given pp / PK).

| parameter set | d | N | T | samples | KeyGen | KAgg | Sign | Verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 128 | 32 | 1 | 100 | 3.50 ms | 3.78 ms | 105.7 ms | 20.34 ms |
| `N=32,T=4` | 128 | 32 | 4 | 100 | 2.43 ms | 9.19 ms | 139.3 ms | 26.75 ms |
| `N=32,T=8` | 128 | 32 | 8 | 100 | 2.34 ms | 15.37 ms | 173.5 ms | 32.99 ms |
| `N=32,T=16` | 128 | 32 | 16 | 100 | 1.88 ms | 26.71 ms | 219.2 ms | 45.21 ms |
| `N=32,T=32` | 128 | 32 | 32 | 100 | 1.64 ms | 55.39 ms | 292.7 ms | 72.01 ms |
| `N=100,T=1` | 128 | 100 | 1 | 100 | 1.62 ms | 5.63 ms | 243.2 ms | 45.99 ms |
| `N=100,T=5` | 128 | 100 | 5 | 100 | 1.66 ms | 23.41 ms | 423.7 ms | 64.26 ms |
| `N=100,T=10` | 128 | 100 | 10 | 100 | 1.67 ms | 45.11 ms | 475.9 ms | 87.70 ms |
| `N=100,T=25` | 128 | 100 | 25 | 100 | 1.68 ms | 100.9 ms | 616.3 ms | 156.9 ms |
| `N=100,T=50` | 128 | 100 | 50 | 100 | 1.76 ms | 210.3 ms | 887.2 ms | 272.0 ms |
| `N=1,T=2` | 128 | 1 | 2 | 100 | 1.73 ms | 0.493 ms | 41.97 ms | 7.11 ms |
| `N=1,T=4` | 128 | 1 | 4 | 100 | 1.59 ms | 0.979 ms | 44.20 ms | 6.99 ms |
| `N=1,T=8` | 128 | 1 | 8 | 100 | 1.62 ms | 2.15 ms | 46.17 ms | 7.88 ms |
| `N=1,T=16` | 128 | 1 | 16 | 100 | 1.62 ms | 3.91 ms | 69.97 ms | 10.13 ms |

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
| `N=32,T=1` | 6.05 | 62.66 ms | 27.07 ms | 105.7 ms | 6.29 ms | 12.76 ms | 20.34 ms |
| `N=32,T=4` | 6.31 | 88.95 ms | 33.07 ms | 139.3 ms | 10.67 ms | 13.11 ms | 26.75 ms |
| `N=32,T=8` | 6.49 | 117.0 ms | 35.90 ms | 173.5 ms | 16.48 ms | 13.04 ms | 32.99 ms |
| `N=32,T=16` | 6.83 | 153.2 ms | 39.22 ms | 219.2 ms | 27.74 ms | 13.55 ms | 45.21 ms |
| `N=32,T=32` | 6.16 | 218.7 ms | 35.93 ms | 292.7 ms | 51.50 ms | 13.78 ms | 72.01 ms |
| `N=100,T=1` | 5.55 | 143.8 ms | 61.01 ms | 243.2 ms | 10.35 ms | 33.35 ms | 45.99 ms |
| `N=100,T=5` | 6.72 | 295.1 ms | 80.60 ms | 423.7 ms | 26.95 ms | 33.29 ms | 64.26 ms |
| `N=100,T=10` | 6.62 | 338.1 ms | 79.05 ms | 475.9 ms | 47.50 ms | 33.57 ms | 87.70 ms |
| `N=100,T=25` | 6.69 | 442.9 ms | 82.22 ms | 616.3 ms | 108.9 ms | 33.81 ms | 156.9 ms |
| `N=100,T=50` | 6.19 | 665.1 ms | 77.42 ms | 887.2 ms | 211.4 ms | 33.69 ms | 272.0 ms |
| `N=1,T=2` | 4.85 | 24.51 ms | 12.15 ms | 41.97 ms | 2.89 ms | 3.77 ms | 7.11 ms |
| `N=1,T=4` | 5.06 | 26.76 ms | 12.26 ms | 44.20 ms | 3.27 ms | 3.41 ms | 6.99 ms |
| `N=1,T=8` | 4.64 | 29.39 ms | 11.42 ms | 46.17 ms | 4.17 ms | 3.26 ms | 7.88 ms |
| `N=1,T=16` | 6.03 | 48.87 ms | 15.23 ms | 69.97 ms | 6.15 ms | 3.24 ms | 10.13 ms |

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
| `N=32,T=1` | 92.23 ms | 73.54 ms | 64.28 ms | 41.02 ms | 26.36 ms | 17.40 ms | 6.28 | 4.00 |
| `N=32,T=4` | 99.22 ms | 114.1 ms | 71.49 ms | 70.33 ms | 26.30 ms | 26.08 ms | 5.29 | 5.00 |
| `N=32,T=8` | 158.2 ms | 125.6 ms | 119.5 ms | 82.97 ms | 36.66 ms | 23.10 ms | 6.76 | 4.00 |
| `N=32,T=16` | 185.5 ms | 181.7 ms | 146.4 ms | 122.9 ms | 37.33 ms | 29.73 ms | 6.59 | 5.00 |
| `N=32,T=32` | 243.3 ms | 212.9 ms | 206.9 ms | 150.6 ms | 33.93 ms | 24.90 ms | 5.81 | 4.00 |
| `N=100,T=1` | 199.0 ms | 180.2 ms | 138.8 ms | 102.5 ms | 55.25 ms | 41.56 ms | 5.38 | 4.00 |
| `N=100,T=5` | 327.4 ms | 327.9 ms | 258.5 ms | 220.5 ms | 64.26 ms | 63.46 ms | 5.69 | 5.00 |
| `N=100,T=10` | 443.1 ms | 335.5 ms | 362.4 ms | 223.9 ms | 75.33 ms | 56.92 ms | 6.65 | 4.50 |
| `N=100,T=25` | 394.5 ms | 513.3 ms | 329.7 ms | 362.4 ms | 59.73 ms | 62.26 ms | 5.13 | 5.00 |
| `N=100,T=50` | 547.9 ms | 734.6 ms | 487.4 ms | 533.3 ms | 55.79 ms | 66.66 ms | 4.66 | 5.00 |
| `N=1,T=2` | 29.65 ms | 33.83 ms | 19.48 ms | 18.77 ms | 10.09 ms | 9.61 ms | 4.25 | 4.00 |
| `N=1,T=4` | 30.26 ms | 35.19 ms | 20.64 ms | 20.47 ms | 9.65 ms | 9.28 ms | 4.05 | 4.00 |
| `N=1,T=8` | 36.17 ms | 32.33 ms | 26.01 ms | 18.85 ms | 10.13 ms | 7.83 ms | 4.24 | 3.00 |
| `N=1,T=16` | 56.97 ms | 54.89 ms | 43.32 ms | 37.28 ms | 13.51 ms | 10.98 ms | 5.46 | 4.50 |

### Verify sample statistics

| parameter set | Verify std | Verify median | DualMS std | DualMS median | RS std | RS median |
|---|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 1.40 ms | 20.00 ms | 0.861 ms | 6.07 ms | 0.654 ms | 12.48 ms |
| `N=32,T=4` | 3.52 ms | 25.92 ms | 1.37 ms | 10.49 ms | 2.74 ms | 12.35 ms |
| `N=32,T=8` | 3.02 ms | 32.48 ms | 1.80 ms | 16.18 ms | 2.13 ms | 12.42 ms |
| `N=32,T=16` | 3.34 ms | 44.81 ms | 2.85 ms | 27.60 ms | 1.83 ms | 13.07 ms |
| `N=32,T=32` | 6.67 ms | 73.12 ms | 5.35 ms | 52.94 ms | 2.51 ms | 13.21 ms |
| `N=100,T=1` | 1.73 ms | 45.55 ms | 0.950 ms | 10.05 ms | 1.32 ms | 33.09 ms |
| `N=100,T=5` | 2.84 ms | 64.13 ms | 1.21 ms | 26.85 ms | 2.45 ms | 32.86 ms |
| `N=100,T=10` | 2.70 ms | 87.25 ms | 1.85 ms | 47.11 ms | 1.43 ms | 33.30 ms |
| `N=100,T=25` | 4.51 ms | 156.6 ms | 2.79 ms | 108.7 ms | 2.98 ms | 33.19 ms |
| `N=100,T=50` | 6.55 ms | 272.1 ms | 5.84 ms | 211.2 ms | 1.56 ms | 33.24 ms |
| `N=1,T=2` | 1.25 ms | 6.84 ms | 0.532 ms | 2.75 ms | 0.673 ms | 3.62 ms |
| `N=1,T=4` | 1.23 ms | 6.72 ms | 0.494 ms | 3.18 ms | 0.731 ms | 3.24 ms |
| `N=1,T=8` | 0.282 ms | 7.86 ms | 0.031 ms | 4.17 ms | 0.208 ms | 3.24 ms |
| `N=1,T=16` | 0.097 ms | 10.13 ms | 0.038 ms | 6.15 ms | 0.075 ms | 3.24 ms |

### Key / signature sizes

| parameter set | sk | pk (single signer) | ring PK table (N·T·pk) | signature |
|---|---:|---:|---:|---:|
| `N=32,T=1` | 32 B | 7.12 KiB | 228.00 KiB | 22.81 KiB |
| `N=32,T=4` | 32 B | 7.12 KiB | 912.00 KiB | 23.90 KiB |
| `N=32,T=8` | 32 B | 7.12 KiB | 1.78 MiB | 24.36 KiB |
| `N=32,T=16` | 32 B | 7.12 KiB | 3.56 MiB | 24.99 KiB |
| `N=32,T=32` | 32 B | 7.12 KiB | 7.12 MiB | 25.41 KiB |
| `N=100,T=1` | 32 B | 7.12 KiB | 712.50 KiB | 32.84 KiB |
| `N=100,T=5` | 32 B | 7.12 KiB | 3.48 MiB | 34.01 KiB |
| `N=100,T=10` | 32 B | 7.12 KiB | 6.96 MiB | 34.64 KiB |
| `N=100,T=25` | 32 B | 7.12 KiB | 17.40 MiB | 35.35 KiB |
| `N=100,T=50` | 32 B | 7.12 KiB | 34.79 MiB | 35.79 KiB |
| `N=1,T=2` | 32 B | 7.12 KiB | 14.25 KiB | 18.69 KiB |
| `N=1,T=4` | 32 B | 7.12 KiB | 28.50 KiB | 19.33 KiB |
| `N=1,T=8` | 32 B | 7.12 KiB | 57.00 KiB | 19.78 KiB |
| `N=1,T=16` | 32 B | 7.12 KiB | 114.00 KiB | 20.42 KiB |

`sk` is the 32-byte seed the signer stores — the full secret-key
material `s ∈ R_q^{l+k}` is deterministically expanded from it.
