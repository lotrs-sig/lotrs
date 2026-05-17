    Finished `release` profile [optimized] target(s) in 0.02s
     Running `target/release/examples/bench --grid '32,1:4:8:16:32;100,1:5:10:25:50;1,2:4:8:16'`
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
setting up 14 cells…
  setup N=32,T=1 (1-of-32)
  setup N=32,T=4 (4-of-32)
  setup N=32,T=8 (8-of-32)
  setup N=32,T=16 (16-of-32)
  setup N=32,T=32 (32-of-32)
  setup N=100,T=1 (1-of-100)
  setup N=100,T=5 (5-of-100)
  setup N=100,T=10 (10-of-100)
  setup N=100,T=25 (25-of-100)
  setup N=100,T=50 (50-of-100)
  setup N=1,T=2 (2-of-1)
  setup N=1,T=4 (4-of-1)
  setup N=1,T=8 (8-of-1)
  setup N=1,T=16 (16-of-1)
running 100 sign samples × 14 cells (interleaved)…
  sign sweep 10/100  (31.56 s)
  sign sweep 20/100  (66.63 s)
  sign sweep 30/100  (107.11 s)
  sign sweep 40/100  (145.61 s)
  sign sweep 50/100  (181.89 s)
  sign sweep 60/100  (213.83 s)
  sign sweep 70/100  (248.09 s)
  sign sweep 80/100  (282.83 s)
  sign sweep 90/100  (311.46 s)
  sign sweep 100/100  (348.40 s)
running 100 verify samples × 14 cells (interleaved)…
  verify sweep 10/100  (356.35 s)
  verify sweep 20/100  (364.30 s)
  verify sweep 30/100  (372.22 s)
  verify sweep 40/100  (380.19 s)
  verify sweep 50/100  (388.17 s)
  verify sweep 60/100  (396.12 s)
  verify sweep 70/100  (404.07 s)
  verify sweep 80/100  (412.05 s)
  verify sweep 90/100  (420.03 s)
  verify sweep 100/100  (427.91 s)
bench sampling phase: 427.91 s (100 samples × 14 cells)
  N=32,T=1 sign 108.0 ms (DualMS 64.84 ms + RS 28.34 ms), verify 19.43 ms, sig 22.82 KiB
  N=32,T=4 sign 119.6 ms (DualMS 75.93 ms + RS 28.31 ms), verify 25.53 ms, sig 23.89 KiB
  N=32,T=8 sign 142.7 ms (DualMS 95.88 ms + RS 28.71 ms), verify 31.03 ms, sig 24.34 KiB
  N=32,T=16 sign 149.1 ms (DualMS 101.0 ms + RS 25.07 ms), verify 43.23 ms, sig 24.98 KiB
  N=32,T=32 sign 282.2 ms (DualMS 214.5 ms + RS 34.51 ms), verify 66.02 ms, sig 25.42 KiB
  N=100,T=1 sign 245.3 ms (DualMS 147.8 ms + RS 61.63 ms), verify 43.34 ms, sig 32.84 KiB
  N=100,T=5 sign 417.2 ms (DualMS 292.7 ms + RS 80.93 ms), verify 60.12 ms, sig 34.01 KiB
  N=100,T=10 sign 441.8 ms (DualMS 316.8 ms + RS 72.92 ms), verify 81.41 ms, sig 34.64 KiB
  N=100,T=25 sign 567.4 ms (DualMS 413.8 ms + RS 75.26 ms), verify 145.2 ms, sig 35.36 KiB
  N=100,T=50 sign 788.5 ms (DualMS 595.2 ms + RS 71.75 ms), verify 250.0 ms, sig 35.79 KiB
  N=1,T=2 sign 46.16 ms (DualMS 27.33 ms + RS 13.87 ms), verify 6.46 ms, sig 18.70 KiB
  N=1,T=4 sign 56.92 ms (DualMS 35.59 ms + RS 16.43 ms), verify 6.30 ms, sig 19.34 KiB
  N=1,T=8 sign 54.21 ms (DualMS 35.23 ms + RS 13.93 ms), verify 7.43 ms, sig 19.79 KiB
  N=1,T=16 sign 64.78 ms (DualMS 45.01 ms + RS 14.13 ms), verify 9.64 ms, sig 20.42 KiB

### Primitive timings

Sign / Verify are arithmetic means over the listed
number of signing seeds; KeyGen / KAgg are single-run
(deterministic given pp / PK).

| parameter set | d | N | T | samples | KeyGen | KAgg | Sign | Verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 128 | 32 | 1 | 100 | 3.31 ms | 3.74 ms | 108.0 ms | 19.43 ms |
| `N=32,T=4` | 128 | 32 | 4 | 100 | 2.61 ms | 9.83 ms | 119.6 ms | 25.53 ms |
| `N=32,T=8` | 128 | 32 | 8 | 100 | 2.60 ms | 16.23 ms | 142.7 ms | 31.03 ms |
| `N=32,T=16` | 128 | 32 | 16 | 100 | 1.71 ms | 31.56 ms | 149.1 ms | 43.23 ms |
| `N=32,T=32` | 128 | 32 | 32 | 100 | 1.59 ms | 51.57 ms | 282.2 ms | 66.02 ms |
| `N=100,T=1` | 128 | 100 | 1 | 100 | 1.65 ms | 5.83 ms | 245.3 ms | 43.34 ms |
| `N=100,T=5` | 128 | 100 | 5 | 100 | 1.52 ms | 22.91 ms | 417.2 ms | 60.12 ms |
| `N=100,T=10` | 128 | 100 | 10 | 100 | 1.83 ms | 42.98 ms | 441.8 ms | 81.41 ms |
| `N=100,T=25` | 128 | 100 | 25 | 100 | 1.71 ms | 103.2 ms | 567.4 ms | 145.2 ms |
| `N=100,T=50` | 128 | 100 | 50 | 100 | 1.62 ms | 198.3 ms | 788.5 ms | 250.0 ms |
| `N=1,T=2` | 128 | 1 | 2 | 100 | 1.82 ms | 0.482 ms | 46.16 ms | 6.46 ms |
| `N=1,T=4` | 128 | 1 | 4 | 100 | 1.50 ms | 0.948 ms | 56.92 ms | 6.30 ms |
| `N=1,T=8` | 128 | 1 | 8 | 100 | 1.51 ms | 1.90 ms | 54.21 ms | 7.43 ms |
| `N=1,T=16` | 128 | 1 | 16 | 100 | 1.51 ms | 3.79 ms | 64.78 ms | 9.64 ms |

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
| `N=32,T=1` | 6.49 | 64.84 ms | 28.34 ms | 108.0 ms | 6.18 ms | 11.91 ms | 19.43 ms |
| `N=32,T=4` | 5.41 | 75.93 ms | 28.31 ms | 119.6 ms | 10.38 ms | 12.29 ms | 25.53 ms |
| `N=32,T=8` | 5.15 | 95.88 ms | 28.71 ms | 142.7 ms | 15.59 ms | 12.14 ms | 31.03 ms |
| `N=32,T=16` | 4.32 | 101.0 ms | 25.07 ms | 149.1 ms | 27.05 ms | 12.15 ms | 43.23 ms |
| `N=32,T=32` | 6.03 | 214.5 ms | 34.51 ms | 282.2 ms | 46.68 ms | 12.46 ms | 66.02 ms |
| `N=100,T=1` | 5.82 | 147.8 ms | 61.63 ms | 245.3 ms | 10.06 ms | 31.06 ms | 43.34 ms |
| `N=100,T=5` | 6.84 | 292.7 ms | 80.93 ms | 417.2 ms | 25.08 ms | 30.99 ms | 60.12 ms |
| `N=100,T=10` | 6.06 | 316.8 ms | 72.92 ms | 441.8 ms | 43.69 ms | 31.09 ms | 81.41 ms |
| `N=100,T=25` | 6.23 | 413.8 ms | 75.26 ms | 567.4 ms | 99.33 ms | 31.36 ms | 145.2 ms |
| `N=100,T=50` | 5.51 | 595.2 ms | 71.75 ms | 788.5 ms | 192.1 ms | 31.52 ms | 250.0 ms |
| `N=1,T=2` | 5.76 | 27.33 ms | 13.87 ms | 46.16 ms | 2.60 ms | 3.43 ms | 6.46 ms |
| `N=1,T=4` | 6.98 | 35.59 ms | 16.43 ms | 56.92 ms | 3.01 ms | 3.01 ms | 6.30 ms |
| `N=1,T=8` | 5.63 | 35.23 ms | 13.93 ms | 54.21 ms | 3.98 ms | 3.01 ms | 7.43 ms |
| `N=1,T=16` | 5.71 | 45.01 ms | 14.13 ms | 64.78 ms | 5.90 ms | 3.01 ms | 9.64 ms |

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
| `N=32,T=1` | 91.74 ms | 73.12 ms | 63.74 ms | 40.26 ms | 26.50 ms | 18.72 ms | 6.41 | 4.00 |
| `N=32,T=4` | 87.51 ms | 96.53 ms | 62.63 ms | 58.47 ms | 23.57 ms | 21.70 ms | 4.81 | 4.00 |
| `N=32,T=8` | 113.5 ms | 106.7 ms | 86.79 ms | 67.89 ms | 25.50 ms | 20.72 ms | 4.79 | 3.50 |
| `N=32,T=16` | 93.21 ms | 122.9 ms | 75.24 ms | 80.80 ms | 17.25 ms | 18.47 ms | 3.16 | 3.00 |
| `N=32,T=32` | 229.2 ms | 197.1 ms | 196.1 ms | 140.4 ms | 30.95 ms | 24.17 ms | 5.57 | 4.00 |
| `N=100,T=1` | 187.9 ms | 175.9 ms | 131.8 ms | 101.2 ms | 51.00 ms | 41.67 ms | 5.22 | 4.00 |
| `N=100,T=5` | 442.3 ms | 260.2 ms | 343.4 ms | 171.4 ms | 91.60 ms | 54.09 ms | 8.09 | 4.00 |
| `N=100,T=10` | 333.9 ms | 316.8 ms | 272.2 ms | 212.8 ms | 57.63 ms | 51.38 ms | 5.03 | 4.00 |
| `N=100,T=25` | 474.2 ms | 421.4 ms | 395.0 ms | 296.1 ms | 73.10 ms | 53.70 ms | 6.23 | 4.00 |
| `N=100,T=50` | 653.4 ms | 581.0 ms | 575.4 ms | 407.7 ms | 71.91 ms | 48.94 ms | 5.59 | 4.00 |
| `N=1,T=2` | 35.71 ms | 33.98 ms | 23.43 ms | 19.73 ms | 12.44 ms | 9.35 ms | 5.49 | 3.00 |
| `N=1,T=4` | 42.55 ms | 50.71 ms | 28.89 ms | 32.11 ms | 13.82 ms | 14.05 ms | 6.31 | 6.00 |
| `N=1,T=8` | 41.45 ms | 41.28 ms | 29.49 ms | 26.42 ms | 11.94 ms | 10.33 ms | 4.83 | 4.00 |
| `N=1,T=16` | 61.74 ms | 45.26 ms | 47.39 ms | 30.79 ms | 14.19 ms | 9.95 ms | 6.07 | 4.00 |

### Verify sample statistics

| parameter set | Verify std | Verify median | DualMS std | DualMS median | RS std | RS median |
|---|---:|---:|---:|---:|---:|---:|
| `N=32,T=1` | 1.71 ms | 19.10 ms | 0.996 ms | 5.92 ms | 0.918 ms | 11.55 ms |
| `N=32,T=4` | 3.53 ms | 24.73 ms | 1.49 ms | 10.11 ms | 2.69 ms | 11.47 ms |
| `N=32,T=8` | 2.94 ms | 30.29 ms | 1.89 ms | 15.02 ms | 1.78 ms | 11.57 ms |
| `N=32,T=16` | 4.00 ms | 43.78 ms | 3.43 ms | 27.55 ms | 1.40 ms | 11.68 ms |
| `N=32,T=32` | 6.13 ms | 66.28 ms | 5.08 ms | 47.08 ms | 1.38 ms | 12.31 ms |
| `N=100,T=1` | 1.62 ms | 42.98 ms | 1.09 ms | 9.81 ms | 1.09 ms | 30.69 ms |
| `N=100,T=5` | 3.46 ms | 59.48 ms | 1.42 ms | 24.96 ms | 3.06 ms | 30.26 ms |
| `N=100,T=10` | 3.16 ms | 80.91 ms | 2.12 ms | 43.25 ms | 2.21 ms | 30.72 ms |
| `N=100,T=25` | 4.13 ms | 144.5 ms | 2.79 ms | 98.95 ms | 2.89 ms | 30.70 ms |
| `N=100,T=50` | 6.92 ms | 248.8 ms | 5.42 ms | 191.9 ms | 3.26 ms | 30.59 ms |
| `N=1,T=2` | 0.280 ms | 6.43 ms | 0.103 ms | 2.58 ms | 0.218 ms | 3.38 ms |
| `N=1,T=4` | 0.031 ms | 6.30 ms | 0.016 ms | 3.01 ms | 0.015 ms | 3.01 ms |
| `N=1,T=8` | 0.045 ms | 7.42 ms | 0.025 ms | 3.98 ms | 0.025 ms | 3.01 ms |
| `N=1,T=16` | 0.052 ms | 9.64 ms | 0.035 ms | 5.90 ms | 0.016 ms | 3.00 ms |

### Key / signature sizes

| parameter set | sk | pk (single signer) | ring PK table (N·T·pk) | signature |
|---|---:|---:|---:|---:|
| `N=32,T=1` | 32 B | 7.12 KiB | 228.00 KiB | 22.82 KiB |
| `N=32,T=4` | 32 B | 7.12 KiB | 912.00 KiB | 23.89 KiB |
| `N=32,T=8` | 32 B | 7.12 KiB | 1.78 MiB | 24.34 KiB |
| `N=32,T=16` | 32 B | 7.12 KiB | 3.56 MiB | 24.98 KiB |
| `N=32,T=32` | 32 B | 7.12 KiB | 7.12 MiB | 25.42 KiB |
| `N=100,T=1` | 32 B | 7.12 KiB | 712.50 KiB | 32.84 KiB |
| `N=100,T=5` | 32 B | 7.12 KiB | 3.48 MiB | 34.01 KiB |
| `N=100,T=10` | 32 B | 7.12 KiB | 6.96 MiB | 34.64 KiB |
| `N=100,T=25` | 32 B | 7.12 KiB | 17.40 MiB | 35.36 KiB |
| `N=100,T=50` | 32 B | 7.12 KiB | 34.79 MiB | 35.79 KiB |
| `N=1,T=2` | 32 B | 7.12 KiB | 14.25 KiB | 18.70 KiB |
| `N=1,T=4` | 32 B | 7.12 KiB | 28.50 KiB | 19.34 KiB |
| `N=1,T=8` | 32 B | 7.12 KiB | 57.00 KiB | 19.79 KiB |
| `N=1,T=16` | 32 B | 7.12 KiB | 114.00 KiB | 20.42 KiB |

`sk` is the 32-byte seed the signer stores — the full secret-key
material `s ∈ R_q^{l+k}` is deterministically expanded from it.
