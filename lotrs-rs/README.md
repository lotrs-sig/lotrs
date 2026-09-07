# lotrs-rs

Rust implementation of **LoTRS** — practical post-quantum threshold ring
signatures from lattices.  Test-vector compatible with the Python reference
in [`../lotrs-py`](../lotrs-py/).

## Goals

- **Byte-for-byte interop with the Python reference.** Every seed-derived
  randomness stream, every serialized object, every Fiat–Shamir hash input
  must match `lotrs-py` exactly.  Integration tests load
  `../lotrs-py/vectors.json` and compare Rust-derived artefacts byte-wise.
- **Performance-oriented.** Uses the same CRT-NTT backend as `aux_ntt.py`,
  but with 64-bit native arithmetic, cache-friendly layouts, and
  pre-transformed CRT-NTT matrices for the large matrix-vector products.
  The auxiliary primes are both near `2^48`, so the Rust backend uses
  `u128` products plus pseudo-Mersenne reduction (`hi·c + lo mod p`,
  constants `c ∈ {16383, 19967}`) in the transform hot path.
- **More constant-time, but not CT-audited.** The arithmetic hot paths
  avoid coefficient-dependent branches for modular add/sub/neg,
  pseudo-Mersenne final reduction, CRT input splitting, and CRT output
  centering.  The signer as a whole is still **not** constant-time:
  Gaussian / challenge / uniform rejection loops, CDT binary search,
  FACCT acceptance, and restart logic remain data-dependent.  See
  *Constant-time considerations* below.
- **Robust verification.** `verify()` returns `false` for every malformed
  input class (wrong-length bytes, out-of-range coefficients, nonzero
  padding bits, trailing bytes, oversized Rice unary runs, ...) rather
  than panicking or surfacing error details that might leak signer state.
- **Fail-closed on unsupported parameter sets.** `LoTRS::try_new`
  refuses any parameter set it can't serve — currently `kappa != 1`
  or a named profile whose derived Gaussian widths do not match.

## Paper alignment

The public API mirrors the protocol figures of the accompanying paper:

| Paper            | Rust                                  |
|------------------|---------------------------------------|
| Fig. 2 `Setup`   | `LoTRS::setup`                        |
| Fig. 2 `KGen`    | `LoTRS::keygen`                       |
| Fig. 2 `KAgg`    | `LoTRS::kagg`                         |
| Fig. 3 `Sign₁`   | `LoTRS::sign1`                        |
| Fig. 6 `SAgg`    | `LoTRS::sagg`                         |
| Fig. 4 `Sign₂`   | `LoTRS::sign2`                        |
| Fig. 5 `Sign_bin`| `LoTRS::sign_bin`                     |
| Fig. 7 `Vf`      | `LoTRS::verify`                       |
| Fig. 8 `Rej` | `sample::rej` (including z_b) |
| Table 2 bounds   | methods on `LoTRSParams`              |
| Table 3 params   | `PRODUCTION_PARAMS`                   |

Implementation notes for this artifact:

- The concrete artifact implements the `kappa = 1` parameter sets used by the
  paper.
- The ring backend uses exact CRT-NTT multiplication, matching the Python
  reference arithmetic while using Rust-native layouts.
- Large masking widths use the FACCT-style sampler described in
  [`../lotrs-facct-sampler.md`](../lotrs-facct-sampler.md).
- The structured public-key table is hashed once to a 256-bit digest and that
  digest is used in the `H_agg`, `H_com`, and Fiat-Shamir inputs.

## Crate layout

```
src/
  lib.rs         Public API (re-exports).
  params.rs      Parameter sets (TEST / BENCH_4OF32 / BENCH / PRODUCTION).
  aux_ntt.rs     Exact negacyclic multiplication via CRT over two
                 48-bit auxiliary primes  (mirrors ../lotrs-py/aux_ntt.py).
  ring.rs        Polynomial ring R_q = Z_q[X]/(X^d + 1).
  sample.rs      SHAKE128 XOF + uniform / short / ternary / challenge /
                 Gaussian samplers (matches ../lotrs-py/sample.py),
                 plus FACCT-style large-sigma sampler.
  codec.rs       Canonical serialization of pp / sk / pk / signature.
  cdt.rs         Exact 128-bit CDT construction and process-wide cache.
  lotrs.rs       Scheme implementation: Setup / KeyGen / Sign / Verify.
tests/
  interop.rs     Loads ../lotrs-py/vectors.json and checks byte-exact
                 reproduction of every wire object; Rust-vs-Python
                 signature bytes; tampering rejection; BENCH sign/verify.
  sampler_kat.rs Cross-language Gaussian-sampler KAT vs
                 tests/sampler_kat.json (emitted by the Python side).
scripts/
  gen_sampler_kat.py Regenerates tests/sampler_kat.json.
```

## Coverage

The implementation covers setup, key generation, aggregation, signing,
verification, serialization, CRT-NTT arithmetic, and CDT/FACCT sampling.
Tests cover deterministic Python interoperability, production signing,
parameter consistency, and sampler fixtures. The benchmark harness ships
with a complete 14-cell grid, data, and plots.

### Byte-for-byte interop vs `../lotrs-py/vectors.json`

Every externally-visible artefact of the Python reference is reproduced
bit-identically by the Rust code, under identical seeds:

* `pp_bytes`, `sk_bytes`, `pk_bytes` (all key pairs)
* full signature bytes: `LoTRS::sign(pp, sks, ell, mu, pk_table, seed)`
* verification:   a Python-generated signature verifies `true` in Rust;
  a Rust-generated signature verifies `true` in Rust (and would in Python)
* negative paths: tampered message / flipped bit / wrong pk-table shape
  / truncated / trailing bytes  all return `false` without panics

### Constant-time considerations (status)

The current implementation meets the **panic-free on any malformed input**
contract for `verify()` and the public codec entry points. Arithmetic
uses the following protections:

* `Ring::{add,sub,neg}` and the in-place variants use mask-style
  conditional reductions rather than coefficient-dependent branches.
* Auxiliary-prime add/sub and pseudo-Mersenne final reduction use the
  same mask pattern.
* CRT input splitting uses a mask for `c > q/2`; it maps the
  negative centered case to `c + p_i - q` under a mask.
* CRT output centering and final non-negative reduction avoid
  branch-on-secret fixups.

This is **not** a full constant-time signer claim.  A deeper audit is
still outstanding; the concentrated risk areas are all on the
**signing** side:

1. **CDT binary search** in `xof_sample_gaussian` — branches on a
   secret-derived 128-bit value.  Leak channel: the sampled magnitude
   (which is secret), not the seed itself.  Mitigation for a hardened
   build: constant-time scan (linear or bit-sliced tournament) over the
   full table.  Cost scales with table length — tolerable for
   `sigma_a`, `sigma_b` (≤ ~20k entries); impractical at
   `sigma_0 ≈ 70M`, which is another reason a different sampler is
   needed at `BENCH` / `PRODUCTION` (see below).
2. **FACCT / rejection sampling** — FACCT proposals, Bernoulli
   accept/reject tests, and `rej` has data-dependent
   loop counts or branches.  Some accept / reject outcomes are already
   externally visible as signing restarts, but this is still not a
   constant-time sampler.
3. **Centred decomposition** in `Ring::centered_decompose` — branches
   on the signed coefficient value.  Inputs here are public (the
   commitments `w_tilde`, the proof commitments `B_bin`), so no secret
   data flows through the branch.
4. **Secret-key polynomials** (`sk_u`) are consumed through
   `Ring::vec_scale` and ring multiplication.  The CRT-NTT fast path
   now avoids the obvious coefficient-dependent arithmetic branches,
   but this is not a substitute for a compiler / microarchitecture CT
   audit.  The Python-matching schoolbook fallback at `d = 32` is for
   `TEST_PARAMS`, not a production path.

Bottom line: every public API is panic-free and returns `false` on
garbage input; arithmetic is now more CT-friendly; a full CT-audited
signer remains a future pass.

### Gaussian sampling

Two backends, matching the Python reference one-for-one:

* **CDT** (`xof_sample_gaussian`) — used for every width where the
  table fits in memory. `src/cdt.rs` constructs each required table
  once during `LoTRS::try_new` and caches it for later contexts. The
  required widths are the four TEST widths
  (`sigma_0`, `sigma_0_prime`, `sigma_a`, `sigma_b`) plus
  `sigma_a` at `BENCH_4OF32` / `BENCH_PARAMS` / `PRODUCTION_PARAMS`
  and the shared `sigma_b` used by the three larger profiles.
* **FACCT-style** (`xof_sample_gaussian_facct` +
  `prepare_facct`) — used for the two mask widths `sigma_0`,
  `sigma_0_prime` at `BENCH_4OF32` / `BENCH_PARAMS` / `PRODUCTION_PARAMS`,
  where the CDT would need 10⁷–10⁸ entries.  Spec at
  [`../lotrs-facct-sampler.md`](../lotrs-facct-sampler.md);
  integer-only runtime, degree-20 Q(64) polynomial evaluated by
  Horner.

The dispatch is decided once in `LoTRS::try_new`, from the explicit
`mask_sampler` field on `LoTRSParams`: `sigma_a` / `sigma_b` always use
CDT; `sigma_0` / `sigma_0_prime` use the backend declared on the
parameter set (`Cdt` for `TEST_PARAMS`, `Facct` for `BENCH_4OF32` /
`BENCH_PARAMS` / `PRODUCTION_PARAMS`). The call sites in `sign1` /
`sign_bin` match on the pre-resolved sampler; there is no hot-path
dispatch.

**Cross-language sampler KAT.**  `scripts/gen_sampler_kat.py` emits
`tests/sampler_kat.json` from the Python reference (fixed seeds,
fixed sigmas, expected `i64[]`).  The integration test
`cross_language_sampler_kat_matches_python` asserts Rust reproduces
every entry byte-for-byte.  Covers:

* forced-FACCT at moderate sigma (CDT and FACCT would both work
  there, so we can compare)
* FACCT at a fixed large-sigma point, `sigma ≈ 8.5 × 10⁶`;
  the production-lattice signature fixture additionally exercises the
  current masking widths near `7 × 10⁷`
* CDT at small sigma

**BENCH / PRODUCTION end-to-end** signing + verification works
(see the `#[ignore]`d `bench_and_production_signing_round_trip`
test; includes construction of the full public-key table).

Regenerate the sampler KAT with

```bash
python scripts/gen_sampler_kat.py    > tests/sampler_kat.json
```

### Verified against `../lotrs-py/vectors.json`

* `pp_bytes`, `sk_bytes`, `pk_bytes` for every key pair — byte-for-byte.
* Signature bytes round-trip (decode then re-encode → identical).
* A Python-generated signature verifies `true` in Rust.
* Decoder refuses truncated, trailing-byte, and tampered signatures.
* Verifier returns `false` for a wrong message and for a flipped sig bit.

### CDT construction

At `TEST_PARAMS` all four Gaussian widths fit in CDT form and are
constructed when the scheme context is initialized. At `BENCH_4OF32` /
`BENCH_PARAMS` / `PRODUCTION_PARAMS`, only the small binary-proof
widths `sigma_a` / `sigma_b` stay on CDT; the two large mask widths
`sigma_0` / `sigma_0_prime` use the FACCT-style sampler described
above. Tables are cached by the exact `(sigma, lam)` pair and shared by
later contexts in the same process. Constructing the required tables takes
about 0.3 seconds in a release build on the reference machine. Context
construction occurs outside the benchmark timing loops.

## Build

```bash
cd lotrs-rs
cargo build --release
cargo test
cargo test --test interop           # byte-exact vs lotrs-py/vectors.json
```

The interop test requires `../lotrs-py/vectors.json` to exist — generate
it by running `python vectors.py --out vectors.json` in `../lotrs-py/`.

## Benchmarks

`examples/bench.rs` measures the four high-level primitives
(`keygen` / `kagg` / `sign` / `verify`) and the wire sizes.  Two modes:

```bash
# Regression presets (TEST at d=32 + d=128 4-of-32, 16-of-32, optionally 50-of-100):
cargo run --release --example bench                  # TEST, 4-of-32, 16-of-32
cargo run --release --example bench -- --with-prod   # + 50-of-100

# Grid of (N, T) pairs on the d=128 lattice (full grid for the
# captured data and plots in bench-out/, including the standalone
# RS (T=1) and DualMS (N=1) sweeps):
cargo run --release --example bench -- \
    --grid "32,1:4:8:16:32;100,1:5:10:25:50;1,2:4:8:16"
```

The reproducible-grid command above completes in ≈ **15 minutes** on
the hardware below; it produces the table shown under
[Benchmark parameters and results](#benchmark-parameters-and-results) and corresponds to the captured data in
[`bench-out/`](bench-out/).

### Plotting bench output

`scripts/plot_bench.py` parses the bench binary's Markdown report and
emits CSV + paper-ready plots. Capture the bench output to a file and
hand it to the script:

```bash
mkdir -p bench-out
cargo run --release --example bench -- \
    --grid "32,1:4:8:16:32;100,1:5:10:25:50;1,2:4:8:16" \
    > bench-out/grid-d128.md 2>&1
python3 scripts/plot_bench.py bench-out/grid-d128.md
# → bench-out/{data.csv, summary.md,
#              sign-vs-T.pdf, sigsize-vs-T.pdf, breakdown-vs-T.pdf,
#              rs-alone-vs-N.pdf, dualms-alone-vs-T.pdf}
```

The grid has three regimes mixed into one run:

* **threshold** rows (`N≥2, T≥2`): the LoTRS combined protocol.
* **RS-alone** rows (`T=1, N≥2`): plain ring signature, one signer.
* **DualMS-alone** rows (`N=1, T≥2`): plain multi-sig, no ring hiding.

Outputs land alongside the input file:

| file | content |
|---|---|
| `data.csv`              | one row per `(N, T)` cell; timings and sizes parsed at report precision |
| `sign-vs-T.pdf`         | log-log Sign / Verify time vs threshold `T`, one line per `N` (threshold rows only) |
| `breakdown-vs-T.pdf`    | Sign decomposition: total / DualMS / RS sub-times vs `T` |
| `sigsize-vs-T.pdf`      | signature size (KiB) vs `T` (threshold rows only) |
| `rs-alone-vs-N.pdf`     | RS-alone (`T=1`): Sign / Verify / sig size vs ring size `N` |
| `dualms-alone-vs-T.pdf` | DualMS-alone (`N=1`): Sign$_{\text{DualMS}}$ / Verify$_{\text{DualMS}}$ vs signer count `T` |
| `summary.md`            | Markdown tables, one per regime (paper-friendly subsets of the columns) |

Requires `pip install matplotlib`. Running with no path argument reads
the report from stdin and writes outputs to the current working directory.

If `examples/bench.rs` gains or removes columns in any of its three
output tables (`Primitive timings` / `Sign / Verify breakdown` /
`Key / signature sizes`), the regexes at the top of `plot_bench.py`
must be updated to match.

### Benchmark parameters and results

All grid cells use the lattice in [`../parameters.json`](../parameters.json):

```
d = 128, κ = 1, k = 14, l = 20, l' = 21, n̂ = 12, k̂ = 11
q = 8796093022141, q_hat = 34359737917, w = 31, η = η' = 1
φ_a = φ_b = 24, φ = max(22·T,1100)
K_A = 28, K_B = K_w = 5, ε_tot = 0.01
mask_sampler = FACCT, tail_t = 1.2, tail_inf = 12
```

`N = β` at `κ = 1`. Only `N` and `T` vary over the 14-cell grid;
all listed thresholds retain `φ = 1100`.

| N | T | Sign mean | Verify mean | KAgg | Signature |
|---:|---:|---:|---:|---:|---:|
| 32 | 4 | 97.81 ms | 33.95 ms | 7.17 ms | 41.90 KiB |
| 32 | 16 | 151.4 ms | 54.56 ms | 25.76 ms | 42.72 KiB |
| 100 | 5 | 226.0 ms | 76.56 ms | 24.10 ms | 51.97 KiB |
| 100 | 50 | 923.6 ms | 311.0 ms | 224.2 ms | 53.53 KiB |

See [`bench-out/README.md`](bench-out/README.md) for hardware, sample
counts, timing variation, and reproduction guidance. The
[raw report](bench-out/grid-d128.md), [CSV](bench-out/data.csv), and
[summary](bench-out/summary.md) cover all threshold, `T=1`, and `N=1`
cells. The five plots listed above are generated from that report.

Each cell has 100 signing seeds and 100 verification calls. Verification
repeats the final signature in each cell; key generation averages four
calls, and key aggregation is measured once. Wire sizes are reported for
the final signature. The CSV preserves the report's display precision,
so its byte columns are rounded, not exact encoded lengths.

At N=100, T=50, the observed mean is 5.28 attempts, with standard error
0.50; the estimator heuristic is 4.7728. Ordinary `Rej` handles every
response, including `z_b`. The commitment-stability check contributes
no restarts at `kappa=1`.

A single public key occupies 9,632 bytes (9.40625 KiB); the complete
N=100, T=50 table occupies 47,031.25 KiB. The analytic signature estimate
is 52.6574 KiB, compared with the measured 53.53 KiB wire size. See
[`../estimator/README.md`](../estimator/README.md) for the encoding model
and security-estimation limits.

### Smoke-test presets

The named `BENCH_4OF32` (N=32, T=4), `BENCH_PARAMS` (N=32, T=16),
and `PRODUCTION_PARAMS` (N=100, T=50) presets provide a smaller run:

```bash
cargo run --release --example bench -- --skip-test
cargo run --release --example bench -- --skip-test --with-prod
```
