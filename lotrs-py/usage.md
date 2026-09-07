# LoTRS Python reference — usage

Reference implementation and test-vector generator for the LoTRS lattice-based structured threshold ring signature scheme (kappa = 1 case). Run from the `lotrs-py/` directory.

## Prerequisites

```bash
pip install -r requirements.txt   # numpy, pycryptodome, mpmath
```

Python 3.10+. No compiled extensions.

## Running tests

```bash
python test_ring.py       # ring arithmetic + CRT-NTT (22 tests)
python test_sample.py     # XOF samplers, CDT + FACCT, rejection sampling (27 tests)
python test_params.py     # parameter consistency (27 tests)
python test_lotrs.py      # scheme unit + end-to-end tests (12 tests)
python test_codec.py      # serialization, Rice coding, test vectors (23 tests)
python test_wtilde.py     # w-tilde compression tests (16 tests)
python test_e2e.py        # full pipeline and tampering tests (15 tests)
```

The test scripts cover arithmetic, sampling, parameter-manifest agreement, private session randomness, column-injectivity, serialization and end-to-end signing. First run builds the small-sigma CDTs; subsequent scheme operations reuse the cached tables. The Rust mirror adds unit, interop, parameter-manifest and sampler tests.

### Module self-tests

Each module has an `if __name__ == "__main__"` block with basic smoke tests:

```bash
python ring.py            # negacyclic property, commutativity, decomposition
python aux_ntt.py         # auxiliary-prime NTT, CRT reconstruction vs schoolbook (d=128 and d=256)
python sample.py          # determinism, Gaussian tail, challenge weight
python params.py          # prints derived parameter values for TEST, BENCH, and PRODUCTION
python lotrs.py           # full keygen → sign → verify cycle
python codec.py           # Rice round-trip + size report
```

## Programmatic usage

### End-to-end signing

```python
from params import TEST_PARAMS
from lotrs import LoTRS

scheme = LoTRS(TEST_PARAMS)              # builds CDT tables (~2s)
pp = scheme.setup(b"\x00" * 32)          # public parameters

# Key generation: N columns, T rows
pk_table = []
all_sks = []
for col in range(TEST_PARAMS.N):         # N = 4
    col_pks, col_sks = [], []
    for row in range(TEST_PARAMS.T):     # T = 2
        seed = bytes([col, row]) + b"\x00" * 30
        sk, pk = scheme.keygen(pp, seed)
        col_sks.append(sk)
        col_pks.append(pk)
    pk_table.append(col_pks)
    all_sks.append(col_sks)

# Sign with the signers from column ell
ell = 1
sks = all_sks[ell]
mu = b"approve transaction"

sig = scheme.sign(pp, sks, ell, mu, pk_table, b"\xAA" * 32)

# Verify
assert scheme.verify(pp, mu, sig, pk_table)
```

### Step-by-step signing (two-round protocol)

For applications that need to inspect intermediate state or simulate the interactive protocol across a network:

```python
from sample import derive_subseed

rho = derive_subseed(signing_seed, b"rho")
# Centralized simulation only: each distributed signer instead samples
# its own private local_seed. Never share this harness's signing_seed.
local_seeds = [derive_subseed(signing_seed, b"local", u) for u in range(T)]

# Round 1: each signer produces commitments
states, all_coms = [], []
for u in range(T):
    st, com = scheme.sign1(pp, sks[u], u, ell, mu, pk_table, rho, attempt,
                          local_seeds[u])
    states.append(st)
    all_coms.append(com)

# Round 2: each signer produces a partial signature
sigmas = []
for u in range(T):
    sig_u = scheme.sign2(states[u], all_coms, pk_table)
    if sig_u is None:
        break                             # restart with next attempt
    sigmas.append(sig_u)

# Aggregate
sigma = scheme.sagg(sigmas)
```

### Serialization

```python
from codec import LoTRSCodec

codec = LoTRSCodec(TEST_PARAMS)

# Encode / decode public key
pk_bytes = codec.pk_encode(pk)            # fixed-width at log_q bits/coeff
pk_back = codec.pk_decode(pk_bytes)       # raises ValueError on malformation

# Encode / decode signature (Rice coding for Gaussian components)
sig_bytes = codec.sig_encode(sig)
sig_back = codec.sig_decode(sig_bytes)    # raises ValueError on malformation
assert scheme.verify(pp, mu, sig_back, pk_table)

# Size breakdown
codec.print_sizes()
```

Decoders reject: out-of-range coefficients, nonzero padding bits, trailing bytes, truncated data, and excessive Rice unary runs (DoS guard).

### Test vector generation

```bash
python vectors.py --out vectors.json          # generate from fixed seeds
python vectors.py --verify vectors.json       # re-derive and compare byte-for-byte
```

The centralized `sign()` harness derives shared `rho` and separate private
signer seeds from `signing_seed` once per session. Each restart counter
selects fresh streams under those fixed seeds. Distributed signers must
generate their own private seeds; the harness's master seed is not shared.

Fixed seeds used by `vectors.py`:

- pp seed: `00 01 02 ... 1f`
- signer (col, row): `bytes([col ^ 0x40, row ^ 0x80]) + b'\x00' * 30`
- signing seed: `aa aa ... aa`

The JSON blob contains hex-encoded binary for pp, pk, and the full signature, plus intermediate values (challenge x, norms) for cross-implementation debugging.

## Parameter sets

### TEST_PARAMS (correctness testing)

Small, fast, not secure. Uses distinct primes q != q_hat to exercise both rings.

| Parameter | Value | Notes |
|-----------|-------|-------|
| d | 32 | Ring dimension |
| q | 4194389 | Prime, 5 mod 8, ~2^22 |
| q_hat | 7000061 | Distinct prime, 5 mod 8, ~2^23 |
| kappa | 1 | Only supported value |
| beta | 4 | Column index base |
| N | 4 | Ring size (columns in PK) |
| T | 2 | Threshold (signers) |
| k, l, l' | 2, 2, 3 | Matrix dimensions |
| n_hat, k_hat | 2, 3 | Binary proof dimensions |
| w | 4 | Challenge weight |
| eta | 1 | Ternary secret keys |
| phi, phi_a, phi_b | 12.0, 12.0, 12.0 | Rejection sampling slack |
| K_A, K_B, K_w | 13, 4, 5 | Bit-dropping |
| tail_t | 2.0 | Gaussian tail factor (looser than 1.2 for small dims) |
| `mask_sampler` | `"cdt"` (σ₀ ≈ 2.2 × 10³) | Small enough for a CDT |

Expected ~33 signing attempts per signature (μ·μ_a·μ_b·μ_BG·μ_fg at the estimator-formula aggregate, `μ(12)² ≈ 7.4` for the T=2 z_u factor alone).

### BENCH_4OF32 (4-of-32 benchmark-only variant)

The three d=128 sets share `k=14, l=20, l'=21, n_hat=12, k_hat=11`,
`q=8796093022141`, `q_hat=34359737917`, `phi_a=phi_b=24`,
`K_A=28, K_B=K_w=5`, and `mask_sampler="facct"`.
They use `phi=max(22*T,1100)`; all three shipped profiles have `phi=1100`
and `sigma_0 ≈ 6.97 × 10^7`.

| Profile | N | T |
|---|---:|---:|
| `BENCH_4OF32` | 32 | 4 |
| `BENCH_PARAMS` | 32 | 16 |
| `PRODUCTION_PARAMS` | 100 | 50 |

The full production profile is specified in `../parameters.json`. See
[the estimator documentation](../estimator/README.md) for measured and analytic
results and the estimator's security limitations. The name `lotrs-128`
is an identifier, not a validated security level.

The verifier checks both l2 and infinity norms of the aggregate responses.
The aggregate error width is `sqrt(T*(sigma_0^2+sigma_0_prime^2))`.
The binary proof uses ordinary `Rej` for `z_b`, and keeps every `z_b`
coefficient in its lossless Rice encoding. The `kappa=1` commitment
stability check contributes no restarts.

## Benchmarks

Wall-clock timings are produced by Rust. The current reports live in
[`../lotrs-rs/bench-out/`](../lotrs-rs/bench-out/).
The current full-profile repetition heuristic is 4.7728 attempts. The
benchmark samples 100 signing seeds per cell, interleaved across cells.

`examples/bench.rs` supports two modes:

```bash
# 1. Regression-comparison mode — named presets (TEST at d=32; and
# the d=128 presets BENCH_4OF32 / BENCH_PARAMS / PRODUCTION):
cargo run --release --example bench -- --with-prod

# 2. Grid mode — arbitrary (N, T) pairs on the shared d=128 lattice:
cargo run --release --example bench -- \
    --grid "32,1:4:8:16:32;100,1:5:10:25:50;1,2:4:8:16"
```

Allow approximately 15 minutes for the full grid on
a Ryzen AI 9 HX 370 (release build, `rayon` multi-threaded).

## Mapping to the paper

| Paper figure | Code method |
|-------------|-------------|
| Fig. 2, Setup | `LoTRS.setup()` |
| Fig. 2, KGen | `LoTRS.keygen()` |
| Fig. 2, KAgg | `LoTRS.kagg()` |
| Fig. 3, Sign_1 | `LoTRS.sign1()` |
| Fig. 6, SAgg | `LoTRS.sagg()` |
| Fig. 4, Sign_2 | `LoTRS.sign2()` — includes w̃₀ stability check |
| Fig. 5, Sign_bin | `LoTRS._sign_bin()` — w̃₀^(1) excluded from pi |
| Fig. 7, Vf | `LoTRS.verify()` — reconstructs ŵ₀^(1) from verification eq. |
| Fig. 8, Rej (also used for z_b) | `sample.rej()` |
| Table 2 | `params.LoTRSParams` properties |
| Section 4.1, encoding | `codec.LoTRSCodec` |
| — (KAT infra) | `vectors.generate()` / `vectors.verify_vectors()` |
