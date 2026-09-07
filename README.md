# LoTRS: Practical Post-Quantum Structured Threshold Ring Signatures from Lattices

This repository accompanies a paper accepted to ACM CCS 2026.
A preprint is available from the IACR Cryptology ePrint Archive:

> Nikai Jagganath, Muhammed F. Esgin, Ron Steinfeld, Amin Sakzad,
> Markku-Juhani O. Saarinen, and Dongxi Liu. **LoTRS: Practical
> Post-Quantum Structured Threshold Ring Signatures from Lattices**.
> In the *Proceedings of the 2026 ACM SIGSAC Conference on Computer and
> Communications Security (CCS 2026)*. Preprint: IACR Cryptology ePrint
> Archive, Report 2026/974.
> <https://eprint.iacr.org/2026/974>

The artifact package includes the [accepted CCS paper](LoTRS.pdf) and its
[artifact appendix](LoTRS-artifact-appendix.pdf).

Citation:

```bibtex
@inproceedings{jagganath2026lotrs,
      author = {Nikai Jagganath and Muhammed F. Esgin and Ron Steinfeld and Amin Sakzad and Markku-Juhani O. Saarinen and Dongxi Liu},
      title = {{LoTRS}: Practical Post-Quantum Structured Threshold Ring Signatures from Lattices},
      booktitle = {Proceedings of the 2026 ACM SIGSAC Conference on Computer and Communications Security},
      year = {2026},
      publisher = {Association for Computing Machinery},
      note = {Preprint available as Cryptology {ePrint} Archive, Paper 2026/974},
      url = {https://eprint.iacr.org/2026/974}
}
```

The artifact contains Python and Rust implementations, parameter-estimation
scripts, a FACCT-style sampler specification, and a benchmark harness.
The concrete `kappa=1` instantiation uses the shared production profile in
[`parameters.json`](parameters.json).

```
README.md                  this file
LoTRS.pdf                  accepted CCS paper
LoTRS-artifact-appendix.pdf artifact appendix
LICENSE                    MIT
Makefile                   conformance checks and cleanup
parameters.json            shared production parameter manifest
lotrs-facct-sampler.md     specification of the large-sigma sampler
lotrs-py/                  Python reference implementation
lotrs-rs/                  Rust performance implementation
estimator/                 SageMath parameter-estimation scripts
```

Conformance scripts and signature fixtures live in `lotrs-py/`; the Rust
tests consume those fixtures and the shared manifest directly.

The Python implementation is the **golden reference** — it is short,
readable, and emits a deterministic test-vector blob that the Rust
implementation reproduces byte-for-byte.

## Quick reproducibility check

Requires Python, a Rust toolchain with a C linker, and Make. `check-full`
also requires SageMath as `sage` on `PATH`. Tested with Python 3.14.7,
Rust/Cargo 1.98.1, and SageMath 10.9 on Linux x86_64. Dependency
installation needs network access; the tests and experiments run locally.

Create a Python environment and run the complete conformance check:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r lotrs-py/requirements.txt
make check
make check-full       # adds full production signing and Sage alignment tests
```

`make check` runs all Python tests, verifies both shipped signature fixtures,
checks the parameter manifest, and runs Rust unit and interoperability tests.
The Rust tests require the shipped Python vectors and compare keys and full
signatures byte-for-byte. The shipped vectors use schema 3.
`make check-full` passes 142 Python tests, 65 Rust tests, and five Sage tests,
including production signing and the compact production-lattice fixture.
Allow about five minutes after dependency installation.

## Reproducing the benchmarks

The benchmark reports, CSV data, and plots are in
[`lotrs-rs/bench-out/`](lotrs-rs/bench-out/). To reproduce the full grid:

```bash
cd lotrs-rs
mkdir -p bench-out
cargo run --release --example bench --      \
    --grid "32,1:4:8:16:32;100,1:5:10:25:50;1,2:4:8:16" \
    > bench-out/grid-d128.md 2>&1
pip install matplotlib                       # one-time, only for plot_bench.py
python3 scripts/plot_bench.py bench-out/grid-d128.md
```

Runtime depends on the machine. The release build uses `rayon` across
available hardware threads. The plot script writes
`bench-out/{data.csv, summary.md, sign-vs-T.pdf,
sigsize-vs-T.pdf, breakdown-vs-T.pdf, rs-alone-vs-N.pdf,
dualms-alone-vs-T.pdf}`.

For a faster smoke test that produces the headline parameter rows
without the full grid:

```bash
cargo run --release --example bench -- --skip-test --with-prod
```

The current run's `summary.md` and `data.csv` are the readable and machine
readable results. Its `README.md` records the measurement environment.

See [`lotrs-rs/README.md`](lotrs-rs/README.md) § Benchmarks for the
hardware / methodology footnotes (sample counts per cell, the
measured and estimated attempt counts, and column definitions).

## Reproducing the parameter selection

The SageMath scripts in `estimator/` calculate sizes, rejection counts,
parameter conditions, and attack-cost estimates for the shared manifest:

```bash
cd estimator
make                # runs lotrs_estimate.py — prints the headline output
make reference      # writes a fresh comparison log to compare against
                    # the checked-in LoTRS-Estimate-Output-N100T50.txt
```

For the production profile (`N=100`, `T=50`), the reference run gives:

```text
Analytic signature size                  52.6574 KiB
Single public key size                   9.40625 KiB
Ring PK size                             47,031.25 KiB
Expected signing attempts                4.7728 (heuristic)
Binary-proof PQ ASIS cost (variant 0)     100.7978 bits
DualMS PQ ASIS cost (variant 0)           94.16636 bits
```

The full output reports all three bundled ASIS variants separately;
variants 1 and 2 give 88.86122 bits for the binary proof and 86.20864 bits
for DualMS.
The manifest uses `k=14, l=20, l'=21, n_hat=12, k_hat=11`,
`q=2^43-67`, and `q_hat=2^35-451`. Both binary-proof rejection factors
are 24; `phi=max(22*T,1100)` retains the regularity floor at small thresholds.
The analytic size is an encoding estimate; the measured Rice-encoded
signature is 53.53 KiB. The attack costs above do not substantiate 128-bit
post-quantum security.

Requires SageMath with Python support available as `sage`.  The
estimator vendors local copies of the lattice estimator and the
ASIS/MSIS estimator so no network access is needed at run time —
see [`estimator/README.md`](estimator/README.md) for requirements and
the bundled helper libraries.

## Component overviews

### `lotrs-py/`

Python reference implementation of the concrete `kappa = 1` LoTRS
instantiation.  Covers parameters / derived bounds, ring arithmetic
(with auxiliary-prime CRT-NTT), CDT and FACCT-style Gaussian
samplers, signature encoding/decoding, the full signing and
verification pipeline, unit tests, and the deterministic
test-vector emitter.  The LoTRS implementation is Python; dependencies include NumPy,
PyCryptodome, and mpmath.

### `lotrs-rs/`

Rust implementation of the same concrete LoTRS path, aligned with
the Python reference at the public wire-format boundary.  Covers
setup, key generation, aggregation, signing, and verification;
serialization compatible with the Python reference; a CRT-NTT ring
backend with pseudo-Mersenne reduction; CDT and FACCT-style
samplers; the Python/Rust interop tests; and the bench harness.

Both implementations precompute a 256-bit SHAKE-128 digest of the
canonical PK-table serialization once per signing or verification
call and feed *that* digest into `H_agg`, `H_com`, and the
Fiat-Shamir hash, instead of re-hashing the multi-MiB ring
public-key table at every call site.  Binding to the full PK is
preserved by SHAKE-128 collision-resistance.

The artifact does **not** claim a constant-time signing implementation.
Gaussian/FACCT/rejection sampling and signing restart logic are
data-dependent; see `lotrs-rs/README.md` for the side-channel status.

### `estimator/`

SageMath scripts that reproduce the concrete parameter selection,
size calculations, and post-quantum security estimates.  Vendors
local copies of the lattice estimator and the ASIS/MSIS estimator
so the artifact can be evaluated without fetching dependencies.
See `estimator/README.md` for requirements and details of
the bundled external estimator components.

### `lotrs-facct-sampler.md`

Specification of the FACCT-style integer Gaussian sampler used for
the large masking distributions (`sigma_0`, `sigma_0_prime`) in the
benchmark and production parameter sets.  Covers the truncated
target distribution, the SHAKE-128/XOF-driven randomness, the
uniform proposal, the fixed-point Bernoulli-exp acceptance test,
the explicit parameter-set sampler selection used by the
implementations, and the validation requirements that the Python/Rust
cross-language KAT enforces.

## Artifact scope

The artifact focuses on the concrete `kappa = 1` implementation
path and the parameter set used for the paper's reported sizes and
benchmarks.  The Python implementation is the readable reference,
the Rust implementation is the performance-oriented implementation,
and the estimator reproduces the parameter and size calculations.

## License

MIT — see [`LICENSE`](LICENSE).
