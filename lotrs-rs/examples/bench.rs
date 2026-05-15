//! Simple benchmarks for the LoTRS high-level primitives.
//!
//! Measures wall-clock time for every public primitive alongside the
//! concrete public-key / secret-key / signature byte sizes.  Output is
//! a Markdown table so the numbers can be pasted into artifact notes.
//!
//! Usage:
//!
//!   cargo run --release --example bench                      # TEST + BENCH_4OF32 + BENCH_PARAMS
//!   cargo run --release --example bench -- --with-prod       # + PRODUCTION_PARAMS (slow)
//!   cargo run --release --example bench -- --skip-test
//!   cargo run --release --example bench -- --grid 25,5:13:25;50,10:25:50;100,25:50
//!
//! `--grid` accepts a `;`-separated list of `N,T1:T2:…` groups.  Each
//! group shares a ring size `N` and instantiates one signer set per
//! listed threshold `T`.  All grid entries use the d=128 lattice
//! declared by the paper (`k=12, l=5, l'=6, n̂=11, k̂=8, phi_a=24,
//! phi=22·T`, `q = q_hat = largest prime < 2^38`, both ≡ 5 mod 8;
//! `mask_sampler = facct`).

use std::env;
use std::time::{Duration, Instant};

use lotrs::lotrs::LoTRS;
use lotrs::{
    LoTRSCodec, LoTRSParams, MaskSamplerKind, BENCH_4OF32, BENCH_PARAMS, PRODUCTION_PARAMS,
    TEST_PARAMS,
};

// -------------------------------------------------------------------------

/// Mean of a slice of Durations (returns ZERO for empty input).
fn mean_dur(xs: &[Duration]) -> Duration {
    if xs.is_empty() {
        return Duration::ZERO;
    }
    let sum_ns: u128 = xs.iter().map(|d| d.as_nanos()).sum();
    Duration::from_nanos((sum_ns / xs.len() as u128) as u64)
}

/// Sample standard deviation (n-1 denom) of Durations.  Returns ZERO
/// for n < 2.  Computed in nanoseconds as f64 to avoid u128 overflow
/// when squaring deviations.
fn std_dur(xs: &[Duration]) -> Duration {
    let n = xs.len();
    if n < 2 {
        return Duration::ZERO;
    }
    let mean_ns = xs.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / n as f64;
    let var: f64 = xs
        .iter()
        .map(|d| {
            let v = d.as_nanos() as f64 - mean_ns;
            v * v
        })
        .sum::<f64>()
        / (n - 1) as f64;
    Duration::from_nanos(var.sqrt().round() as u64)
}

/// Median of a slice of Durations (linear average of the two middle
/// values for even-length input).  Returns ZERO for empty input.
fn median_dur(xs: &[Duration]) -> Duration {
    if xs.is_empty() {
        return Duration::ZERO;
    }
    let mut sorted = xs.to_vec();
    sorted.sort();
    let n = sorted.len();
    if n % 2 == 0 {
        let a = sorted[n / 2 - 1].as_nanos();
        let b = sorted[n / 2].as_nanos();
        Duration::from_nanos(((a + b) / 2) as u64)
    } else {
        sorted[n / 2]
    }
}

fn mean_f64(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

fn std_f64(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 {
        return 0.0;
    }
    let m = mean_f64(xs);
    let var: f64 = xs.iter().map(|&v| (v - m) * (v - m)).sum::<f64>() / (n - 1) as f64;
    var.sqrt()
}

fn median_f64(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n % 2 == 0 {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    } else {
        s[n / 2]
    }
}

/// Per-cell timings + first/second-moment statistics over the
/// `sign_samples` independent signing/verify seeds.
///
/// Means are the headline bar heights; std deviations feed the
/// `breakdown-vs-T` error bars and the CSV; medians sit alongside
/// the mean in the CSV so heavy-tailed cells can be spotted.
struct Row {
    name: String,
    par: LoTRSParams,
    keygen: Duration,
    kagg: Duration,
    sign: Duration,
    sign_std: Duration,
    sign_median: Duration,
    /// DualMS portion of `sign` — sign1 (T-fold commitments) +
    /// sign2 minus the binary proof + sagg.  Summed across all
    /// rejection-sampling attempts in a single call, then averaged
    /// across seeds.
    sign_dualms: Duration,
    sign_dualms_std: Duration,
    sign_dualms_median: Duration,
    /// Ring-signature portion of `sign` — `sign_bin` only.  Summed
    /// across all attempts then averaged across seeds.
    sign_rs: Duration,
    sign_rs_std: Duration,
    sign_rs_median: Duration,
    /// Mean number of rejection-sampling attempts per accepted
    /// signature.  Mostly a sanity check (μ_total ≈ 3 at production
    /// under v1.5 parameters; empirical may be slightly higher).
    sign_attempts: f64,
    sign_attempts_std: f64,
    sign_attempts_median: f64,
    verify: Duration,
    verify_std: Duration,
    verify_median: Duration,
    /// DualMS portion of `verify` — z̃/r̃/ẽ bounds, A·z̃ + B·r̃ + ẽ
    /// reconstruction, KAgg, ring-keyed pk_sum, w̃₀ recovery, FS hash.
    verify_dualms: Duration,
    verify_dualms_std: Duration,
    verify_dualms_median: Duration,
    /// Ring-signature portion of `verify` — f1/f0/g0/g1 bounds,
    /// A_hat_bin reconstruction & low-bit check.
    verify_rs: Duration,
    verify_rs_std: Duration,
    verify_rs_median: Duration,
    pk_bytes: usize,
    sk_bytes: usize,
    sig_bytes: usize,
    sign_samples: usize,
}

/// Build a d=128 grid parameter set for an arbitrary `(N, T)`.  Shares
/// the lattice, bit-drops, and `phi_a / phi_b / eps_tot` with the
/// paper-aligned `PRODUCTION_PARAMS`; only `beta = N`, `T`, and
/// `phi = 22·T` change.  The `name` field borrows from the
/// `lotrs-bench-16of32` whitelist entry so `resolve_cdt` picks the
/// right (identical across 4of32 / 16of32 / 50of100) `sigma_a` CDT.
fn make_grid_params(n: usize, t: usize) -> LoTRSParams {
    LoTRSParams {
        name: "lotrs-bench-16of32",
        d: 128,
        q: 274_877_906_837,
        q_hat: 274_877_906_837,
        kappa: 1,
        beta: n, // κ = 1 ⇒ N = β
        T: t,
        k: 12,
        l: 5,
        l_prime: 6,
        n_hat: 11,
        k_hat: 8,
        w: 31,
        eta: 1,
        phi: 22.0 * t as f64,
        phi_a: 24.0,
        phi_b: 4.0,
        K_A: 28,
        K_B: 5,
        K_w: 5,
        lam: 128,
        max_attempts: 200,
        eta_prime: -1,
        tail_t: 1.2,
        mask_sampler: MaskSamplerKind::Facct,
        eps_tot: 0.01,
    }
}

/// Uniform sample count across all cells, so the relative SE on
/// each cell of the `breakdown-vs-T` figure is constant (~10% per
/// bar).  Attempts is geometric with success probability p = 1/μ,
/// giving SE_rel = √(1 − 1/μ)/√N — for the cells we measure (μ ≈
/// 5–7) that's ~0.89–0.93 / √N, near-uniform across the figure.
const SIGN_SAMPLES: usize = 100;

/// All per-cell state used by the interleaved benchmark loop.
///
/// We hold the scheme, pp, PK table, signing keys, and per-sample
/// duration buckets in one place so the outer `for sample in 0..N
/// { for cell in cells { ... } }` loop can mutate sample state
/// in-place without re-creating the (expensive) PK tables every
/// time.
struct CellState {
    name: String,
    par: LoTRSParams,
    scheme: LoTRS,
    cell_idx: u8,
    pp: Vec<u8>,
    pk_table: Vec<Vec<Vec<Vec<u64>>>>,
    pk_bytes_tbl: Vec<Vec<Vec<u8>>>,
    sks: Vec<Vec<Vec<u64>>>,
    keygen: Duration,
    kagg: Duration,
    pk_bytes_len: usize,
    last_sig: Vec<u8>,
    sign_samples_dur: Vec<Duration>,
    sign_dualms_samples: Vec<Duration>,
    sign_rs_samples: Vec<Duration>,
    attempts_samples: Vec<f64>,
    verify_samples_dur: Vec<Duration>,
    verify_dualms_samples: Vec<Duration>,
    verify_rs_samples: Vec<Duration>,
}

fn setup_cell(cell_idx: u8, name: String, par: LoTRSParams) -> CellState {
    let scheme = LoTRS::new(par);
    let codec = LoTRSCodec::new(par);
    let pp = scheme.setup(&[0u8; 32]);

    // ---- KeyGen — average over a few runs ----------------------------
    let keygen_samples = if par.d == 32 { 64 } else { 4 };
    let t0 = Instant::now();
    for i in 0..keygen_samples {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        let _ = scheme.keygen(&pp, &seed);
    }
    let keygen = t0.elapsed() / keygen_samples as u32;

    // Build the full PK/SK table deterministically.
    let mut pk_table: Vec<Vec<Vec<Vec<u64>>>> = Vec::with_capacity(par.N());
    let mut sk_table: Vec<Vec<Vec<Vec<u64>>>> = Vec::with_capacity(par.N());
    let mut pk_bytes_tbl: Vec<Vec<Vec<u8>>> = Vec::with_capacity(par.N());
    for col in 0..par.N() {
        let mut col_pk = Vec::with_capacity(par.T);
        let mut col_sk = Vec::with_capacity(par.T);
        let mut col_pkb = Vec::with_capacity(par.T);
        for row in 0..par.T {
            let mut seed = [0u8; 32];
            seed[0] = col as u8;
            seed[1] = row as u8;
            let (sk, pk) = scheme.keygen(&pp, &seed);
            let pkb = codec.pk_encode(&pk).expect("pk_encode");
            col_pk.push(pk);
            col_sk.push(sk);
            col_pkb.push(pkb);
        }
        pk_table.push(col_pk);
        sk_table.push(col_sk);
        pk_bytes_tbl.push(col_pkb);
    }

    // ---- KAgg --------------------------------------------------------
    let t0 = Instant::now();
    let _ = scheme.kagg(&pk_table);
    let kagg = t0.elapsed();

    let ell = 0;
    let sks: Vec<_> = (0..par.T).map(|u| sk_table[ell][u].clone()).collect();
    let pk_bytes_len = pk_bytes_tbl[0][0].len();

    CellState {
        name,
        par,
        scheme,
        cell_idx,
        pp,
        pk_table,
        pk_bytes_tbl,
        sks,
        keygen,
        kagg,
        pk_bytes_len,
        last_sig: Vec::new(),
        sign_samples_dur: Vec::with_capacity(SIGN_SAMPLES),
        sign_dualms_samples: Vec::with_capacity(SIGN_SAMPLES),
        sign_rs_samples: Vec::with_capacity(SIGN_SAMPLES),
        attempts_samples: Vec::with_capacity(SIGN_SAMPLES),
        verify_samples_dur: Vec::with_capacity(SIGN_SAMPLES),
        verify_dualms_samples: Vec::with_capacity(SIGN_SAMPLES),
        verify_rs_samples: Vec::with_capacity(SIGN_SAMPLES),
    }
}

/// One sign measurement for `cell` at sample index `i`.  Mutates
/// `cell.last_sig` and pushes timings onto the per-cell vectors.
fn one_sign_sample(cell: &mut CellState, i: usize) {
    let mu = b"bench";
    let ell = 0;
    // Seed encodes (sample_idx, cell_idx) so cells don't share
    // signing seeds even though they share a 0x00 prefix.
    let mut seed = [0x00; 32];
    seed[1] = i as u8;
    seed[2] = cell.cell_idx;
    let t_call = Instant::now();
    let (sig_bytes, st) = cell
        .scheme
        .sign_with_timings(&cell.pp, &cell.sks, ell, mu, &cell.pk_table, &seed)
        .expect("sign");
    cell.sign_samples_dur.push(t_call.elapsed());
    cell.last_sig = sig_bytes;
    // DualMS = sign1 + sign2_rest + sagg; RS = sign_bin.
    cell.sign_dualms_samples
        .push(st.sign1 + st.sign2_rest + st.sagg);
    cell.sign_rs_samples.push(st.sign_bin);
    cell.attempts_samples.push(st.attempts as f64);
}

/// One verify measurement for `cell`, re-verifying `cell.last_sig`.
/// verify() cost is deterministic given (pp, μ, sig, PK) so the
/// sample variance is essentially scheduler / cache jitter, but we
/// collect per-sample timings to keep the stats pipeline symmetric
/// with sign.
fn one_verify_sample(cell: &mut CellState) {
    let mu = b"bench";
    let t_call = Instant::now();
    let (ok, vt) =
        cell.scheme
            .verify_with_timings(&cell.pp, mu, &cell.last_sig, &cell.pk_bytes_tbl);
    cell.verify_samples_dur.push(t_call.elapsed());
    assert!(ok, "bench signature failed to verify");
    cell.verify_dualms_samples.push(vt.verify_dualms);
    cell.verify_rs_samples.push(vt.verify_bin);
}

fn finalize_cell(cell: CellState) -> Row {
    let sign_samples = cell.sign_samples_dur.len();
    Row {
        name: cell.name,
        par: cell.par,
        keygen: cell.keygen,
        kagg: cell.kagg,
        sign: mean_dur(&cell.sign_samples_dur),
        sign_std: std_dur(&cell.sign_samples_dur),
        sign_median: median_dur(&cell.sign_samples_dur),
        sign_dualms: mean_dur(&cell.sign_dualms_samples),
        sign_dualms_std: std_dur(&cell.sign_dualms_samples),
        sign_dualms_median: median_dur(&cell.sign_dualms_samples),
        sign_rs: mean_dur(&cell.sign_rs_samples),
        sign_rs_std: std_dur(&cell.sign_rs_samples),
        sign_rs_median: median_dur(&cell.sign_rs_samples),
        sign_attempts: mean_f64(&cell.attempts_samples),
        sign_attempts_std: std_f64(&cell.attempts_samples),
        sign_attempts_median: median_f64(&cell.attempts_samples),
        verify: mean_dur(&cell.verify_samples_dur),
        verify_std: std_dur(&cell.verify_samples_dur),
        verify_median: median_dur(&cell.verify_samples_dur),
        verify_dualms: mean_dur(&cell.verify_dualms_samples),
        verify_dualms_std: std_dur(&cell.verify_dualms_samples),
        verify_dualms_median: median_dur(&cell.verify_dualms_samples),
        verify_rs: mean_dur(&cell.verify_rs_samples),
        verify_rs_std: std_dur(&cell.verify_rs_samples),
        verify_rs_median: median_dur(&cell.verify_rs_samples),
        pk_bytes: cell.pk_bytes_len,
        sk_bytes: 32, // codec::sk_encode output
        sig_bytes: cell.last_sig.len(),
        sign_samples,
    }
}

// -------------------------------------------------------------------------

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{:.3} ms", ms)
    } else if ms < 100.0 {
        format!("{:.2} ms", ms)
    } else if ms < 10_000.0 {
        format!("{:.1} ms", ms)
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

fn fmt_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else if n < 1024 * 1024 {
        format!("{:.2} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.2} MiB", n as f64 / (1024.0 * 1024.0))
    }
}

fn print_report(rows: &[Row]) {
    println!();
    println!("### Primitive timings");
    println!();
    println!("Sign / Verify are arithmetic means over the listed");
    println!("number of signing seeds; KeyGen / KAgg are single-run");
    println!("(deterministic given pp / PK).");
    println!();
    println!("| parameter set | d | N | T | samples | KeyGen | KAgg | Sign | Verify |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |",
            r.name,
            r.par.d,
            r.par.N(),
            r.par.T,
            r.sign_samples,
            fmt_ms(r.keygen),
            fmt_ms(r.kagg),
            fmt_ms(r.sign),
            fmt_ms(r.verify),
        );
    }

    println!();
    println!("### Sign / Verify breakdown — DualMS multi-sig vs RS binary proof");
    println!();
    println!("Sign_DualMS = sign1 (T-fold commitments) + sign2 minus the");
    println!("binary proof + sagg.  Sign_RS = `sign_bin`, the binary ring");
    println!("proof, run once per rejection-sampling attempt (the shared");
    println!("`pi` is broadcast to every signer; `sagg` then asserts the");
    println!("T transcripts agree on it).  Both are wall-clock totals on");
    println!("the multi-threaded (rayon) implementation, so");
    println!("Sign_DualMS + Sign_RS ≈ Sign minus the one-shot context");
    println!("expansion (expand_A/G/B, NTT prep, KAgg α_u).  `attempts` is");
    println!("the mean attempt count per accepted signature.");
    println!();
    println!("Verify_DualMS = z̃/r̃/ẽ bounds + `A·z̃ + B·r̃ + ẽ` reconstruction");
    println!("+ KAgg + ring-keyed `pk_sum` + w̃₀ recovery + closing FS hash.");
    println!("Verify_RS = f1/f0/g0/g1 bounds + A_hat_bin reconstruction &");
    println!("low-bit check.  pk_sum is attributed to DualMS because it's");
    println!("part of the LHS=RHS multi-sig closing check.");
    println!();
    println!(
        "| parameter set | attempts | Sign_DualMS | Sign_RS | Sign | Verify_DualMS | Verify_RS | Verify |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| `{}` | {:.2} | {} | {} | {} | {} | {} | {} |",
            r.name,
            r.sign_attempts,
            fmt_ms(r.sign_dualms),
            fmt_ms(r.sign_rs),
            fmt_ms(r.sign),
            fmt_ms(r.verify_dualms),
            fmt_ms(r.verify_rs),
            fmt_ms(r.verify),
        );
    }

    println!();
    println!("### Sign sample statistics");
    println!();
    println!("Per-cell sample standard deviation (n-1 denom) and median");
    println!("over the listed number of signing seeds.  Std deviation is");
    println!("the noise carried by the headline mean — useful for sizing");
    println!("error bars on the breakdown figure.  Median sits alongside");
    println!("the mean as a heavy-tail diagnostic: a large gap between");
    println!("mean and median usually means a few outlier-high attempt");
    println!("counts dominated the cell.  `attempts` columns are plain");
    println!("numbers (counts), not durations.");
    println!();
    println!(
        "| parameter set | Sign std | Sign median | DualMS std | DualMS median | RS std | RS median | attempts std | attempts median |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} |",
            r.name,
            fmt_ms(r.sign_std),
            fmt_ms(r.sign_median),
            fmt_ms(r.sign_dualms_std),
            fmt_ms(r.sign_dualms_median),
            fmt_ms(r.sign_rs_std),
            fmt_ms(r.sign_rs_median),
            r.sign_attempts_std,
            r.sign_attempts_median,
        );
    }

    println!();
    println!("### Verify sample statistics");
    println!();
    println!(
        "| parameter set | Verify std | Verify median | DualMS std | DualMS median | RS std | RS median |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| `{}` | {} | {} | {} | {} | {} | {} |",
            r.name,
            fmt_ms(r.verify_std),
            fmt_ms(r.verify_median),
            fmt_ms(r.verify_dualms_std),
            fmt_ms(r.verify_dualms_median),
            fmt_ms(r.verify_rs_std),
            fmt_ms(r.verify_rs_median),
        );
    }

    println!();
    println!("### Key / signature sizes");
    println!();
    println!("| parameter set | sk | pk (single signer) | ring PK table (N·T·pk) | signature |");
    println!("|---|---:|---:|---:|---:|");
    for r in rows {
        let ring_bytes = r.pk_bytes * r.par.N() * r.par.T;
        println!(
            "| `{}` | {} | {} | {} | {} |",
            r.name,
            fmt_bytes(r.sk_bytes),
            fmt_bytes(r.pk_bytes),
            fmt_bytes(ring_bytes),
            fmt_bytes(r.sig_bytes),
        );
    }
    println!();
    println!("`sk` is the 32-byte seed the signer stores — the full secret-key");
    println!("material `s ∈ R_q^{{l+k}}` is deterministically expanded from it.");
}

/// Parse `--grid N1,T1:T2:T3;N2,Ta:Tb` into a list of `(N, T)` pairs.
fn parse_grid(spec: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for group in spec.split(';').filter(|s| !s.is_empty()) {
        let (n_s, ts_s) = group
            .split_once(',')
            .unwrap_or_else(|| panic!("grid group {group:?} is not N,T1:T2:…"));
        let n: usize = n_s
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("bad N in {group:?}"));
        for t_s in ts_s.split(':') {
            let t: usize = t_s
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("bad T in {group:?}"));
            out.push((n, t));
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let with_prod = args.iter().any(|a| a == "--with-prod");
    let skip_test = args.iter().any(|a| a == "--skip-test");
    let grid_spec: Option<&str> = args
        .iter()
        .position(|a| a == "--grid")
        .and_then(|i| args.get(i + 1).map(|s| s.as_str()));

    let mut targets: Vec<(String, LoTRSParams)> = Vec::new();

    if let Some(spec) = grid_spec {
        let grid = parse_grid(spec);
        for (n, t) in grid {
            let name = format!("N={n},T={t}");
            targets.push((name, make_grid_params(n, t)));
        }
    } else {
        if !skip_test {
            targets.push(("TEST".into(), TEST_PARAMS));
        }
        targets.push(("BENCH_4OF32".into(), BENCH_4OF32));
        targets.push(("BENCH_PARAMS".into(), BENCH_PARAMS));
        if with_prod {
            targets.push(("PRODUCTION".into(), PRODUCTION_PARAMS));
        }
    }

    println!("LoTRS — primitive benchmarks (release build)");
    println!("Timings averaged over multiple signing seeds to smooth out");
    println!("the high-variance rejection-sampling attempt count.");
    println!();
    if grid_spec.is_some() {
        let par0 = targets[0].1;
        println!("All rows use the shared d=128 lattice:");
        println!(
            "  d={}, κ=1, k={}, l={}, l'={}, n̂={}, k̂={}, w={}, η={}",
            par0.d, par0.k, par0.l, par0.l_prime, par0.n_hat, par0.k_hat, par0.w, par0.eta
        );
        println!("  q = {} (largest prime ≤ 2^38 with q ≡ 5 mod 8)", par0.q);
        println!(
            "  q_hat = {} (largest prime < 2^38 with q_hat ≡ 5 mod 8)",
            par0.q_hat
        );
        println!(
            "  phi_a = {}, phi_b = {}, phi = 22·T",
            par0.phi_a, par0.phi_b
        );
        println!(
            "  K_A = {}, K_B = {}, K_w = {}, eps_tot = {}",
            par0.K_A, par0.K_B, par0.K_w, par0.eps_tot
        );
        println!("  mask_sampler = facct, tail_t = {}", par0.tail_t);
    }

    // ---- Phase 1: set up every cell up front -------------------------
    //
    // Each cell builds its pp / PK-SK table / KAgg etc. once.  This is
    // also where keygen and kagg are timed.  Setup is sequential and
    // short relative to the sampling phase, so no need to parallelise.
    eprintln!("setting up {} cells…", targets.len());
    let mut cells: Vec<CellState> = targets
        .into_iter()
        .enumerate()
        .map(|(idx, (name, par))| {
            eprintln!("  setup {name} ({}-of-{})", par.T, par.N());
            setup_cell(idx as u8, name, par)
        })
        .collect();

    // ---- Phase 2: interleaved sample collection ----------------------
    //
    // Instead of running all 100 samples of cell A back-to-back, then
    // all 100 of cell B, etc., we sweep `for sample in 0..N { for cell
    // in cells { … } }`.  This spreads each cell's samples evenly over
    // the entire bench wall-clock, so any time-varying nuisance — CPU
    // frequency / thermal scaling, scheduler load, other processes
    // briefly stealing cores — averages into every cell equally rather
    // than getting concentrated into whichever cell happened to run
    // during the disturbance.
    let bench_t0 = Instant::now();
    eprintln!(
        "running {} sign samples × {} cells (interleaved)…",
        SIGN_SAMPLES,
        cells.len()
    );
    for i in 0..SIGN_SAMPLES {
        for cell in &mut cells {
            one_sign_sample(cell, i);
        }
        if (i + 1) % 10 == 0 || i + 1 == SIGN_SAMPLES {
            eprintln!(
                "  sign sweep {}/{}  ({})",
                i + 1,
                SIGN_SAMPLES,
                fmt_ms(bench_t0.elapsed())
            );
        }
    }
    eprintln!(
        "running {} verify samples × {} cells (interleaved)…",
        SIGN_SAMPLES,
        cells.len()
    );
    for i in 0..SIGN_SAMPLES {
        for cell in &mut cells {
            one_verify_sample(cell);
        }
        if (i + 1) % 10 == 0 || i + 1 == SIGN_SAMPLES {
            eprintln!(
                "  verify sweep {}/{}  ({})",
                i + 1,
                SIGN_SAMPLES,
                fmt_ms(bench_t0.elapsed())
            );
        }
    }
    eprintln!(
        "bench sampling phase: {} ({} samples × {} cells)",
        fmt_ms(bench_t0.elapsed()),
        SIGN_SAMPLES,
        cells.len()
    );

    // ---- Phase 3: finalize & report ---------------------------------
    let rows: Vec<Row> = cells.into_iter().map(finalize_cell).collect();
    for r in &rows {
        eprintln!(
            "  {} sign {} (DualMS {} + RS {}), verify {}, sig {}",
            r.name,
            fmt_ms(r.sign),
            fmt_ms(r.sign_dualms),
            fmt_ms(r.sign_rs),
            fmt_ms(r.verify),
            fmt_bytes(r.sig_bytes),
        );
    }
    print_report(&rows);
}
