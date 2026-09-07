//! Cross-language Gaussian-sampler KAT.
//!
//! Loads `tests/sampler_kat.json` — emitted by
//! `scripts/gen_sampler_kat.py` against the Python reference — and
//! verifies that the Rust backends produce byte-identical samples for
//! each entry.  The KAT covers:
//!
//! * forced-FACCT at moderate sigma (two seeds)
//! * FACCT at large sigma (the BENCH `sigma_0` regime)
//! * CDT at small sigma
//!
//! The test is skipped gracefully if the KAT file is missing so a
//! fresh clone doesn't fail `cargo test` before the user has generated
//! the file.

use std::fs;
use std::path::PathBuf;

use lotrs::sample::{prepare_facct, xof_sample_gaussian, xof_sample_gaussian_facct, Tag, Xof};

#[derive(serde::Deserialize)]
struct Kat {
    kat: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    name: String,
    backend: String,
    sigma: f64,
    d: usize,
    seed: String,
    tags: Vec<String>,
    samples: Vec<i64>,
}

fn kat_path() -> Option<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = here.join("tests").join("sampler_kat.json");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn build_xof(seed_hex: &str, tag_hex_list: &[String]) -> Xof {
    let seed = hex::decode(seed_hex).expect("seed hex");
    // Convert each tag from hex into a Tag::Bytes slice.  We store the
    // decoded bytes in a Vec and take slice references in a second pass
    // because Tag borrows its contents.
    let tag_bytes: Vec<Vec<u8>> = tag_hex_list
        .iter()
        .map(|t| hex::decode(t).expect("tag hex"))
        .collect();
    let tags: Vec<Tag<'_>> = tag_bytes.iter().map(|b| Tag::Bytes(b)).collect();
    Xof::new(&seed, &tags)
}

#[test]
fn cross_language_sampler_kat_matches_python() {
    let path = match kat_path() {
        Some(p) => p,
        None => {
            eprintln!(
                "tests/sampler_kat.json not found — skipping. \
                       Regenerate via `python scripts/gen_sampler_kat.py > tests/sampler_kat.json`"
            );
            return;
        }
    };
    let raw = fs::read_to_string(path).expect("read KAT");
    let kat: Kat = serde_json::from_str(&raw).expect("parse KAT");

    for entry in kat.kat {
        let mut xof = build_xof(&entry.seed, &entry.tags);
        let rust_samples: Vec<i64> = match entry.backend.as_str() {
            "facct" => {
                let p = prepare_facct(entry.sigma).expect("KAT sigma must be finite positive");
                xof_sample_gaussian_facct(&mut xof, &p, entry.d)
            }
            "cdt" => {
                let cdt = lotrs::cdt::build_cdt_cached(entry.sigma, 128)
                    .expect("KAT sigma must be finite and positive");
                xof_sample_gaussian(&mut xof, &cdt, 128, entry.d)
            }
            other => panic!("unknown backend {other:?} in KAT"),
        };
        assert_eq!(
            rust_samples, entry.samples,
            "KAT {:?} diverged between Rust and Python",
            entry.name
        );
    }
}
