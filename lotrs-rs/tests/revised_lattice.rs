//! Compact Python/Rust KAT at the production lattice dimensions and moduli.
//! N=4/T=2 keeps this signing fixture quick; phi retains the regularity floor.
use lotrs::lotrs::LoTRS;
use lotrs::{LoTRSCodec, LoTRSParams, PRODUCTION_PARAMS};
use sha3::{Digest, Sha3_256};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

#[test]
fn revised_lattice_matches_python() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../lotrs-py/revised_lattice_kat.json")).unwrap();
    let base: serde_json::Value =
        serde_json::from_str(include_str!("../../parameters.json")).unwrap();
    assert_eq!(v["schema_version"], 3);
    assert_eq!(v["base_parameters"], base);
    let par = LoTRSParams {
        beta: 4,
        T: 2,
        ..PRODUCTION_PARAMS
    };
    assert_eq!(
        v["overrides"],
        serde_json::json!({
            "beta": par.beta, "T": par.T
        })
    );
    let scheme = LoTRS::new(par);
    let codec = LoTRSCodec::new(par);
    let pp_seed = hex::decode(v["pp_seed"].as_str().unwrap()).unwrap();
    let pp = scheme.setup(&pp_seed);
    assert_eq!(digest(&codec.pp_encode(&pp).unwrap()), v["pp_sha3_256"]);

    let keys = v["keygen"].as_array().unwrap();
    assert_eq!(keys.len(), par.N() * par.T);
    let mut pk_table = vec![Vec::new(); par.N()];
    let mut sk_table = vec![Vec::new(); par.N()];
    let mut pk_bytes = vec![Vec::new(); par.N()];
    for col in 0..par.N() {
        for row in 0..par.T {
            let key = &keys[col * par.T + row];
            assert_eq!(key["col"], col);
            assert_eq!(key["row"], row);
            let seed = hex::decode(key["seed"].as_str().unwrap()).unwrap();
            let (sk, pk) = scheme.keygen(&pp, &seed);
            let encoded = codec.pk_encode(&pk).unwrap();
            assert_eq!(digest(&encoded), key["pk_sha3_256"], "key {col}/{row}");
            sk_table[col].push(sk);
            pk_table[col].push(pk);
            pk_bytes[col].push(encoded);
        }
    }
    let ell = v["ell"].as_u64().unwrap() as usize;
    let message = v["message"].as_str().unwrap().as_bytes();
    let seed = hex::decode(v["signing_seed"].as_str().unwrap()).unwrap();
    let sig = scheme
        .sign(&pp, &sk_table[ell], ell, message, &pk_table, &seed)
        .unwrap();
    assert_eq!(
        sig.len(),
        v["signature_byte_length"].as_u64().unwrap() as usize
    );
    assert_eq!(digest(&sig), v["signature_sha3_256"]);
    assert!(scheme.verify(&pp, message, &sig, &pk_bytes));
}
