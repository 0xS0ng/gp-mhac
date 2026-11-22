use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use gp_mhac::access::compile_access;
use gp_mhac::detect::{detect, envelopes_from_transcript, DetectOutcome};
use gp_mhac::issuance::{cred_iss, iss_keygen, setup};
use gp_mhac::lsss::{compile_formula, disjunction, dnf_chain, threshold, Formula, Lsss};
use gp_mhac::presentation::{cred_pres_with_lsss, vf_pres};
use gp_mhac::primitives::hash::hash_to_g1;

fn run_case(name: &str, lsss: Lsss, n: usize, active: Vec<usize>) {
    let mut rng = test_rng();
    let params = setup(16, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![0, 1];
    let rev: Vec<_> = (8..16).collect();
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let access = compile_access(lsss, n);
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let ctx = format!("gp-mhac-policy-{name}").into_bytes();
    let nonce = [0xA8; 32];
    let (_, transcript) = cred_pres_with_lsss(
        &params,
        &keys.ipk,
        &precredentials,
        &attrs,
        &prv,
        &access.lsss,
        &active,
        &rev,
        &ctx,
        nonce,
        &mut rng,
    )
    .unwrap();
    let primary = active
        .iter()
        .map(|&row| access.lsss.rho[row])
        .min()
        .unwrap();
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", &ctx);
    let outcome = detect(
        &params,
        &keys.ipk,
        &precredentials[primary].a_sig,
        &op,
        &access,
        &active,
        &envelopes_from_transcript(&access, &active, &transcript),
        transcript.verified_coin(),
        &revealed,
        &precredentials[primary].pub_attrs,
        &prv,
        prv[0],
        &ctx,
        nonce,
    );
    let DetectOutcome::Pres(presentation) = outcome else {
        panic!("detector W rejected an honest presentation under policy {name}");
    };
    assert!(vf_pres(
        &params,
        &keys.ipk,
        &presentation,
        &revealed,
        prv[0],
        &ctx,
        nonce
    ));
}

#[test]
fn honest_path_covers_threshold_and_general_access_policies() {
    for t in [5usize, 20, 50] {
        run_case(
            &format!("threshold-{t}"),
            threshold(t, 2 * t),
            2 * t,
            (0..t).collect(),
        );
    }

    let cases = vec![
        ("threshold-3-of-6", threshold(3, 6), 6, (0..3).collect()),
        ("threshold-3-of-12", threshold(3, 12), 12, (0..3).collect()),
        ("threshold-6-of-12", threshold(6, 12), 12, (0..6).collect()),
        ("disjunction-1-of-12", disjunction(12, 1), 12, vec![0]),
        ("dnf-chain-4", dnf_chain(4), 12, vec![9, 10, 11]),
        (
            "multi-row-6-of-12",
            Lsss {
                matrix: threshold(6, 12).matrix,
                rho: (0..12).map(|row| row / 2).collect(),
            },
            6,
            (0..6).collect(),
        ),
    ];
    for (name, lsss, n, active) in cases {
        run_case(name, lsss, n, active);
    }

    let left = Formula::Thr(3, (0..6).map(Formula::Leaf).collect());
    let right = Formula::Thr(2, (6..12).map(Formula::Leaf).collect());
    let nested = compile_formula(&Formula::Thr(2, vec![left, right]));
    run_case("nested-3-of-6-and-2-of-6", nested, 12, vec![0, 1, 2, 6, 7]);
}
