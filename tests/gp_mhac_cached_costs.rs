use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_std::test_rng;
use gp_mhac::access::compile_access;
use gp_mhac::issuance::{cred_iss, iss_keygen, setup};
use gp_mhac::lsss::{dnf_chain, threshold, Lsss};
use gp_mhac::ops::{self, reset, snapshot, OpCounts};
use gp_mhac::presentation::{
    cred_pres_with_lsss, round1_holder_cached, round2_open, round3_primary_cached, round5_primary,
};
use gp_mhac::primitives::hash::hash_to_g1;

fn coefficients(lsss: &Lsss, active: &[usize]) -> Vec<(usize, Fr)> {
    let sparse = lsss.recon_coeffs(active).unwrap();
    active
        .iter()
        .map(|&row| {
            let value = sparse
                .iter()
                .find(|(index, _)| *index == row)
                .map(|(_, value)| *value)
                .unwrap_or_default();
            (row, value)
        })
        .collect()
}

fn reconstruct(lsss: &Lsss, rows: &[usize], shares: &[Fr]) -> Option<Fr> {
    lsss.recon_coeffs(rows).map(|coefficients| {
        coefficients
            .iter()
            .fold(Fr::zero(), |sum, (row, value)| sum + *value * shares[*row])
    })
}

#[test]
fn dnf_chain_reconstructs_exact_clauses_without_counts() {
    let mut rng = test_rng();
    let lsss = dnf_chain(4);
    assert_eq!(lsss.matrix.len(), 12);
    assert!(lsss.matrix.iter().all(|row| row.len() == 9));
    assert_eq!(lsss.rho, (0..12).collect::<Vec<_>>());
    let secret = Fr::rand(&mut rng);
    reset();
    let shares = lsss.share(secret, &mut rng);
    for clause in 0..4 {
        let rows = [3 * clause, 3 * clause + 1, 3 * clause + 2];
        assert_eq!(reconstruct(&lsss, &rows, &shares), Some(secret));
        assert_eq!(lsss.recon_coeffs(&rows[..2]), None);
    }
    for mixed in [vec![0, 4, 8], vec![0, 1, 3, 4], vec![2, 5, 8, 10]] {
        assert_eq!(lsss.recon_coeffs(&mixed), None);
    }
    assert_eq!(snapshot(), OpCounts::default());
}

#[test]
fn gp_cached_roles_and_orchestrator_match_operation_counts() {
    let mut rng = test_rng();
    let message_count = 16usize;
    let private_count = 2usize;
    let hidden_count = 8usize;
    let params = setup(message_count, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
    let prv: Vec<_> = (0..private_count).collect();
    let rev: Vec<_> = (hidden_count..message_count).collect();
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let lsss = threshold(3, 5);
    let access = compile_access(lsss.clone(), 5);
    let active = vec![0, 1, 2];
    let coefficients = coefficients(&lsss, &active);
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let ctx = b"gp-mhac-cached-holder";
    let nonce = [0x82; 32];
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", ctx);
    let (_, baseline_transcript) = cred_pres_with_lsss(
        &params,
        &keys.ipk,
        &precredentials,
        &attrs,
        &prv,
        &lsss,
        &active,
        &rev,
        ctx,
        nonce,
        &mut rng,
    )
    .unwrap();
    let ssid = &baseline_transcript.ssid;
    let mut b_pub = params.g1;
    for (index, attribute) in attrs.iter().enumerate() {
        if prv.binary_search(&index).is_err() {
            b_pub += ops::g1_mul(&params.h[index], attribute);
        }
    }

    reset();
    let (_, holder_state) = round1_holder_cached(
        &op,
        &params,
        &precredentials[1],
        1,
        &active,
        &coefficients,
        &prv,
        ssid,
        &mut rng,
    )
    .unwrap();
    let holder_coin = gp_mhac::presentation::verify_round4_coin(
        &keys.ipk,
        &baseline_transcript.round1,
        &baseline_transcript.seed_openings,
        &active,
        &baseline_transcript.active_holders,
        &baseline_transcript.round2,
        &baseline_transcript.round3,
        &revealed,
        ctx,
        &baseline_transcript.ssid,
        nonce,
    )
    .unwrap();
    let _ = gp_mhac::presentation::round5_holder(&holder_state, &holder_coin);
    assert_eq!(
        snapshot(),
        OpCounts {
            e1: (2 * private_count + 3) as u64,
            h: (active.len() + 4) as u64,
            ..OpCounts::default()
        }
    );

    let mut messages = Vec::new();
    let mut states = Vec::new();
    for &holder in &active {
        let (message, state) = round1_holder_cached(
            &op,
            &params,
            &precredentials[holder],
            holder,
            &active,
            &coefficients,
            &prv,
            ssid,
            &mut rng,
        )
        .unwrap();
        messages.push(message);
        states.push(state);
    }
    reset();
    let (primary_message, primary_holder_state) = round1_holder_cached(
        &op,
        &params,
        &precredentials[0],
        0,
        &active,
        &coefficients,
        &prv,
        ssid,
        &mut rng,
    )
    .unwrap();
    messages[0] = primary_message;
    states[0] = primary_holder_state;
    let (openings, _) = round2_open(&states);
    let (round3, primary_state) = round3_primary_cached(
        &op,
        &b_pub,
        &params,
        &precredentials[0].a_sig,
        &attrs,
        &prv,
        &rev,
        &active,
        &coefficients,
        &messages,
        &openings,
        ctx,
        ssid,
        nonce,
        &mut rng,
    )
    .unwrap();
    let seed_openings = gp_mhac::presentation::round4_open(&states);
    let primary_coin = gp_mhac::presentation::verify_round4_coin(
        &keys.ipk,
        &messages,
        &seed_openings,
        &active,
        &baseline_transcript.active_holders,
        &round2_open(&states).1,
        &round3,
        &revealed,
        ctx,
        ssid,
        nonce,
    )
    .unwrap();
    let _ = round5_primary(&states[0], &primary_state, &primary_coin);
    assert_eq!(
        snapshot(),
        OpCounts {
            e1: (hidden_count + private_count + active.len() + 11) as u64,
            h: (active.len() + 5) as u64,
            ..OpCounts::default()
        }
    );

    reset();
    let (presentation, _) = cred_pres_with_lsss(
        &params,
        &keys.ipk,
        &precredentials,
        &attrs,
        &prv,
        &lsss,
        &active,
        &rev,
        ctx,
        nonce,
        &mut rng,
    )
    .unwrap();
    assert!(!presentation.a_bar.is_zero());
    assert_eq!(
        snapshot(),
        OpCounts {
            e1: ((active.len() - 1) * (2 * private_count + 3)
                + message_count
                + hidden_count
                + active.len()
                + 11) as u64,
            h: (3 * active.len() + 3) as u64,
            h_g: active.len() as u64,
            ..OpCounts::default()
        }
    );
}
