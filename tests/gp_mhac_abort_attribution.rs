use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use gp_mhac::access::compile_access;
use gp_mhac::detect::{detect, envelopes_from_transcript, DecodedMessage, DetectOutcome};
use gp_mhac::issuance::{cred_iss, iss_keygen, setup};
use gp_mhac::lsss::threshold;
use gp_mhac::presentation::cred_pres_with_lsss;
use gp_mhac::primitives::hash::hash_to_g1;
use std::collections::BTreeSet;

const NONCE: [u8; 32] = [0x5D; 32];

#[test]
fn check_prefix_attributes_fault_to_authenticated_sender() {
    let mut rng = test_rng();
    let params = setup(16, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![0, 1];
    let rev: Vec<_> = (8..16).collect();
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let access = compile_access(threshold(3, 5), 5);
    let active = vec![0, 1, 2];
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let ctx = b"gp-mhac-attribution";
    let (_, transcript) = cred_pres_with_lsss(
        &params,
        &keys.ipk,
        &precredentials,
        &attrs,
        &prv,
        &access.lsss,
        &active,
        &rev,
        ctx,
        NONCE,
        &mut rng,
    )
    .unwrap();
    let mut envelopes = envelopes_from_transcript(&access, &active, &transcript);
    let culprit = 1usize;
    let foreign = transcript.round1[2].rows[0].clone();
    let envelope = envelopes
        .iter_mut()
        .find(|item| item.round == 1 && item.sender == culprit)
        .unwrap();
    let Ok(DecodedMessage::Round1(message)) = &mut envelope.payload else {
        panic!("Round 1 expected");
    };
    message.rows.push(foreign);
    message.rows.sort_unstable_by_key(|row| row.index);
    let envelope = envelopes.iter_mut().find(|item| item.round == 3).unwrap();
    let Ok(DecodedMessage::Round3(message)) = &mut envelope.payload else {
        panic!("Round 3 expected");
    };
    message.b_bar += params.g1;
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", ctx);
    let outcome = detect(
        &params,
        &keys.ipk,
        &precredentials[0].a_sig,
        &op,
        &access,
        &active,
        &envelopes,
        transcript.verified_coin(),
        &revealed,
        &precredentials[0].pub_attrs,
        &prv,
        prv[0],
        ctx,
        NONCE,
    );
    assert_eq!(outcome, DetectOutcome::Abort(BTreeSet::from([culprit])));
}
