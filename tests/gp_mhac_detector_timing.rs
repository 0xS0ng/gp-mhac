use ark_bls12_381::Fr;
use ark_ff::{One, UniformRand};
use ark_std::test_rng;
use gp_mhac::access::compile_access;
use gp_mhac::detect::{
    detect, detect_timed, envelopes_from_transcript, DecodedMessage, DetectOutcome,
};
use gp_mhac::issuance::{cred_iss, iss_keygen, setup};
use gp_mhac::lsss::threshold;
use gp_mhac::ops::{reset, snapshot};
use gp_mhac::presentation::cred_pres_with_lsss;
use gp_mhac::primitives::hash::hash_to_g1;

const NONCE: [u8; 32] = [0x91; 32];

#[test]
fn timed_and_untimed_detectors_match() {
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
    let ctx = b"gp-mhac-consistency";
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
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", ctx);
    let base = envelopes_from_transcript(&access, &active, &transcript);

    let run = |envelopes: &[_], timed: bool| {
        if timed {
            detect_timed(
                &params,
                &keys.ipk,
                &precredentials[0].a_sig,
                &op,
                &access,
                &active,
                envelopes,
                transcript.verified_coin(),
                &revealed,
                &precredentials[0].pub_attrs,
                &prv,
                prv[0],
                ctx,
                NONCE,
            )
            .0
        } else {
            detect(
                &params,
                &keys.ipk,
                &precredentials[0].a_sig,
                &op,
                &access,
                &active,
                envelopes,
                transcript.verified_coin(),
                &revealed,
                &precredentials[0].pub_attrs,
                &prv,
                prv[0],
                ctx,
                NONCE,
            )
        }
    };

    let mut cases = vec![base.clone()];
    let mut bad_holder = base.clone();
    let envelope = bad_holder
        .iter_mut()
        .find(|item| item.round == 5 && item.sender == 1)
        .unwrap();
    let Ok(DecodedMessage::Round5Holder(response)) = &mut envelope.payload else {
        panic!("holder response expected");
    };
    response.z_e += Fr::one();
    cases.push(bad_holder);

    let mut bad_primary = base;
    let envelope = bad_primary.iter_mut().find(|item| item.round == 3).unwrap();
    let Ok(DecodedMessage::Round3(message)) = &mut envelope.payload else {
        panic!("Round 3 expected");
    };
    message.b_bar += params.g1;
    cases.push(bad_primary);

    for envelopes in cases {
        reset();
        let ordinary = run(&envelopes, false);
        let ordinary_counts = snapshot();
        reset();
        let timed = run(&envelopes, true);
        assert_eq!(timed, ordinary);
        assert_eq!(snapshot(), ordinary_counts);
        assert!(matches!(
            timed,
            DetectOutcome::Pres(_) | DetectOutcome::Abort(_)
        ));
    }
}
