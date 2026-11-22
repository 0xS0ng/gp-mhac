use ark_bls12_381::Fr;
use ark_ff::{One, UniformRand, Zero};
use ark_std::test_rng;
use gp_mhac::baselines::tz23::{
    bbs_verify, keygen, pok_prove, pok_verify, setup, sign, Error, Signature,
};
use gp_mhac::ops::{reset, snapshot, OpCounts};

fn expected(e1: u64, e2: u64, pairing: u64, h: u64) -> OpCounts {
    OpCounts {
        e1,
        e2,
        pairing,
        h,
        ..OpCounts::default()
    }
}

#[test]
fn setup_samples_the_two_generators_independently_of_the_message_bases() {
    let mut rng = test_rng();
    let a = setup(3, &mut rng);
    let b = setup(3, &mut rng);
    assert!(!a.g1.is_zero() && !a.g2.is_zero());
    assert!(!b.g1.is_zero() && !b.g2.is_zero());
    assert_ne!(a.g1, b.g1);
    assert_ne!(a.g2, b.g2);
    assert_eq!(a.h, b.h);
}

#[test]
fn matrix_round_trips_counts_and_lengths() {
    for &(message_count, hidden_count) in &[(4usize, 0usize), (4, 4), (16, 8), (32, 32)] {
        let mut rng = test_rng();
        let params = setup(message_count, &mut rng);
        let (secret_key, verification_key) = keygen(&params, &mut rng);
        let messages: Vec<_> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
        let disclosed_count = message_count - hidden_count;
        let disclosed_indices: Vec<_> = (0..disclosed_count).collect();
        let disclosed_messages: Vec<_> = disclosed_indices
            .iter()
            .map(|&index| messages[index])
            .collect();

        reset();
        let signature = sign(&params, &secret_key, &messages, &mut rng).unwrap();
        assert_eq!(
            snapshot(),
            expected((message_count + 1) as u64, 0, 0, 0),
            "Sign count mismatch for (ell, hidden)=({message_count}, {hidden_count})"
        );
        assert_eq!(signature.to_bytes().len(), 80);

        reset();
        assert!(bbs_verify(
            &params,
            &verification_key,
            &messages,
            &signature
        ));
        assert_eq!(
            snapshot(),
            expected(message_count as u64, 1, 2, 0),
            "BbsVerify count mismatch for (ell, hidden)=({message_count}, {hidden_count})"
        );

        reset();
        let proof = pok_prove(
            &params,
            &verification_key,
            &messages,
            &signature,
            &disclosed_indices,
            &mut rng,
        )
        .unwrap();
        let prove_counts = snapshot();
        assert_eq!(
            prove_counts,
            expected((message_count + hidden_count + 5) as u64, 0, 0, 1),
            "PokProve count mismatch for (ell, hidden)=({message_count}, {hidden_count})"
        );
        assert_eq!(proof.to_bytes().len(), 2 * 48 + (hidden_count + 3) * 32);
        if (message_count, hidden_count) == (16, 8) {
            println!("TZ23 (ell=16, hidden=8) PokProve snapshot: {prove_counts:?}");
        }

        reset();
        assert!(pok_verify(
            &params,
            &verification_key,
            &disclosed_indices,
            &disclosed_messages,
            &proof,
        ));
        let verify_counts = snapshot();
        assert_eq!(
            verify_counts,
            expected((message_count + 3) as u64, 0, 2, 1),
            "PokVerify count mismatch for (ell, hidden)=({message_count}, {hidden_count})"
        );
        if (message_count, hidden_count) == (16, 8) {
            println!("TZ23 (ell=16, hidden=8) PokVerify snapshot: {verify_counts:?}");
        }
    }
}

fn fixture() -> (
    gp_mhac::baselines::tz23::Parameters,
    gp_mhac::baselines::tz23::VerificationKey,
    Vec<Fr>,
    Signature,
    Vec<usize>,
    Vec<Fr>,
    gp_mhac::baselines::tz23::PokProof,
) {
    let mut rng = test_rng();
    let params = setup(16, &mut rng);
    let (secret_key, verification_key) = keygen(&params, &mut rng);
    let messages: Vec<_> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
    let signature = sign(&params, &secret_key, &messages, &mut rng).unwrap();
    let disclosed_indices: Vec<_> = (0..8).collect();
    let disclosed_messages = disclosed_indices
        .iter()
        .map(|&index| messages[index])
        .collect();
    let proof = pok_prove(
        &params,
        &verification_key,
        &messages,
        &signature,
        &disclosed_indices,
        &mut rng,
    )
    .unwrap();
    (
        params,
        verification_key,
        messages,
        signature,
        disclosed_indices,
        disclosed_messages,
        proof,
    )
}

#[test]
fn rejects_flipped_hidden_response() {
    let (params, verification_key, _, _, indices, values, mut proof) = fixture();
    proof.u[0] += Fr::one();
    assert!(!pok_verify(
        &params,
        &verification_key,
        &indices,
        &values,
        &proof
    ));
}

#[test]
fn rejects_changed_disclosed_message() {
    let (params, verification_key, _, _, indices, mut values, proof) = fixture();
    values[0] += Fr::one();
    assert!(!pok_verify(
        &params,
        &verification_key,
        &indices,
        &values,
        &proof
    ));
}

#[test]
fn rejects_swapped_a_bar_and_b_bar() {
    let (params, verification_key, _, _, indices, values, mut proof) = fixture();
    std::mem::swap(&mut proof.a_bar, &mut proof.b_bar);
    assert!(!pok_verify(
        &params,
        &verification_key,
        &indices,
        &values,
        &proof
    ));
}

#[test]
fn prover_rejects_identity_signature() {
    let (params, verification_key, messages, mut signature, indices, _, _) = fixture();
    signature.a = Default::default();
    let mut rng = test_rng();
    assert_eq!(
        pok_prove(
            &params,
            &verification_key,
            &messages,
            &signature,
            &indices,
            &mut rng,
        ),
        Err(Error::IdentitySignature)
    );
    assert!(signature.a.is_zero());
}
