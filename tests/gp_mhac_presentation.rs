use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, UniformRand};
use ark_std::test_rng;
use gp_mhac::access::compile_access;
use gp_mhac::issuance::{cred_iss, holder_verify, iss_keygen, setup, IssuerKeys, Parameters};
use gp_mhac::lsss::{dnf_example, threshold, Lsss};
use gp_mhac::ops::{reset, snapshot, OpCounts};
use gp_mhac::presentation::{
    assemble, cred_pres_with_lsss, round1_holder, round2_open, round3_primary, round4_open,
    round5_holder, round5_primary, transcript_bytes, verify_round4_coin, vf_pres, HolderState,
    Presentation, Round1Message,
};

fn expected_holder(private_count: usize) -> OpCounts {
    OpCounts {
        e1: (2 * private_count + 3) as u64,
        h: 2,
        h_g: 1,
        ..OpCounts::default()
    }
}

fn expected_primary(
    message_count: usize,
    hidden_count: usize,
    active_rows: usize,
    active_holders: usize,
) -> OpCounts {
    OpCounts {
        e1: (message_count + hidden_count + active_rows + 11) as u64,
        h: (active_holders + 5) as u64,
        h_g: 1,
        ..OpCounts::default()
    }
}

fn expected_verifier(message_count: usize) -> OpCounts {
    OpCounts {
        e1: (message_count + 7) as u64,
        pairing: 2,
        h: 1,
        h_g: 1,
        ..OpCounts::default()
    }
}

struct CaseResult {
    params: Parameters,
    keys: IssuerKeys,
    presentation: Presentation,
    revealed: Vec<(usize, Fr)>,
    ctx: Vec<u8>,
    nonce: [u8; 32],
}

fn run_case(
    name: &str,
    lsss: Lsss,
    active_rows: Vec<usize>,
    message_count: usize,
    private_count: usize,
    revealed_count: usize,
    print_anchor: bool,
) -> CaseResult {
    let mut rng = test_rng();
    let params = setup(message_count, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
    let prv: Vec<_> = (0..private_count).collect();
    let rev: Vec<_> = (message_count - revealed_count..message_count).collect();
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let holder_count = lsss.rho.iter().copied().max().unwrap() + 1;
    let access = compile_access(lsss.clone(), holder_count);
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    for (holder, precredential) in precredentials.iter().enumerate() {
        assert!(holder_verify(
            &params,
            &keys.auth_pk,
            &access,
            holder,
            precredential,
            &prv
        ));
    }

    let coefficients = lsss.recon_coeffs(&active_rows).unwrap();
    let active_rows: Vec<_> = coefficients.iter().map(|(row, _)| *row).collect();
    let mut active_holders: Vec<_> = active_rows.iter().map(|&row| lsss.rho[row]).collect();
    active_holders.sort_unstable();
    active_holders.dedup();
    let primary = active_holders[0];
    let ctx = format!("context-{name}").into_bytes();
    let nonce = [0x72; 32];
    let ssid = gp_mhac::presentation::derive_ssid(
        &keys.ipk.header(&ctx),
        &access.asid,
        &precredentials[primary].a_sig,
        &active_rows,
        &rev,
        &nonce,
    );

    let mut role_data: Vec<(usize, Round1Message, HolderState)> = Vec::new();
    for &holder in active_holders.iter().filter(|&&holder| holder != primary) {
        reset();
        let (message, state) = round1_holder(
            &params,
            &precredentials[holder],
            holder,
            &active_rows,
            &coefficients,
            &prv,
            &ctx,
            &ssid,
            &mut rng,
        )
        .unwrap();
        let holder_counts = snapshot();
        assert_eq!(
            holder_counts,
            expected_holder(private_count),
            "non-primary count mismatch for {name}, holder {holder}"
        );
        if print_anchor
            && active_holders
                .iter()
                .copied()
                .find(|candidate| *candidate != primary)
                == Some(holder)
        {
            println!("CredPres (m=16,p=2,|Rev|=8) holder[{holder}] snapshot: {holder_counts:?}");
        }
        role_data.push((holder, message, state));
    }

    // Keep the Primary's counter window open through Rounds 1, 3, and 4.
    reset();
    let (primary_message, primary_holder_state) = round1_holder(
        &params,
        &precredentials[primary],
        primary,
        &active_rows,
        &coefficients,
        &prv,
        &ctx,
        &ssid,
        &mut rng,
    )
    .unwrap();
    role_data.push((primary, primary_message, primary_holder_state));
    role_data.sort_unstable_by_key(|(holder, _, _)| *holder);
    let messages: Vec<_> = role_data
        .iter()
        .map(|(_, message, _)| message.clone())
        .collect();
    let states: Vec<_> = role_data
        .iter()
        .map(|(_, _, state)| state.clone())
        .collect();
    let (openings, round2) = round2_open(&states);
    let (round3, primary_state) = round3_primary(
        &params,
        &precredentials[primary].a_sig,
        &attrs,
        &prv,
        &rev,
        &active_rows,
        &coefficients,
        &messages,
        &openings,
        &ctx,
        &ssid,
        nonce,
        &mut rng,
    )
    .unwrap();
    let seed_openings = round4_open(&states);
    let coin = verify_round4_coin(
        &keys.ipk,
        &messages,
        &seed_openings,
        &active_rows,
        &active_holders,
        &round2,
        &round3,
        &revealed,
        &ctx,
        &ssid,
        nonce,
    )
    .unwrap();
    let mut holder_responses = Vec::new();
    let mut primary_response = None;
    for state in &states {
        if state.opening().holder == primary {
            let (holder_response, extra) = round5_primary(state, &primary_state, &coin);
            holder_responses.push(holder_response);
            primary_response = Some(extra);
        } else {
            holder_responses.push(round5_holder(state, &coin));
        }
    }
    let hidden: Vec<_> = (0..message_count)
        .filter(|index| rev.binary_search(index).is_err())
        .collect();
    let presentation = assemble(
        &round2,
        &round3,
        &coin,
        &holder_responses,
        &primary_response.unwrap(),
        &hidden,
        &prv,
    )
    .unwrap();
    let primary_counts = snapshot();
    assert_eq!(
        primary_counts,
        expected_primary(
            message_count,
            hidden.len(),
            active_rows.len(),
            active_holders.len(),
        ),
        "primary count mismatch for {name}"
    );
    if print_anchor {
        println!("CredPres (m=16,p=2,|Rev|=8) Primary snapshot: {primary_counts:?}");
    }

    assert_eq!(presentation.to_bytes().len(), 352 + 32 * hidden.len());
    reset();
    assert!(vf_pres(
        &params,
        &keys.ipk,
        &presentation,
        &revealed,
        prv[0],
        &ctx,
        nonce
    ));
    let verifier_counts = snapshot();
    assert_eq!(
        verifier_counts,
        expected_verifier(message_count),
        "VfPres count mismatch for {name}"
    );
    if print_anchor {
        println!("CredPres (m=16,p=2,|Rev|=8) VfPres snapshot: {verifier_counts:?}");
    }

    CaseResult {
        params,
        keys,
        presentation,
        revealed,
        ctx,
        nonce,
    }
}

#[test]
fn verification_binds_issuer_authentication_key_context_and_public_parameters() {
    let f = run_case(
        "public-binding",
        threshold(2, 3),
        vec![0, 1],
        6,
        2,
        2,
        false,
    );
    let mut rng = test_rng();
    let independent = iss_keygen(&f.params, &mut rng);
    let other = gp_mhac::issuance::IssuerPublicKey::from_parts(
        &f.params,
        f.keys.x2,
        independent.auth_pk.clone(),
    );
    assert_ne!(other.auth_pk, f.keys.auth_pk);
    assert!(!vf_pres(
        &f.params,
        &other,
        &f.presentation,
        &f.revealed,
        0,
        &f.ctx,
        f.nonce
    ));
    assert!(!vf_pres(
        &f.params,
        &f.keys.ipk,
        &f.presentation,
        &f.revealed,
        0,
        b"unrelated-context",
        f.nonce
    ));
    let pp = setup(6, &mut rng);
    assert!(!vf_pres(
        &pp,
        &f.keys.ipk,
        &f.presentation,
        &f.revealed,
        0,
        &f.ctx,
        f.nonce
    ));
}

#[test]
fn presentation_matrix_counts_sizes_and_verifies() {
    run_case(
        "threshold-8-1-4",
        threshold(3, 5),
        vec![0, 1, 2],
        8,
        1,
        4,
        false,
    );
    run_case(
        "threshold-16-2-8",
        threshold(3, 5),
        vec![0, 1, 2],
        16,
        2,
        8,
        true,
    );
    run_case(
        "threshold-32-4-16",
        threshold(3, 5),
        vec![0, 1, 2],
        32,
        4,
        16,
        false,
    );
    run_case("dnf-16-2-8", dnf_example(), vec![2, 3, 4], 16, 2, 8, false);
    run_case(
        "multi-row-16-2-8",
        Lsss {
            matrix: threshold(3, 4).matrix,
            rho: vec![0, 0, 1, 2],
        },
        vec![0, 1, 2],
        16,
        2,
        8,
        false,
    );
}

fn negative_fixture() -> CaseResult {
    run_case(
        "negative-fixture",
        threshold(3, 5),
        vec![0, 1, 2],
        16,
        2,
        8,
        false,
    )
}

#[test]
fn checked_presentation_decoding_preserves_bytes_and_leaves_verification_to_vf_pres() {
    let f = negative_fixture();
    let verify =
        |p: &Presentation| vf_pres(&f.params, &f.keys.ipk, p, &f.revealed, 0, &f.ctx, f.nonce);
    let encoded = f.presentation.to_bytes();
    let decoded = Presentation::from_bytes_checked(&encoded).unwrap();
    assert_eq!(decoded, f.presentation);
    assert_eq!(decoded.to_bytes(), encoded);
    assert!(verify(&decoded));

    let mut changed_eta = encoded.clone();
    changed_eta[4 * 48] ^= 1;
    let changed = Presentation::from_bytes_checked(&changed_eta).unwrap();
    assert_ne!(changed.eta, decoded.eta);
    assert!(!verify(&changed));

    // Encoding has no hidden-response count; VfPres knows it from the disclosure set.
    let shorter = Presentation::from_bytes_checked(&encoded[..encoded.len() - 32]).unwrap();
    assert_eq!(shorter.z_hidden.len() + 1, decoded.z_hidden.len());
    assert!(!verify(&shorter));
    let mut longer = encoded;
    longer.extend_from_slice(&[0; 32]);
    let longer = Presentation::from_bytes_checked(&longer).unwrap();
    assert_eq!(longer.z_hidden.len(), decoded.z_hidden.len() + 1);
    assert!(!verify(&longer));
}

#[test]
fn checked_presentation_decoding_rejects_truncation_and_partial_response() {
    let full = negative_fixture().presentation.to_bytes();
    for n in [0, 47, 191, 192, 223, 224, 351, 353, full.len() - 1] {
        assert!(
            Presentation::from_bytes_checked(&full[..n]).is_err(),
            "length {n}"
        );
    }
    let mut extra = full;
    extra.push(0);
    assert!(Presentation::from_bytes_checked(&extra).is_err());
}

#[test]
fn checked_presentation_decoding_validates_all_four_group_elements() {
    use ark_bls12_381::{Fq, G1Affine};
    use ark_ff::Zero;
    use ark_serialize::CanonicalSerialize;
    let f = negative_fixture();
    let valid = f.presentation.to_bytes();
    let torsion = G1Affine::new_unchecked(Fq::zero(), Fq::from(2u64));
    assert!(torsion.is_on_curve());
    assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
    let mut torsion_bytes = Vec::new();
    torsion.serialize_compressed(&mut torsion_bytes).unwrap();
    assert_eq!(torsion_bytes.len(), 48);
    let mut infinity = [0u8; 48];
    G1Affine::identity()
        .serialize_compressed(&mut infinity[..])
        .unwrap();
    let mut wrong_sign = infinity;
    wrong_sign[0] |= 0x20;
    let mut wrong_payload = infinity;
    wrong_payload[47] = 1;
    for (slot, offset) in [0, 48, 96, 144].into_iter().enumerate() {
        for invalid in [&torsion_bytes[..], &wrong_sign, &wrong_payload, &[0u8; 48]] {
            let mut bytes = valid.clone();
            bytes[offset..offset + 48].copy_from_slice(invalid);
            assert!(
                Presentation::from_bytes_checked(&bytes).is_err(),
                "point {slot}"
            );
        }
    }
    let mut zero_a = valid;
    zero_a[..48].copy_from_slice(&infinity);
    let p = Presentation::from_bytes_checked(&zero_a).unwrap();
    assert!(p.a_bar.is_zero());
    assert!(!vf_pres(
        &f.params,
        &f.keys.ipk,
        &p,
        &f.revealed,
        0,
        &f.ctx,
        f.nonce
    ));
}

#[test]
fn checked_presentation_decoding_rejects_noncanonical_fixed_and_hidden_scalars() {
    use ark_ff::{BigInteger, PrimeField};
    let f = negative_fixture();
    let valid = f.presentation.to_bytes();
    let modulus = Fr::MODULUS.to_bytes_le();
    assert_eq!(modulus.len(), 32);
    let scalar_start = 4 * 48 + 32;
    let scalar_count = 4 + f.presentation.z_hidden.len();
    assert_eq!(valid.len(), scalar_start + scalar_count * 32);
    for slot in 0..scalar_count {
        let start = scalar_start + slot * 32;
        let mut bytes = valid.clone();
        bytes[start..start + 32].copy_from_slice(&modulus);
        assert!(
            Presentation::from_bytes_checked(&bytes).is_err(),
            "scalar {slot}"
        );
    }
}

#[test]
fn rejects_changed_response() {
    let mut fixture = negative_fixture();
    fixture.presentation.z_first_randomizer += Fr::one();
    assert!(!vf_pres(
        &fixture.params,
        &fixture.keys.ipk,
        &fixture.presentation,
        &fixture.revealed,
        0,
        &fixture.ctx,
        fixture.nonce
    ));
}

#[test]
fn rejects_tampered_coin_fields() {
    let mut eta_fixture = negative_fixture();
    eta_fixture.presentation.eta[0] ^= 1;
    assert!(!vf_pres(
        &eta_fixture.params,
        &eta_fixture.keys.ipk,
        &eta_fixture.presentation,
        &eta_fixture.revealed,
        0,
        &eta_fixture.ctx,
        eta_fixture.nonce
    ));

    let mut challenge_fixture = negative_fixture();
    challenge_fixture.presentation.ch += Fr::one();
    assert!(!vf_pres(
        &challenge_fixture.params,
        &challenge_fixture.keys.ipk,
        &challenge_fixture.presentation,
        &challenge_fixture.revealed,
        0,
        &challenge_fixture.ctx,
        challenge_fixture.nonce
    ));
}

#[test]
fn rejects_changed_revealed_value() {
    let mut fixture = negative_fixture();
    fixture.revealed[0].1 += Fr::one();
    assert!(!vf_pres(
        &fixture.params,
        &fixture.keys.ipk,
        &fixture.presentation,
        &fixture.revealed,
        0,
        &fixture.ctx,
        fixture.nonce
    ));
}

#[test]
fn rejects_random_nym() {
    let mut fixture = negative_fixture();
    let mut rng = test_rng();
    fixture.presentation.nym = G1Projective::rand(&mut rng);
    assert!(!vf_pres(
        &fixture.params,
        &fixture.keys.ipk,
        &fixture.presentation,
        &fixture.revealed,
        0,
        &fixture.ctx,
        fixture.nonce
    ));
}

#[test]
fn orchestrator_returns_complete_transcript() {
    let mut rng = test_rng();
    let params = setup(8, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![0];
    let rev: Vec<_> = (4..8).collect();
    let lsss = threshold(3, 5);
    let access = compile_access(lsss.clone(), 5);
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let (presentation, transcript) = cred_pres_with_lsss(
        &params,
        &keys.ipk,
        &precredentials,
        &attrs,
        &prv,
        &lsss,
        &[0, 1, 2],
        &rev,
        b"orchestrator-context",
        [7u8; 32],
        &mut rng,
    )
    .unwrap();
    assert_eq!(transcript.round1.len(), 3);
    assert_eq!(transcript.openings.len(), 3);
    assert_eq!(transcript.seed_openings.len(), 3);
    assert_eq!(transcript.holder_responses.len(), 3);
    assert_eq!(transcript_bytes(&transcript, 1, 4), 2_336);
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let mut shuffled_seed_openings = transcript.seed_openings.clone();
    shuffled_seed_openings.reverse();
    let shuffled_coin = verify_round4_coin(
        &keys.ipk,
        &transcript.round1,
        &shuffled_seed_openings,
        &[0, 1, 2],
        &transcript.active_holders,
        &transcript.round2,
        &transcript.round3,
        &revealed,
        b"orchestrator-context",
        &transcript.ssid,
        [7u8; 32],
    )
    .unwrap();
    let shuffled_presentation = assemble(
        &transcript.round2,
        &transcript.round3,
        &shuffled_coin,
        &transcript.holder_responses,
        &transcript.primary_response,
        &[0, 1, 2, 3],
        &prv,
    )
    .unwrap();
    assert_eq!(shuffled_presentation.eta, presentation.eta);
    assert_eq!(shuffled_presentation.ch, presentation.ch);
    assert!(vf_pres(
        &params,
        &keys.ipk,
        &presentation,
        &revealed,
        prv[0],
        b"orchestrator-context",
        [7u8; 32]
    ));
}
