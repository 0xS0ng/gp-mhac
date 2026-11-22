use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, UniformRand};
use ark_std::test_rng;
use gp_mhac::access::{compile_access, CompiledAccess, Reconstruction};
use gp_mhac::detect::{
    canonicalize, canonicalize_cached, detect, detect_cached, detect_timed,
    envelopes_from_transcript, AuthenticatedEnvelope, DecodeError, DecodedMessage, DetectOutcome,
};
use gp_mhac::issuance::{cred_iss, iss_keygen, setup, IssuerKeys, Parameters, PreCred};
use gp_mhac::lsss::{threshold, Lsss};
use gp_mhac::ops::{reset, snapshot, OpCounts, SuspendGuard};
use gp_mhac::presentation::{
    assemble, cred_pres, derive_ssid, round1_holder, round2_open, round3_primary, round4_open,
    round5_holder, round5_primary, verify_round4_coin, vf_pres, Transcript, VerifiedCoin,
};
use gp_mhac::primitives::hash::hash_to_g1;
use std::collections::BTreeSet;

const NONCE: [u8; 32] = [0x91; 32];

#[derive(Clone)]
struct Fixture {
    params: Parameters,
    keys: IssuerKeys,
    access: CompiledAccess,
    precredentials: Vec<PreCred>,
    active_rows: Vec<usize>,
    transcript: Transcript,
    envelopes: Vec<AuthenticatedEnvelope>,
    revealed: Vec<(usize, Fr)>,
    prv: Vec<usize>,
    ctx: Vec<u8>,
    op: G1Projective,
    ch: Fr,
}

fn fixture(multi_row: bool) -> Fixture {
    let mut rng = test_rng();
    let params = setup(16, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![0, 1];
    let rev: Vec<_> = (8..16).collect();
    let revealed = rev.iter().map(|&index| (index, attrs[index])).collect();
    let (lsss, active_rows, holder_count, label) = if multi_row {
        (
            Lsss {
                matrix: threshold(3, 4).matrix,
                rho: vec![0, 0, 1, 2],
            },
            vec![0, 1, 2],
            3,
            "multi-row",
        )
    } else {
        (threshold(3, 5), vec![0, 1, 2], 5, "threshold")
    };
    let access = compile_access(lsss.clone(), holder_count);
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let ctx = format!("gp-mhac-detection-{label}").into_bytes();
    let (presentation, transcript) = cred_pres(
        &params,
        &keys.ipk,
        &precredentials,
        &attrs,
        &prv,
        &access,
        &active_rows,
        &rev,
        &ctx,
        NONCE,
        &mut rng,
    )
    .unwrap();
    let envelopes = envelopes_from_transcript(&access, &active_rows, &transcript);
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", &ctx);
    Fixture {
        params,
        keys,
        access,
        precredentials,
        active_rows,
        transcript,
        envelopes,
        revealed,
        prv,
        ctx,
        op,
        ch: presentation.ch,
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_detectors(
    params: &Parameters,
    ipk: &gp_mhac::issuance::IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    rows: &[usize],
    reconstruction: &Reconstruction,
    envelopes: &[AuthenticatedEnvelope],
    coin: &VerifiedCoin,
    revealed: &[(usize, Fr)],
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ctx: &[u8],
    nonce: [u8; 32],
) -> DetectOutcome {
    let expected = {
        let _count = SuspendGuard::new();
        detect(
            params, ipk, a_sig, op, access, rows, envelopes, coin, revealed, pub_attrs, prv, j_pid,
            ctx, nonce,
        )
    };
    let actual = detect_cached(
        params,
        ipk,
        a_sig,
        op,
        access,
        rows,
        reconstruction,
        envelopes,
        coin,
        revealed,
        pub_attrs,
        prv,
        j_pid,
        ctx,
        nonce,
    );
    assert_eq!(actual, expected);
    actual
}

fn detect_fixture(fixture: &Fixture) -> DetectOutcome {
    compare_detectors(
        &fixture.params,
        &fixture.keys.ipk,
        &fixture.precredentials[0].a_sig,
        &fixture.op,
        &fixture.access,
        &fixture.active_rows,
        fixture.transcript.reconstruction().unwrap(),
        &fixture.envelopes,
        fixture.transcript.verified_coin(),
        &fixture.revealed,
        &fixture.precredentials[0].pub_attrs,
        &fixture.prv,
        fixture.prv[0],
        &fixture.ctx,
        NONCE,
    )
}

fn blame(holders: &[usize]) -> DetectOutcome {
    DetectOutcome::Abort(holders.iter().copied().collect::<BTreeSet<_>>())
}

fn holder_response_mut(envelopes: &mut [AuthenticatedEnvelope], holder: usize) -> &mut Fr {
    let envelope = envelopes
        .iter_mut()
        .find(|item| item.round == 5 && item.sender == holder)
        .unwrap();
    match envelope.payload.as_mut().unwrap() {
        DecodedMessage::Round5Holder(response) => &mut response.z_e,
        DecodedMessage::Round5Primary { holder, .. } => &mut holder.z_e,
        _ => panic!("Round-4 response expected"),
    }
}

fn assert_valid_pres(fixture: &Fixture, outcome: DetectOutcome) {
    let DetectOutcome::Pres(presentation) = outcome else {
        panic!("expected honest path acceptance");
    };
    assert!(vf_pres(
        &fixture.params,
        &fixture.keys.ipk,
        &presentation,
        &fixture.revealed,
        fixture.prv[0],
        &fixture.ctx,
        NONCE
    ));
}

#[test]
fn honest_path_has_vf_pres_counts_only() {
    for multi_row in [false, true] {
        let fixture = fixture(multi_row);
        reset();
        let outcome = detect_fixture(&fixture);
        assert_eq!(
            snapshot(),
            OpCounts {
                e1: 23,
                pairing: 2,
                h: 1,
                h_g: 1,
                ..OpCounts::default()
            }
        );
        assert_valid_pres(&fixture, outcome);
    }
}

#[test]
fn timed_honest_path_has_only_terminal_segment() {
    let fixture = fixture(false);
    reset();
    let (outcome, timing) = detect_timed(
        &fixture.params,
        &fixture.keys.ipk,
        &fixture.precredentials[0].a_sig,
        &fixture.op,
        &fixture.access,
        &fixture.active_rows,
        &fixture.envelopes,
        fixture.transcript.verified_coin(),
        &fixture.revealed,
        &fixture.precredentials[0].pub_attrs,
        &fixture.prv,
        fixture.prv[0],
        &fixture.ctx,
        NONCE,
    );
    assert!(matches!(outcome, DetectOutcome::Pres(_)));
    assert_eq!(timing.row_auth_ns, 0);
    assert_eq!(timing.relations_ns, 0);
    assert_eq!(timing.lifting_ns, 0);
    assert!(timing.terminal_ns > 0);
    assert!(timing.total_ns >= timing.terminal_ns);
}

#[test]
fn invalid_holder_response_enters_blame_path() {
    let mut fixture = fixture(false);
    let holder = 1;
    *holder_response_mut(&mut fixture.envelopes, holder) += Fr::one();
    assert_eq!(detect_fixture(&fixture), blame(&[holder]));
}

#[test]
fn primary_round3_or_round5_tamper_blames_primary() {
    let fixture = fixture(false);
    let primary = 0;

    let mut bad_round3 = fixture.clone();
    let envelope = bad_round3
        .envelopes
        .iter_mut()
        .find(|item| item.round == 3)
        .unwrap();
    let Ok(DecodedMessage::Round3(message)) = &mut envelope.payload else {
        panic!("Round 3 expected");
    };
    message.b_bar += bad_round3.params.g1;
    assert_eq!(detect_fixture(&bad_round3), blame(&[primary]));

    let mut bad_first_message = fixture.clone();
    let envelope = bad_first_message
        .envelopes
        .iter_mut()
        .find(|item| item.round == 3)
        .unwrap();
    let Ok(DecodedMessage::Round3(message)) = &mut envelope.payload else {
        panic!("Round 3 expected");
    };
    message.u_ii += bad_first_message.params.g1;
    let bad_round3 = message.clone();
    let new_coin = verify_round4_coin(
        &bad_first_message.keys.ipk,
        &bad_first_message.transcript.round1,
        &bad_first_message.transcript.seed_openings,
        &bad_first_message.active_rows,
        &bad_first_message.transcript.active_holders,
        &bad_first_message.transcript.round2,
        &bad_round3,
        &bad_first_message.revealed,
        &bad_first_message.ctx,
        &bad_first_message.transcript.ssid,
        NONCE,
    )
    .unwrap();
    let hidden: Vec<_> = (0..bad_first_message.params.h.len())
        .filter(|index| {
            bad_first_message
                .revealed
                .binary_search_by_key(index, |item| item.0)
                .is_err()
        })
        .collect();
    let new_ch = assemble(
        &bad_first_message.transcript.round2,
        &bad_round3,
        &new_coin,
        &bad_first_message.transcript.holder_responses,
        &bad_first_message.transcript.primary_response,
        &hidden,
        &bad_first_message.prv,
    )
    .unwrap()
    .ch;
    let delta = new_ch - bad_first_message.ch;
    let coefficients = bad_first_message
        .access
        .lsss
        .recon_coeffs(&bad_first_message.active_rows)
        .unwrap();
    for envelope in bad_first_message
        .envelopes
        .iter_mut()
        .filter(|item| item.round == 5)
    {
        let holder_response = match envelope.payload.as_mut().unwrap() {
            DecodedMessage::Round5Holder(holder) => holder,
            DecodedMessage::Round5Primary { holder, .. } => holder,
            _ => unreachable!(),
        };
        let credential = &bad_first_message.precredentials[holder_response.holder];
        let mut e_hat = Fr::default();
        let mut a_hats = vec![Fr::default(); bad_first_message.prv.len()];
        for row in &credential.rows {
            if let Some((_, omega)) = coefficients.iter().find(|(index, _)| *index == row.index) {
                e_hat += *omega * row.e_share;
                for (acc, share) in a_hats.iter_mut().zip(&row.prv_shares) {
                    *acc += *omega * share;
                }
            }
        }
        holder_response.z_e += delta * e_hat;
        for ((_, response), share) in holder_response.z_prv.iter_mut().zip(a_hats) {
            *response += delta * share;
        }
    }
    let outcome = compare_detectors(
        &bad_first_message.params,
        &bad_first_message.keys.ipk,
        &bad_first_message.precredentials[primary].a_sig,
        &bad_first_message.op,
        &bad_first_message.access,
        &bad_first_message.active_rows,
        bad_first_message.transcript.reconstruction().unwrap(),
        &bad_first_message.envelopes,
        &new_coin,
        &bad_first_message.revealed,
        &bad_first_message.precredentials[primary].pub_attrs,
        &bad_first_message.prv,
        bad_first_message.prv[0],
        &bad_first_message.ctx,
        NONCE,
    );
    assert_eq!(outcome, blame(&[primary]));

    let mut bad_response = fixture;
    let envelope = bad_response
        .envelopes
        .iter_mut()
        .find(|item| item.round == 5 && item.sender == primary)
        .unwrap();
    let Ok(DecodedMessage::Round5Primary { primary, .. }) = &mut envelope.payload else {
        panic!("Primary response expected");
    };
    primary.z_first_randomizer += Fr::one();
    assert_eq!(detect_fixture(&bad_response), blame(&[0]));
}

#[test]
fn round4_seed_faults_stop_before_responses_and_blame_the_sender() {
    let fixture = fixture(false);
    let holder = 1usize;

    for mode in ["missing", "duplicate", "invalid"] {
        let mut envelopes: Vec<_> = fixture
            .envelopes
            .iter()
            .filter(|envelope| envelope.round <= 4)
            .cloned()
            .collect();
        match mode {
            "missing" => envelopes.retain(|item| !(item.round == 4 && item.sender == holder)),
            "duplicate" => {
                let copied = envelopes
                    .iter()
                    .find(|item| item.round == 4 && item.sender == holder)
                    .unwrap()
                    .clone();
                envelopes.push(copied);
            }
            "invalid" => {
                let envelope = envelopes
                    .iter_mut()
                    .find(|item| item.round == 4 && item.sender == holder)
                    .unwrap();
                let Ok(DecodedMessage::Round4Seed(opening)) = &mut envelope.payload else {
                    unreachable!()
                };
                opening.randomness[0] ^= 1;
            }
            _ => unreachable!(),
        }
        assert!(envelopes.iter().all(|envelope| envelope.round < 5));
        let result = canonicalize(
            &fixture.access,
            &fixture.active_rows,
            &envelopes,
            &fixture.revealed,
            &fixture.prv,
            fixture.params.h.len(),
            &fixture.transcript.ssid,
        );
        assert_eq!(
            result,
            canonicalize_cached(
                &fixture.access,
                &fixture.active_rows,
                fixture.transcript.reconstruction().unwrap(),
                &envelopes,
                &fixture.revealed,
                &fixture.prv,
                fixture.params.h.len(),
                &fixture.transcript.ssid
            )
        );
        assert_eq!(result.first_bad_round, Some(4), "mode={mode}");
        assert_eq!(
            result.structural_blame,
            BTreeSet::from([holder]),
            "mode={mode}"
        );
    }
}

#[test]
fn evidence_only_tampering_is_accepted_when_presentation_remains_valid() {
    let fixture = fixture(false);

    let mut bad_tag = fixture.clone();
    let envelope = bad_tag
        .envelopes
        .iter_mut()
        .find(|item| item.round == 1 && item.sender == 1)
        .unwrap();
    let Ok(DecodedMessage::Round1(message)) = &mut envelope.payload else {
        panic!("Round 1 expected");
    };
    message.rows[0].tag.response += Fr::one();
    assert_valid_pres(&bad_tag, detect_fixture(&bad_tag));

    let mut bad_opening = fixture.clone();
    let envelope = bad_opening
        .envelopes
        .iter_mut()
        .find(|item| item.round == 2 && item.sender == 1)
        .unwrap();
    let Ok(DecodedMessage::Round2(opening)) = &mut envelope.payload else {
        panic!("Round 2 expected");
    };
    opening.c_hat += bad_opening.params.g1;
    assert_valid_pres(&bad_opening, detect_fixture(&bad_opening));

    let mut bad_lift = fixture;
    let envelope = bad_lift
        .envelopes
        .iter_mut()
        .find(|item| item.round == 3)
        .unwrap();
    let Ok(DecodedMessage::Round3(message)) = &mut envelope.payload else {
        panic!("Round 3 expected");
    };
    message.lift.z += Fr::one();
    assert_valid_pres(&bad_lift, detect_fixture(&bad_lift));
}

#[test]
fn round2_silence_does_not_blame_later_honest_senders() {
    let mut fixture = fixture(false);
    let holder = 1;
    fixture
        .envelopes
        .retain(|item| item.round < 2 || !(item.round == 2 && item.sender == holder));
    fixture.envelopes.retain(|item| item.round < 3);
    assert_eq!(detect_fixture(&fixture), blame(&[holder]));
}

#[test]
fn structural_faults_are_attributed_by_authenticated_sender() {
    let fixture = fixture(false);
    let mut duplicate = fixture.clone();
    let copied = duplicate
        .envelopes
        .iter()
        .find(|item| item.round == 2 && item.sender == 1)
        .unwrap()
        .clone();
    duplicate.envelopes.push(copied);
    assert_eq!(detect_fixture(&duplicate), blame(&[1]));

    let mut undecodable = fixture.clone();
    let envelope = undecodable
        .envelopes
        .iter_mut()
        .find(|item| item.round == 2 && item.sender == 1)
        .unwrap();
    envelope.payload = Err(DecodeError::Malformed);
    assert_eq!(detect_fixture(&undecodable), blame(&[1]));

    let mut two_faults = fixture;
    let duplicate = two_faults
        .envelopes
        .iter()
        .find(|item| item.round == 2 && item.sender == 1)
        .unwrap()
        .clone();
    two_faults.envelopes.push(duplicate);
    let envelope = two_faults
        .envelopes
        .iter_mut()
        .find(|item| item.round == 2 && item.sender == 2)
        .unwrap();
    envelope.payload = Err(DecodeError::Malformed);
    assert_eq!(detect_fixture(&two_faults), blame(&[1, 2]));
}

#[test]
fn envelope_role_and_sender_faults_are_structural() {
    let fixture = fixture(false);

    let mut wrong_variant = fixture.clone();
    let envelope = wrong_variant
        .envelopes
        .iter_mut()
        .find(|item| item.round == 2 && item.sender == 1)
        .unwrap();
    let opening = match envelope.payload.clone().unwrap() {
        DecodedMessage::Round2(opening) => opening,
        _ => unreachable!(),
    };
    envelope.payload = Ok(DecodedMessage::Round5Holder(
        gp_mhac::presentation::HolderResponse {
            holder: opening.holder,
            z_e: Fr::default(),
            z_prv: vec![(0, Fr::default()), (1, Fr::default())],
        },
    ));
    assert_eq!(detect_fixture(&wrong_variant), blame(&[1]));

    let mut non_active = fixture.clone();
    non_active.envelopes.push(AuthenticatedEnvelope {
        round: 2,
        sender: 4,
        payload: Err(DecodeError::Malformed),
    });
    assert_eq!(detect_fixture(&non_active), blame(&[4]));

    let mut non_primary_extra = fixture.clone();
    let primary_payload = non_primary_extra
        .envelopes
        .iter()
        .find(|item| item.round == 5 && item.sender == 0)
        .unwrap()
        .payload
        .clone()
        .unwrap();
    let DecodedMessage::Round5Primary { primary, .. } = primary_payload else {
        unreachable!()
    };
    let envelope = non_primary_extra
        .envelopes
        .iter_mut()
        .find(|item| item.round == 5 && item.sender == 1)
        .unwrap();
    let holder = match envelope.payload.clone().unwrap() {
        DecodedMessage::Round5Holder(holder) => holder,
        _ => unreachable!(),
    };
    envelope.payload = Ok(DecodedMessage::Round5Primary { holder, primary });
    assert_eq!(detect_fixture(&non_primary_extra), blame(&[1]));

    let mut primary_bare = fixture.clone();
    let envelope = primary_bare
        .envelopes
        .iter_mut()
        .find(|item| item.round == 5 && item.sender == 0)
        .unwrap();
    let holder = match envelope.payload.clone().unwrap() {
        DecodedMessage::Round5Primary { holder, .. } => holder,
        _ => unreachable!(),
    };
    envelope.payload = Ok(DecodedMessage::Round5Holder(holder));
    assert_eq!(detect_fixture(&primary_bare), blame(&[0]));

    let mut sender_mismatch = fixture;
    let envelope = sender_mismatch
        .envelopes
        .iter_mut()
        .find(|item| item.round == 2 && item.sender == 1)
        .unwrap();
    let Ok(DecodedMessage::Round2(opening)) = &mut envelope.payload else {
        unreachable!()
    };
    opening.holder = 2;
    assert_eq!(detect_fixture(&sender_mismatch), blame(&[1]));
}

#[test]
fn cached_transcript_role_fields_are_not_trusted() {
    let fixture = fixture(false);
    let mut tampered = fixture.transcript.clone();
    tampered.primary = 4;
    tampered.active_rows = vec![3, 4];
    tampered.active_holders = vec![3, 4];
    assert_eq!(
        envelopes_from_transcript(&fixture.access, &fixture.active_rows, &tampered),
        fixture.envelopes
    );
}

#[test]
fn consistent_d_factor_substitution_blames_the_substituting_holder() {
    let mut rng = test_rng();
    let params = setup(16, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![0, 1];
    let rev: Vec<_> = (8..16).collect();
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let access = compile_access(threshold(3, 5), 5);
    let active = vec![0, 1, 2];
    let reconstruction = access.reconstruct(&active).unwrap();
    let sparse = reconstruction.coefficients();
    let coefficients: Vec<_> = active
        .iter()
        .map(|&row| {
            let value = sparse
                .iter()
                .find(|(index, _)| *index == row)
                .map(|(_, value)| *value)
                .unwrap_or_default();
            (row, value)
        })
        .collect();
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let ctx = b"gp-mhac-d-prime";
    let nonce = [0xD7; 32];
    let ssid = derive_ssid(
        &keys.ipk.header(ctx),
        &access.asid,
        &precredentials[0].a_sig,
        &active,
        &rev,
        &nonce,
    );

    let mut messages = Vec::new();
    let mut states = Vec::new();
    for (holder, precredential) in precredentials.iter().enumerate().take(3) {
        let (message, state) = round1_holder(
            &params,
            precredential,
            holder,
            &active,
            &coefficients,
            &prv,
            ctx,
            &ssid,
            &mut rng,
        )
        .unwrap();
        messages.push(message);
        states.push(state);
    }
    let (openings, round2) = round2_open(&states);
    let culprit = 1usize;
    let row_index = messages[culprit].rows[0].index;
    let omega = coefficients
        .iter()
        .find(|(row, _)| *row == row_index)
        .unwrap()
        .1;
    let shift = Fr::one();
    messages[culprit].rows[0].d_factor += gp_mhac::ops::g1_mul(&precredentials[0].a_sig, &shift);

    let (round3, primary_state) = round3_primary(
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
        &active,
        &messages
            .iter()
            .map(|message| message.holder)
            .collect::<Vec<_>>(),
        &round2,
        &round3,
        &revealed,
        ctx,
        &ssid,
        nonce,
    )
    .unwrap();
    let mut responses = Vec::new();
    let mut primary_response = None;
    for (holder, state) in states.iter().enumerate() {
        if holder == 0 {
            let (response, extra) = round5_primary(state, &primary_state, &coin);
            responses.push(response);
            primary_response = Some(extra);
        } else {
            responses.push(round5_holder(state, &coin));
        }
    }
    let hidden: Vec<_> = (0..params.h.len())
        .filter(|index| rev.binary_search(index).is_err())
        .collect();
    let honest_presentation = assemble(
        &round2,
        &round3,
        &coin,
        &responses,
        primary_response.as_ref().unwrap(),
        &hidden,
        &prv,
    )
    .unwrap();
    responses[culprit].z_e -= honest_presentation.ch * omega * shift;

    let mut envelopes = Vec::new();
    for message in messages {
        envelopes.push(AuthenticatedEnvelope {
            round: 1,
            sender: message.holder,
            payload: Ok(DecodedMessage::Round1(message)),
        });
    }
    for opening in openings {
        envelopes.push(AuthenticatedEnvelope {
            round: 2,
            sender: opening.holder,
            payload: Ok(DecodedMessage::Round2(opening)),
        });
    }
    envelopes.push(AuthenticatedEnvelope {
        round: 3,
        sender: 0,
        payload: Ok(DecodedMessage::Round3(round3)),
    });
    for opening in seed_openings {
        envelopes.push(AuthenticatedEnvelope {
            round: 4,
            sender: opening.holder,
            payload: Ok(DecodedMessage::Round4Seed(opening)),
        });
    }
    for response in responses {
        let payload = if response.holder == 0 {
            DecodedMessage::Round5Primary {
                holder: response,
                primary: primary_response.clone().unwrap(),
            }
        } else {
            DecodedMessage::Round5Holder(response)
        };
        let sender = match &payload {
            DecodedMessage::Round5Primary { holder, .. } | DecodedMessage::Round5Holder(holder) => {
                holder.holder
            }
            _ => unreachable!(),
        };
        envelopes.push(AuthenticatedEnvelope {
            round: 5,
            sender,
            payload: Ok(payload),
        });
    }
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", ctx);
    let outcome = compare_detectors(
        &params,
        &keys.ipk,
        &precredentials[0].a_sig,
        &op,
        &access,
        &active,
        &reconstruction,
        &envelopes,
        &coin,
        &revealed,
        &precredentials[0].pub_attrs,
        &prv,
        prv[0],
        ctx,
        nonce,
    );
    assert_eq!(outcome, blame(&[culprit]));
}
