//! GP-MHAC detector W: Canon orders authenticated messages; CheckPrefix checks a blocked transcript.
//! For a complete transcript, W runs Assemble and VfPres before taking the blame path.

use super::access::{CompiledAccess, Reconstruction};
use super::issuance::{row_tag_message, IssuerPublicKey, Parameters};
use super::presentation::{
    assemble, derive_ssid, dleq_challenge, vf_pres, HolderResponse, Presentation, PrimaryResponse,
    Round1Message, Round1Opening, Round2Public, Round3Message, SeedOpening, Transcript,
    VerifiedCoin,
};
use crate::ops;
use crate::primitives::auth::{self, PublicKey};
use crate::primitives::hash::open_seed;
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::Zero;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// Detector verdict for a session, or a caller error before evaluating any holder's evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectOutcome {
    Pres(Box<Presentation>),
    Abort(BTreeSet<usize>),
    /// The public parameters do not match the issuer public key.
    ParameterMismatch,
}

/// Elapsed nanoseconds in detector checks and in the complete invocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DetectTiming {
    pub row_auth_ns: u128,
    pub relations_ns: u128,
    pub lifting_ns: u128,
    pub terminal_ns: u128,
    pub total_ns: u128,
}

/// The received payload has no valid protocol decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Malformed,
}

/// Typed payload decoded from an authenticated round message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum DecodedMessage {
    Round1(Round1Message),
    Round2(Round1Opening),
    Round3(Round3Message),
    Round4Seed(SeedOpening),
    Round5Holder(HolderResponse),
    Round5Primary {
        holder: HolderResponse,
        primary: PrimaryResponse,
    },
}

/// Transport-authenticated sender and round, with the result of decoding the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedEnvelope {
    pub round: u8,
    pub sender: usize,
    pub payload: Result<DecodedMessage, DecodeError>,
}

/// Complete, sender-ordered messages for the selected reconstruction rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTranscript {
    pub active_rows: Vec<usize>,
    pub active_holders: Vec<usize>,
    pub primary: usize,
    pub round1: Vec<Round1Message>,
    pub openings: Vec<Round1Opening>,
    pub round3: Round3Message,
    pub seed_openings: Vec<SeedOpening>,
    pub holder_responses: Vec<HolderResponse>,
    pub primary_response: PrimaryResponse,
}

/// Structurally accepted messages preceding the first invalid round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanonicalPrefix {
    pub round1: Vec<Round1Message>,
    pub openings: Vec<Round1Opening>,
    pub round3: Option<Round3Message>,
    pub seed_openings: Vec<SeedOpening>,
}

/// Full transcript or blocking round, plus the accepted prefix and structural blame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canonicalization {
    pub transcript: Option<CanonicalTranscript>,
    pub prefix: CanonicalPrefix,
    pub first_bad_round: Option<u8>,
    pub structural_blame: BTreeSet<usize>,
}

fn coefficient_for(row: usize, coefficients: &[(usize, Fr)]) -> Fr {
    coefficients
        .iter()
        .find(|(index, _)| *index == row)
        .map(|(_, coefficient)| *coefficient)
        .unwrap_or_else(Fr::zero)
}

fn strictly_ascending(values: &[usize]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn hidden_indices(message_count: usize, revealed: &[(usize, Fr)]) -> Option<Vec<usize>> {
    if revealed.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || revealed.iter().any(|(index, _)| *index >= message_count)
    {
        return None;
    }
    let revealed_indices: Vec<_> = revealed.iter().map(|(index, _)| *index).collect();
    Some(
        (0..message_count)
            .filter(|index| revealed_indices.binary_search(index).is_err())
            .collect(),
    )
}

fn exact_response_indices(response: &HolderResponse, prv: &[usize]) -> bool {
    response.z_prv.len() == prv.len()
        && response
            .z_prv
            .iter()
            .zip(prv)
            .all(|((index, _), expected)| index == expected)
}

fn exact_primary_indices(response: &PrimaryResponse, expected: &[usize]) -> bool {
    response.z_other.len() == expected.len()
        && response
            .z_other
            .iter()
            .zip(expected)
            .all(|((index, _), expected)| index == expected)
}

fn envelopes_for_round(
    envelopes: &[AuthenticatedEnvelope],
    round: u8,
) -> BTreeMap<usize, Vec<&AuthenticatedEnvelope>> {
    let mut grouped = BTreeMap::<usize, Vec<_>>::new();
    for envelope in envelopes.iter().filter(|envelope| envelope.round == round) {
        grouped.entry(envelope.sender).or_default().push(envelope);
    }
    grouped
}

fn structural_round(
    grouped: &BTreeMap<usize, Vec<&AuthenticatedEnvelope>>,
    expected: &[usize],
) -> BTreeSet<usize> {
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    let mut blame = BTreeSet::new();
    for (&sender, messages) in grouped {
        if !expected.contains(&sender) || messages.len() != 1 {
            blame.insert(sender);
        }
    }
    for &sender in &expected {
        if grouped.get(&sender).map_or(0, Vec::len) != 1 {
            blame.insert(sender);
        }
    }
    blame
}

fn reconstruction_for<'a>(
    access: &CompiledAccess,
    rows: &[usize],
    cached: Option<&'a Reconstruction>,
) -> Cow<'a, Reconstruction> {
    if let Some(witness) = cached {
        assert!(
            witness.matches(access) && witness.covers(rows),
            "R_S must match the reconstruction"
        );
        Cow::Borrowed(witness)
    } else {
        Cow::Owned(access.reconstruct(rows).expect("R_S must reconstruct"))
    }
}

/// Orders envelopes by their expected slots and returns the first structurally invalid round, or a complete transcript.
#[allow(clippy::too_many_arguments)]
pub fn canonicalize(
    access: &CompiledAccess,
    r_s: &[usize],
    envelopes: &[AuthenticatedEnvelope],
    revealed: &[(usize, Fr)],
    prv: &[usize],
    message_count: usize,
    ssid: &[u8],
) -> Canonicalization {
    let witness = reconstruction_for(access, r_s, None);
    canonicalize_inner(
        access,
        witness.rows(),
        envelopes,
        revealed,
        prv,
        message_count,
        ssid,
        true,
    )
}

/// Checks all envelope slots and openings using the holder's local row witness.
#[allow(clippy::too_many_arguments)]
pub fn canonicalize_cached(
    access: &CompiledAccess,
    r_s: &[usize],
    reconstruction: &Reconstruction,
    envelopes: &[AuthenticatedEnvelope],
    revealed: &[(usize, Fr)],
    prv: &[usize],
    message_count: usize,
    ssid: &[u8],
) -> Canonicalization {
    let witness = reconstruction_for(access, r_s, Some(reconstruction));
    canonicalize_inner(
        access,
        witness.rows(),
        envelopes,
        revealed,
        prv,
        message_count,
        ssid,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn canonicalize_inner(
    access: &CompiledAccess,
    r_s: &[usize],
    envelopes: &[AuthenticatedEnvelope],
    revealed: &[(usize, Fr)],
    prv: &[usize],
    message_count: usize,
    ssid: &[u8],
    verify_seed_openings: bool,
) -> Canonicalization {
    assert!(
        !prv.is_empty() && strictly_ascending(prv),
        "Prv must be canonical"
    );
    let hidden = hidden_indices(message_count, revealed).expect("Rev must be canonical");
    let other_hidden: Vec<_> = hidden
        .iter()
        .copied()
        .filter(|index| prv.binary_search(index).is_err())
        .collect();
    let mut active_holders: Vec<_> = r_s.iter().map(|&row| access.lsss.rho[row]).collect();
    active_holders.sort_unstable();
    active_holders.dedup();
    let primary = active_holders[0];
    let mut prefix = CanonicalPrefix::default();

    let invalid_round_senders: BTreeSet<_> = envelopes
        .iter()
        .filter(|item| !(1..=5).contains(&item.round))
        .map(|item| item.sender)
        .collect();
    if !invalid_round_senders.is_empty() {
        return Canonicalization {
            transcript: None,
            prefix,
            first_bad_round: Some(1),
            structural_blame: invalid_round_senders,
        };
    }

    // Round 1: one commitment message per active holder.
    let grouped = envelopes_for_round(envelopes, 1);
    let mut blame = structural_round(&grouped, &active_holders);
    let mut round1 = Vec::new();
    for &sender in &active_holders {
        if let Some(messages) = grouped.get(&sender).filter(|messages| messages.len() == 1) {
            match &messages[0].payload {
                Ok(DecodedMessage::Round1(message))
                    if message.holder == sender
                        && message
                            .rows
                            .windows(2)
                            .all(|pair| pair[0].index < pair[1].index)
                        && r_s
                            .iter()
                            .filter(|&&row| access.lsss.rho[row] == sender)
                            .all(|required| {
                                message.rows.iter().any(|row| row.index == *required)
                            }) =>
                {
                    round1.push(message.clone())
                }
                _ => {
                    blame.insert(sender);
                }
            }
        }
    }
    if !blame.is_empty() {
        return Canonicalization {
            transcript: None,
            prefix,
            first_bad_round: Some(1),
            structural_blame: blame,
        };
    }
    prefix.round1 = round1.clone();

    // Round 2: one opening per active holder.
    let grouped = envelopes_for_round(envelopes, 2);
    let mut blame = structural_round(&grouped, &active_holders);
    let mut openings = Vec::new();
    for &sender in &active_holders {
        if let Some(messages) = grouped.get(&sender).filter(|messages| messages.len() == 1) {
            match &messages[0].payload {
                Ok(DecodedMessage::Round2(opening)) if opening.holder == sender => {
                    openings.push(opening.clone())
                }
                _ => {
                    blame.insert(sender);
                }
            }
        }
    }
    if !blame.is_empty() {
        return Canonicalization {
            transcript: None,
            prefix,
            first_bad_round: Some(2),
            structural_blame: blame,
        };
    }
    prefix.openings = openings.clone();

    // Round 3: exactly one Primary message.
    let grouped = envelopes_for_round(envelopes, 3);
    let mut blame = structural_round(&grouped, &[primary]);
    let round3 =
        if let Some(messages) = grouped.get(&primary).filter(|messages| messages.len() == 1) {
            match &messages[0].payload {
                Ok(DecodedMessage::Round3(message)) => Some(message.clone()),
                _ => {
                    blame.insert(primary);
                    None
                }
            }
        } else {
            None
        };
    if !blame.is_empty() {
        return Canonicalization {
            transcript: None,
            prefix,
            first_bad_round: Some(3),
            structural_blame: blame,
        };
    }
    prefix.round3 = round3.clone();

    // Round 4: one seed opening per active holder.
    let grouped = envelopes_for_round(envelopes, 4);
    let mut blame = structural_round(&grouped, &active_holders);
    let mut seed_openings = Vec::new();
    for &sender in &active_holders {
        if let Some(messages) = grouped.get(&sender).filter(|messages| messages.len() == 1) {
            match &messages[0].payload {
                Ok(DecodedMessage::Round4Seed(opening))
                    if opening.holder == sender
                        && round1
                            .iter()
                            .find(|message| message.holder == sender)
                            .is_some_and(|message| {
                                !verify_seed_openings
                                    || open_seed(
                                        &message.seed_commitment,
                                        ssid,
                                        sender as u64,
                                        opening.kappa,
                                        opening.randomness,
                                    )
                            }) =>
                {
                    seed_openings.push(opening.clone());
                }
                _ => {
                    blame.insert(sender);
                }
            }
        }
    }
    if !blame.is_empty() {
        return Canonicalization {
            transcript: None,
            prefix,
            first_bad_round: Some(4),
            structural_blame: blame,
        };
    }
    prefix.seed_openings = seed_openings.clone();

    // Round 5: holder responses, with the Primary response in the Primary envelope.
    let grouped = envelopes_for_round(envelopes, 5);
    let mut blame = structural_round(&grouped, &active_holders);
    let mut holder_responses = Vec::new();
    let mut primary_response = None;
    for &sender in &active_holders {
        if let Some(messages) = grouped.get(&sender).filter(|messages| messages.len() == 1) {
            let valid = match &messages[0].payload {
                Ok(DecodedMessage::Round5Primary {
                    holder,
                    primary: extra,
                }) if sender == primary
                    && holder.holder == sender
                    && exact_response_indices(holder, prv)
                    && exact_primary_indices(extra, &other_hidden) =>
                {
                    holder_responses.push(holder.clone());
                    primary_response = Some(extra.clone());
                    true
                }
                Ok(DecodedMessage::Round5Holder(holder))
                    if sender != primary
                        && holder.holder == sender
                        && exact_response_indices(holder, prv) =>
                {
                    holder_responses.push(holder.clone());
                    true
                }
                _ => false,
            };
            if !valid {
                blame.insert(sender);
            }
        }
    }
    if !blame.is_empty() {
        return Canonicalization {
            transcript: None,
            prefix,
            first_bad_round: Some(5),
            structural_blame: blame,
        };
    }

    Canonicalization {
        transcript: Some(CanonicalTranscript {
            active_rows: r_s.to_vec(),
            active_holders,
            primary,
            round1,
            openings,
            round3: round3.expect("validated Round 3"),
            seed_openings,
            holder_responses,
            primary_response: primary_response.expect("validated Primary response"),
        }),
        prefix,
        first_bad_round: None,
        structural_blame: BTreeSet::new(),
    }
}

/// Converts an honest in-memory transcript to authenticated envelopes. Detection
/// never trusts the transcript's cached active-set or Primary fields.
pub fn envelopes_from_transcript(
    access: &CompiledAccess,
    r_s: &[usize],
    transcript: &Transcript,
) -> Vec<AuthenticatedEnvelope> {
    let witness = reconstruction_for(access, r_s, transcript.reconstruction());
    let primary = witness
        .rows()
        .iter()
        .map(|&row| access.lsss.rho[row])
        .min()
        .expect("nonempty R_S");
    let mut envelopes = Vec::new();
    for message in &transcript.round1 {
        envelopes.push(AuthenticatedEnvelope {
            round: 1,
            sender: message.holder,
            payload: Ok(DecodedMessage::Round1(message.clone())),
        });
    }
    for opening in &transcript.openings {
        envelopes.push(AuthenticatedEnvelope {
            round: 2,
            sender: opening.holder,
            payload: Ok(DecodedMessage::Round2(opening.clone())),
        });
    }
    envelopes.push(AuthenticatedEnvelope {
        round: 3,
        sender: primary,
        payload: Ok(DecodedMessage::Round3(transcript.round3.clone())),
    });
    for opening in &transcript.seed_openings {
        envelopes.push(AuthenticatedEnvelope {
            round: 4,
            sender: opening.holder,
            payload: Ok(DecodedMessage::Round4Seed(opening.clone())),
        });
    }
    for response in &transcript.holder_responses {
        let payload = if response.holder == primary {
            DecodedMessage::Round5Primary {
                holder: response.clone(),
                primary: transcript.primary_response.clone(),
            }
        } else {
            DecodedMessage::Round5Holder(response.clone())
        };
        envelopes.push(AuthenticatedEnvelope {
            round: 5,
            sender: response.holder,
            payload: Ok(payload),
        });
    }
    envelopes
}

fn check_rows(
    auth_pk: &PublicKey,
    access: &CompiledAccess,
    active_rows: &[usize],
    a_sig: &G1Projective,
    pub_attrs: &[(usize, Fr)],
    round1: &[Round1Message],
    blame: &mut BTreeSet<usize>,
) {
    for message in round1 {
        for row in &message.rows {
            if access.lsss.rho.get(row.index) != Some(&message.holder) {
                blame.insert(message.holder);
                continue;
            }
            if !auth::verify(
                auth_pk,
                &row_tag_message(&access.asid, a_sig, row.index, &row.d_factor, pub_attrs),
                &row.tag,
            ) {
                blame.insert(message.holder);
            }
        }
    }
    for &row_index in active_rows {
        let owner = access.lsss.rho[row_index];
        let count = round1
            .iter()
            .filter(|message| message.holder == owner)
            .flat_map(|message| &message.rows)
            .filter(|row| row.index == row_index)
            .count();
        if count != 1 {
            blame.insert(owner);
        }
    }
}

fn check_openings(
    round1: &[Round1Message],
    openings: &[Round1Opening],
    ssid: &[u8],
    blame: &mut BTreeSet<usize>,
) {
    for opening in openings {
        let valid = round1
            .iter()
            .find(|message| message.holder == opening.holder)
            .is_some_and(|message| opening.verify_commitment(message, ssid));
        if !valid {
            blame.insert(opening.holder);
        }
    }
}

fn check_lifting(
    a_sig: &G1Projective,
    primary: usize,
    openings: &[Round1Opening],
    round3: &Round3Message,
    blame: &mut BTreeSet<usize>,
) {
    let v = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.v);
    let lift = &round3.lift;
    let t1 = ops::g1_mul(a_sig, &lift.z) + ops::g1_mul(&round3.a_bar, &(-lift.c));
    let t2 = ops::g1_mul(&v, &lift.z) + ops::g1_mul(&round3.v_prime, &(-lift.c));
    if lift.c != dleq_challenge(a_sig, &v, &round3.a_bar, &round3.v_prime, &t1, &t2) {
        blame.insert(primary);
    }
}

#[allow(clippy::too_many_arguments)]
fn check_relations(
    params: &Parameters,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    transcript: &CanonicalTranscript,
    prv: &[usize],
    j_pid: usize,
    ch: Fr,
    reconstruction: Option<&Reconstruction>,
    blame: &mut BTreeSet<usize>,
) {
    let fresh;
    let coefficients = if let Some(witness) = reconstruction {
        assert!(
            witness.matches(access) && witness.rows() == transcript.active_rows,
            "reconstruction must match the authenticated access and rows"
        );
        witness.coefficients()
    } else {
        fresh = access
            .lsss
            .recon_coeffs(&transcript.active_rows)
            .expect("validated reconstruction set");
        &fresh
    };
    for &holder in &transcript.active_holders {
        let message = transcript
            .round1
            .iter()
            .find(|message| message.holder == holder)
            .expect("canonical Round 1 message");
        let opening = transcript
            .openings
            .iter()
            .find(|opening| opening.holder == holder)
            .expect("canonical opening");
        let response = transcript
            .holder_responses
            .iter()
            .find(|response| response.holder == holder)
            .expect("canonical response");

        let mut a_hat = -opening.c_hat;
        for row in &message.rows {
            if access.lsss.rho.get(row.index) == Some(&holder)
                && transcript.active_rows.binary_search(&row.index).is_ok()
            {
                a_hat += ops::g1_mul(&row.d_factor, &coefficient_for(row.index, coefficients));
            }
        }
        let relation_a =
            ops::g1_mul(a_sig, &(-response.z_e)) == opening.v + ops::g1_mul(&a_hat, &ch);

        let mut lhs_b = G1Projective::zero();
        for (&attribute, (_, value)) in prv.iter().zip(&response.z_prv) {
            lhs_b += ops::g1_mul(&params.h[attribute], &(-*value));
        }
        let relation_b = lhs_b == opening.u_hat + ops::g1_mul(&opening.c_hat, &(-ch));

        let pid_response = response
            .z_prv
            .iter()
            .find(|(index, _)| *index == j_pid)
            .map(|(_, value)| *value)
            .expect("canonical pid response");
        let relation_c =
            ops::g1_mul(op, &pid_response) == opening.u_prime + ops::g1_mul(&opening.n, &ch);
        if !(relation_a && relation_b && relation_c) {
            blame.insert(holder);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn blame_path_with_ssid(
    params: &Parameters,
    auth_pk: &PublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    transcript: &CanonicalTranscript,
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ssid: &[u8],
    ch: Fr,
    reconstruction: Option<&Reconstruction>,
    timing: &mut DetectTiming,
) -> BTreeSet<usize> {
    let mut blame = BTreeSet::new();
    let start = Instant::now();
    check_rows(
        auth_pk,
        access,
        &transcript.active_rows,
        a_sig,
        pub_attrs,
        &transcript.round1,
        &mut blame,
    );
    timing.row_auth_ns += start.elapsed().as_nanos();

    let start = Instant::now();
    check_openings(&transcript.round1, &transcript.openings, ssid, &mut blame);
    check_relations(
        params,
        a_sig,
        op,
        access,
        transcript,
        prv,
        j_pid,
        ch,
        reconstruction,
        &mut blame,
    );
    timing.relations_ns += start.elapsed().as_nanos();

    let start = Instant::now();
    check_lifting(
        a_sig,
        transcript.primary,
        &transcript.openings,
        &transcript.round3,
        &mut blame,
    );
    timing.lifting_ns += start.elapsed().as_nanos();
    blame
}

/// Checks authenticated evidence on the blame path and returns the attributed abort.
#[allow(clippy::too_many_arguments)]
pub fn blame_path(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    transcript: &CanonicalTranscript,
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ssid: &[u8],
    coin: &VerifiedCoin,
) -> DetectOutcome {
    if !ipk.matches_params(params) {
        return DetectOutcome::ParameterMismatch;
    }
    let mut timing = DetectTiming::default();
    let mut blame = blame_path_with_ssid(
        params,
        &ipk.auth_pk,
        a_sig,
        op,
        access,
        transcript,
        pub_attrs,
        prv,
        j_pid,
        ssid,
        coin.ch(),
        None,
        &mut timing,
    );
    if blame.is_empty() {
        blame.insert(transcript.primary);
    }
    DetectOutcome::Abort(blame)
}

fn assemble_canonical(
    transcript: &CanonicalTranscript,
    coin: &VerifiedCoin,
    revealed: &[(usize, Fr)],
    prv: &[usize],
    message_count: usize,
) -> Presentation {
    let hidden = hidden_indices(message_count, revealed).expect("validated Rev");
    let round2 = Round2Public {
        c_prv: transcript
            .openings
            .iter()
            .fold(G1Projective::zero(), |sum, opening| sum + opening.c_hat),
        nym: transcript
            .openings
            .iter()
            .fold(G1Projective::zero(), |sum, opening| sum + opening.n),
    };
    assemble(
        &round2,
        &transcript.round3,
        coin,
        &transcript.holder_responses,
        &transcript.primary_response,
        &hidden,
        prv,
    )
    .expect("canonical responses assemble")
}

#[allow(clippy::too_many_arguments)]
fn check_prefix(
    auth_pk: &PublicKey,
    access: &CompiledAccess,
    r_s: &[usize],
    a_sig: &G1Projective,
    pub_attrs: &[(usize, Fr)],
    ssid: &[u8],
    canonical: Canonicalization,
    first_bad_round: u8,
    timing: &mut DetectTiming,
) -> BTreeSet<usize> {
    let mut blame = canonical.structural_blame;
    if first_bad_round > 1 {
        let start = Instant::now();
        check_rows(
            auth_pk,
            access,
            r_s,
            a_sig,
            pub_attrs,
            &canonical.prefix.round1,
            &mut blame,
        );
        timing.row_auth_ns = start.elapsed().as_nanos();
    }
    if first_bad_round > 2 {
        let start = Instant::now();
        check_openings(
            &canonical.prefix.round1,
            &canonical.prefix.openings,
            ssid,
            &mut blame,
        );
        timing.relations_ns = start.elapsed().as_nanos();
    }
    if first_bad_round > 3 {
        let start = Instant::now();
        let primary = r_s
            .iter()
            .map(|&row| access.lsss.rho[row])
            .min()
            .expect("nonempty R_S");
        check_lifting(
            a_sig,
            primary,
            &canonical.prefix.openings,
            canonical.prefix.round3.as_ref().expect("completed Round 3"),
            &mut blame,
        );
        timing.lifting_ns = start.elapsed().as_nanos();
    }
    debug_assert!(!blame.is_empty());
    blame
}

/// Runs Canon (including seed-opening verification) and CheckPrefix without a verified coin.
/// Returns the complete abort verdict on the first structural fault; a structurally complete
/// transcript requires the usual presentation verification and does not yield a prefix verdict.
/// A parameter/key mismatch is returned without inspecting or blaming any holder.
#[allow(clippy::too_many_arguments)]
pub fn detect_prefix(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    access: &CompiledAccess,
    rows: &[usize],
    envelopes: &[AuthenticatedEnvelope],
    revealed: &[(usize, Fr)],
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    ctx: &[u8],
    nonce: [u8; 32],
) -> Option<DetectOutcome> {
    if !ipk.matches_params(params) {
        return Some(DetectOutcome::ParameterMismatch);
    }
    let witness = reconstruction_for(access, rows, None);
    let r_s = witness.rows();
    let rev: Vec<_> = revealed.iter().map(|(index, _)| *index).collect();
    let ssid = derive_ssid(&ipk.header(ctx), &access.asid, a_sig, r_s, &rev, &nonce);
    let canonical = canonicalize_inner(
        access,
        r_s,
        envelopes,
        revealed,
        prv,
        params.h.len(),
        &ssid,
        true,
    );
    let round = canonical.first_bad_round?;
    let blame = check_prefix(
        &ipk.auth_pk,
        access,
        r_s,
        a_sig,
        pub_attrs,
        &ssid,
        canonical,
        round,
        &mut DetectTiming::default(),
    );
    Some(DetectOutcome::Abort(blame))
}

/// Returns the accepted presentation on the honest path or evaluates the evidence on the blame path.
#[allow(clippy::too_many_arguments)]
pub fn detect(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    r_s: &[usize],
    envelopes: &[AuthenticatedEnvelope],
    coin: &VerifiedCoin,
    revealed: &[(usize, Fr)],
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ctx: &[u8],
    nonce: [u8; 32],
) -> DetectOutcome {
    detect_timed(
        params, ipk, a_sig, op, access, r_s, envelopes, coin, revealed, pub_attrs, prv, j_pid, ctx,
        nonce,
    )
    .0
}

/// Returns detector W's decision together with per-check and total elapsed times.
#[allow(clippy::too_many_arguments)]
pub fn detect_timed(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    r_s: &[usize],
    envelopes: &[AuthenticatedEnvelope],
    coin: &VerifiedCoin,
    revealed: &[(usize, Fr)],
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ctx: &[u8],
    nonce: [u8; 32],
) -> (DetectOutcome, DetectTiming) {
    detect_inner(
        params, ipk, a_sig, op, access, r_s, envelopes, coin, revealed, pub_attrs, prv, j_pid, ctx,
        nonce, None,
    )
}

/// Checks the session's ordered row set against its reconstruction before evaluating the evidence.
#[allow(clippy::too_many_arguments)]
pub fn detect_cached(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    r_s: &[usize],
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
    detect_cached_timed(
        params,
        ipk,
        a_sig,
        op,
        access,
        r_s,
        reconstruction,
        envelopes,
        coin,
        revealed,
        pub_attrs,
        prv,
        j_pid,
        ctx,
        nonce,
    )
    .0
}

/// Measures detector checks using the holder's reconstruction from this presentation.
#[allow(clippy::too_many_arguments)]
pub fn detect_cached_timed(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    r_s: &[usize],
    reconstruction: &Reconstruction,
    envelopes: &[AuthenticatedEnvelope],
    coin: &VerifiedCoin,
    revealed: &[(usize, Fr)],
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ctx: &[u8],
    nonce: [u8; 32],
) -> (DetectOutcome, DetectTiming) {
    detect_inner(
        params,
        ipk,
        a_sig,
        op,
        access,
        r_s,
        envelopes,
        coin,
        revealed,
        pub_attrs,
        prv,
        j_pid,
        ctx,
        nonce,
        Some(reconstruction),
    )
}

#[allow(clippy::too_many_arguments)]
fn detect_inner(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    a_sig: &G1Projective,
    op: &G1Projective,
    access: &CompiledAccess,
    r_s: &[usize],
    envelopes: &[AuthenticatedEnvelope],
    coin: &VerifiedCoin,
    revealed: &[(usize, Fr)],
    pub_attrs: &[(usize, Fr)],
    prv: &[usize],
    j_pid: usize,
    ctx: &[u8],
    nonce: [u8; 32],
    reconstruction: Option<&Reconstruction>,
) -> (DetectOutcome, DetectTiming) {
    let total_start = Instant::now();
    let mut timing = DetectTiming::default();
    if !ipk.matches_params(params) {
        timing.total_ns = total_start.elapsed().as_nanos();
        return (DetectOutcome::ParameterMismatch, timing);
    }
    assert_eq!(
        prv.first().copied(),
        Some(j_pid),
        "j_pid must be the first private attribute"
    );
    assert!(
        pub_attrs.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && pub_attrs.iter().all(|(index, _)| *index < params.h.len())
            && pub_attrs.len() + prv.len() == params.h.len()
            && pub_attrs
                .iter()
                .all(|(index, _)| prv.binary_search(index).is_err()),
        "Pub and Prv must be a canonical partition"
    );
    assert!(
        revealed
            .iter()
            .all(|item| pub_attrs.binary_search(item).is_ok()),
        "revealed attributes must match the credential's public attributes"
    );
    let rev: Vec<_> = revealed.iter().map(|(index, _)| *index).collect();
    let witness = reconstruction_for(access, r_s, reconstruction);
    let r_s = witness.rows();
    let ssid = derive_ssid(&ipk.header(ctx), &access.asid, a_sig, r_s, &rev, &nonce);
    // Round 4 verified the seed openings; Canon checks their structure here.
    let canonical = canonicalize_inner(
        access,
        r_s,
        envelopes,
        revealed,
        prv,
        params.h.len(),
        &ssid,
        false,
    );

    if let Some(first_bad_round) = canonical.first_bad_round {
        let blame = check_prefix(
            &ipk.auth_pk,
            access,
            r_s,
            a_sig,
            pub_attrs,
            &ssid,
            canonical,
            first_bad_round,
            &mut timing,
        );
        timing.total_ns = total_start.elapsed().as_nanos();
        return (DetectOutcome::Abort(blame), timing);
    }

    let transcript = canonical.transcript.expect("complete canonical transcript");
    let presentation = assemble_canonical(&transcript, coin, revealed, prv, params.h.len());
    let terminal_start = Instant::now();
    let valid = vf_pres(params, ipk, &presentation, revealed, j_pid, ctx, nonce);
    timing.terminal_ns = terminal_start.elapsed().as_nanos();
    if valid {
        timing.total_ns = total_start.elapsed().as_nanos();
        return (DetectOutcome::Pres(Box::new(presentation)), timing);
    }

    let mut blame = blame_path_with_ssid(
        params,
        &ipk.auth_pk,
        a_sig,
        op,
        access,
        &transcript,
        pub_attrs,
        prv,
        j_pid,
        &ssid,
        coin.ch(),
        Some(&witness),
        &mut timing,
    );
    if blame.is_empty() {
        blame.insert(transcript.primary);
    }
    debug_assert!(!blame.is_empty());
    timing.total_ns = total_start.elapsed().as_nanos();
    (DetectOutcome::Abort(blame), timing)
}
