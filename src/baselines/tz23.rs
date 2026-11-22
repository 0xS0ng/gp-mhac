//! TZ23 from *Revisiting BBS Signatures* (EUROCRYPT 2023):
//! single-holder BBS signatures and selective-disclosure presentation and verification.

use crate::ops;
use crate::primitives::hash::{hash_to_g1, hash_to_zp};
use crate::primitives::sample_generator;
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

/// Domain of the partially disclosed signature proof.
pub const DOMAIN_TZ23: &[u8] = b"TZ23-POK-v1";
const DOMAIN_GENERATOR: &[u8] = b"TZ23-GENERATOR-v1";

/// Public group generators and indexed BBS message bases.
#[derive(Clone, Debug)]
pub struct Parameters {
    pub g1: G1Projective,
    pub h: Vec<G1Projective>,
    pub g2: G2Projective,
}

/// Nonzero BBS issuer signing scalar.
#[derive(Clone, Debug)]
pub struct SecretKey(pub Fr);

/// Issuer verification key in G2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey(pub G2Projective);

/// BBS signature consisting of a G1 element and a scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub a: G1Projective,
    pub e: Fr,
}

/// Fiat–Shamir proof of a BBS signature with selective disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PokProof {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub c: Fr,
    pub s: Fr,
    pub t: Fr,
    /// Responses for hidden indices, in ascending index order.
    pub u: Vec<Fr>,
}

/// Invalid signature, message arity or disclosure set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongMessageCount,
    InvalidDisclosureSet,
    IdentitySignature,
}

/// Samples both group generators and derives one public message base per position.
pub fn setup<R: Rng + ?Sized>(message_count: usize, rng: &mut R) -> Parameters {
    let mut h = Vec::with_capacity(message_count);
    for index in 1..=message_count {
        h.push(hash_to_g1(DOMAIN_GENERATOR, &index.to_be_bytes()));
    }
    Parameters {
        g1: sample_generator(rng),
        h,
        g2: sample_generator(rng),
    }
}

fn nonzero_scalar<R: Rng + ?Sized>(rng: &mut R) -> Fr {
    loop {
        let scalar = Fr::rand(rng);
        if !scalar.is_zero() {
            return scalar;
        }
    }
}

/// Samples a nonzero signing scalar and derives the verification key.
pub fn keygen<R: Rng + ?Sized>(params: &Parameters, rng: &mut R) -> (SecretKey, VerificationKey) {
    let secret = nonzero_scalar(rng);
    let public = ops::g2_mul(&params.g2, &secret);
    (SecretKey(secret), VerificationKey(public))
}

fn message_commitment(params: &Parameters, messages: &[Fr]) -> G1Projective {
    let mut commitment = params.g1;
    for (base, message) in params.h.iter().zip(messages) {
        commitment += ops::g1_mul(base, message);
    }
    commitment
}

/// Signs the message vector or returns an error if its length differs from the number of bases.
pub fn sign<R: Rng + ?Sized>(
    params: &Parameters,
    secret_key: &SecretKey,
    messages: &[Fr],
    rng: &mut R,
) -> Result<Signature, Error> {
    if messages.len() != params.h.len() {
        return Err(Error::WrongMessageCount);
    }
    let commitment = message_commitment(params, messages);
    let e = loop {
        let candidate = Fr::rand(rng);
        if !(secret_key.0 + candidate).is_zero() {
            break candidate;
        }
    };
    let inverse = (secret_key.0 + e)
        .inverse()
        .expect("nonzero scalar has an inverse");
    let a = ops::g1_mul(&commitment, &inverse);
    Ok(Signature { a, e })
}

/// Checks the signature pairing equation; rejects an incorrect arity or identity signature.
pub fn bbs_verify(
    params: &Parameters,
    verification_key: &VerificationKey,
    messages: &[Fr],
    signature: &Signature,
) -> bool {
    if messages.len() != params.h.len() || signature.a.is_zero() {
        return false;
    }
    let commitment = message_commitment(params, messages);
    let g2_e_plus_key = ops::g2_mul(&params.g2, &signature.e) + verification_key.0;
    ops::pair(&signature.a, &g2_e_plus_key) == ops::pair(&commitment, &params.g2)
}

fn disclosure_layout(
    message_count: usize,
    disclosed_indices: &[usize],
) -> Result<(Vec<usize>, Vec<usize>), Error> {
    let mut disclosed = disclosed_indices.to_vec();
    disclosed.sort_unstable();
    if disclosed.iter().any(|&index| index >= message_count)
        || disclosed.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(Error::InvalidDisclosureSet);
    }
    let mut hidden = Vec::with_capacity(message_count - disclosed.len());
    let mut disclosed_cursor = 0;
    for index in 0..message_count {
        if disclosed.get(disclosed_cursor) == Some(&index) {
            disclosed_cursor += 1;
        } else {
            hidden.push(index);
        }
    }
    Ok((disclosed, hidden))
}

fn disclosed_commitment(
    params: &Parameters,
    disclosed: &[usize],
    values: impl Fn(usize) -> Fr,
) -> G1Projective {
    let mut commitment = params.g1;
    for &index in disclosed {
        commitment += ops::g1_mul(&params.h[index], &values(index));
    }
    commitment
}

fn transcript(
    disclosed: &[(usize, Fr)],
    a_bar: &G1Projective,
    b_bar: &G1Projective,
    u: &G1Projective,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(disclosed.len() as u64).to_be_bytes());
    for (index, message) in disclosed {
        bytes.extend_from_slice(&(*index as u64).to_be_bytes());
        message
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    a_bar
        .serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    b_bar
        .serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    u.serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    bytes
}

/// Proves knowledge of the signature over the messages; rejects an invalid disclosure set, arity or identity signature.
pub fn pok_prove<R: Rng + ?Sized>(
    params: &Parameters,
    _verification_key: &VerificationKey,
    messages: &[Fr],
    signature: &Signature,
    disclosed_indices: &[usize],
    rng: &mut R,
) -> Result<PokProof, Error> {
    if messages.len() != params.h.len() {
        return Err(Error::WrongMessageCount);
    }
    if signature.a.is_zero() {
        return Err(Error::IdentitySignature);
    }
    let (disclosed_indices, hidden_indices) = disclosure_layout(params.h.len(), disclosed_indices)?;

    let r = nonzero_scalar(rng);
    let a_bar = ops::g1_mul(&signature.a, &r);
    let c_j = disclosed_commitment(params, &disclosed_indices, |index| messages[index]);
    let mut commitment = c_j;
    for &index in &hidden_indices {
        commitment += ops::g1_mul(&params.h[index], &messages[index]);
    }
    let a_minus_e = ops::g1_mul(&signature.a, &(-signature.e));
    let b_bar = ops::g1_mul(&(commitment + a_minus_e), &r);

    let alpha = Fr::rand(rng);
    let beta = Fr::rand(rng);
    let deltas: Vec<_> = hidden_indices.iter().map(|_| Fr::rand(rng)).collect();
    let mut announcement = ops::g1_mul(&c_j, &alpha) + ops::g1_mul(&a_bar, &beta);
    for (&index, delta) in hidden_indices.iter().zip(&deltas) {
        announcement += ops::g1_mul(&params.h[index], delta);
    }
    let disclosed: Vec<_> = disclosed_indices
        .iter()
        .map(|&index| (index, messages[index]))
        .collect();
    let c = hash_to_zp(
        DOMAIN_TZ23,
        &transcript(&disclosed, &a_bar, &b_bar, &announcement),
    );
    let s = alpha + r * c;
    let t = beta - signature.e * c;
    let u = hidden_indices
        .iter()
        .zip(deltas)
        .map(|(&index, delta)| delta + r * messages[index] * c)
        .collect();
    Ok(PokProof {
        a_bar,
        b_bar,
        c,
        s,
        t,
        u,
    })
}

/// Checks the proof against the verification key and disclosed index/value pairs; returns false on rejection.
pub fn pok_verify(
    params: &Parameters,
    verification_key: &VerificationKey,
    disclosed_indices: &[usize],
    disclosed_messages: &[Fr],
    proof: &PokProof,
) -> bool {
    if disclosed_indices.len() != disclosed_messages.len() || proof.a_bar.is_zero() {
        return false;
    }
    let (sorted_disclosed, hidden_indices) =
        match disclosure_layout(params.h.len(), disclosed_indices) {
            Ok(layout) => layout,
            Err(_) => return false,
        };
    if proof.u.len() != hidden_indices.len() {
        return false;
    }
    let mut disclosures: Vec<_> = disclosed_indices
        .iter()
        .copied()
        .zip(disclosed_messages.iter().copied())
        .collect();
    disclosures.sort_unstable_by_key(|(index, _)| *index);

    if ops::pair(&proof.a_bar, &verification_key.0) != ops::pair(&proof.b_bar, &params.g2) {
        return false;
    }
    let c_j = disclosed_commitment(params, &sorted_disclosed, |index| {
        disclosures
            .iter()
            .find(|(input_index, _)| *input_index == index)
            .expect("validated disclosure index")
            .1
    });
    let mut announcement = ops::g1_mul(&proof.b_bar, &(-proof.c))
        + ops::g1_mul(&c_j, &proof.s)
        + ops::g1_mul(&proof.a_bar, &proof.t);
    for (&index, response) in hidden_indices.iter().zip(&proof.u) {
        announcement += ops::g1_mul(&params.h[index], response);
    }
    proof.c
        == hash_to_zp(
            DOMAIN_TZ23,
            &transcript(&disclosures, &proof.a_bar, &proof.b_bar, &announcement),
        )
}

impl Signature {
    /// Encodes group elements and scalars in compressed protocol order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        self.a
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.e
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        bytes
    }
}

impl PokProof {
    /// Encodes group elements and scalars in compressed protocol order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96 + (self.u.len() + 3) * 32);
        self.a_bar
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.b_bar
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.c
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.s
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.t
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        for response in &self.u {
            response
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        bytes
    }
}
