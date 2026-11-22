//! MHAC issuance from *Multi-Holder Anonymous Credentials from BBS Signatures* (CRYPTO 2025).
//! The dealer samples consistent shares locally and signs credential-bound factors
//! for the Appendix H share-size optimization.

use crate::baselines::mhac::{Error, MhacCredential};
use crate::issuance::Parameters;
use crate::lsss::{threshold, CompiledLsss};
use crate::ops::{self, SuspendGuard};
use crate::primitives::sample_generator;
use crate::primitives::{auth, hash::hash_bytes};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

/// MHAC Algorithm 1 calls BBS parameter generation: sample the group generators
/// and draw an independent public G1 base for every attribute (Definition 4).
pub fn setup<R: Rng + ?Sized>(message_count: usize, rng: &mut R) -> Parameters {
    let g1 = sample_generator(rng);
    let g2 = sample_generator(rng);
    let h = (0..message_count)
        .map(|_| G1Projective::rand(rng))
        .collect();
    Parameters::from_parts(g1, h, g2)
}

/// A holder's own G1 factor and its issuer signature.
#[derive(Clone, Debug)]
pub struct CertifiedFactor {
    pub d: G1Projective,
    pub signature: auth::Signature,
}

/// Threshold share, its certified factor, and ordered public attributes.
#[derive(Clone, Debug)]
pub struct Credential {
    pub local: MhacCredential,
    pub certificate: CertifiedFactor,
    pub public_attrs: Vec<(usize, Fr)>,
}

impl Credential {
    /// Serializes the local share, factor and issuer signature, excluding public attributes and metadata.
    pub fn counted_bytes(&self) -> Vec<u8> {
        let mut bytes = self.local.to_bytes();
        self.certificate
            .d
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        bytes.extend_from_slice(&self.certificate.signature.to_bytes());
        bytes
    }
}

/// Issued holder credentials, public keys, threshold matrix and attribute partition.
#[derive(Clone, Debug)]
pub struct Dealer {
    pub x2: G2Projective,
    pub auth_vk: auth::PublicKey,
    pub lsss: CompiledLsss,
    pub credentials: Vec<Credential>,
    pub prv: Vec<usize>,
    pub public_attrs: Vec<(usize, Fr)>,
}

/// H(X2, pp, A, indexed public attributes). Fixed suite and ordered, length-
/// framed collections make pp and the public attribute vector unambiguous.
pub fn credential_digest(
    params: &Parameters,
    x2: &G2Projective,
    a: &G1Projective,
    public: &[(usize, Fr)],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    x2.serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    params
        .g1
        .serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    params
        .g2
        .serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    bytes.extend_from_slice(&(params.h.len() as u64).to_be_bytes());
    for h in &params.h {
        h.serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    a.serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    bytes.extend_from_slice(&(public.len() as u64).to_be_bytes());
    for (index, value) in public {
        bytes.extend_from_slice(&(*index as u64).to_be_bytes());
        value
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    hash_bytes(b"MHAC-APP-H-BLS12381-SHA256-v1", &bytes)
}

fn signed_message(digest: &[u8; 32], d: &G1Projective) -> Vec<u8> {
    let mut msg = Vec::with_capacity(80);
    msg.extend_from_slice(digest);
    d.serialize_compressed(&mut msg)
        .expect("Vec serialization cannot fail");
    msg
}

/// Checks that the issuer signed the factor and credential digest.
pub fn verify_bound_factor(
    digest: &[u8; 32],
    d: &G1Projective,
    sig: &auth::Signature,
    vk: &auth::PublicKey,
) -> bool {
    auth::verify(vk, &signed_message(digest, d), sig)
}

/// Derives the credential digest from parameters, issuer key, signature point and public attributes, and verifies the factor certificate.
pub fn verify_factor(
    params: &Parameters,
    x2: &G2Projective,
    a: &G1Projective,
    public: &[(usize, Fr)],
    d: &G1Projective,
    sig: &auth::Signature,
    vk: &auth::PublicKey,
) -> bool {
    verify_bound_factor(&credential_digest(params, x2, a, public), d, sig, vk)
}

/// Issues one compact share and signed factor per holder. The dealer samples the reserved final coordinate.
/// Returns an error for a wrong attribute count, missing private reserved coordinate, or invalid threshold.
pub fn issue<R: Rng + ?Sized>(
    params: &Parameters,
    attrs: &[Fr],
    prv: &[usize],
    t: usize,
    n: usize,
    rng: &mut R,
) -> Result<Dealer, Error> {
    if attrs.len() != params.h.len() || attrs.is_empty() {
        return Err(Error::WrongAttributeCount);
    }
    if prv.last() != Some(&(attrs.len() - 1)) || !prv.windows(2).all(|w| w[0] < w[1]) {
        return Err(Error::InvalidPrivateOrRevealedSet);
    }
    if t == 0 || t > n {
        return Err(Error::InvalidActiveSet);
    }
    let _offline = SuspendGuard::new();
    let mut values = attrs.to_vec();
    *values.last_mut().expect("nonempty") = Fr::rand(rng);
    let public_attrs: Vec<_> = values
        .iter()
        .copied()
        .enumerate()
        .filter(|(j, _)| prv.binary_search(j).is_err())
        .collect();
    let lsss = threshold(t, n);
    let x = loop {
        let s = Fr::rand(rng);
        if !s.is_zero() {
            break s;
        }
    };
    let x2 = ops::g2_mul(&params.g2, &x);
    let (auth_sk, auth_vk) = auth::keygen(rng);
    let mut b = params.g1;
    for (h, v) in params.h.iter().zip(&values) {
        b += ops::g1_mul(h, v);
    }
    let (e, inv) = loop {
        let e = Fr::rand(rng);
        if let Some(inv) = (x + e).inverse() {
            break (e, inv);
        }
    };
    let a = ops::g1_mul(&b, &inv);
    let e_shares = lsss.share(e, rng);
    let shares: Vec<_> = prv.iter().map(|&j| lsss.share(values[j], rng)).collect();
    let factors: Vec<_> = (0..n)
        .map(|i| {
            prv.iter()
                .zip(&shares)
                .fold(ops::g1_mul(&a, &(-e_shares[i])), |acc, (&j, s)| {
                    acc + ops::g1_mul(&params.h[j], &s[i])
                })
        })
        .collect();
    let digest = credential_digest(params, &x2, &a, &public_attrs);
    let credentials = (0..n)
        .map(|holder| {
            let d = factors[holder];
            let certificate = CertifiedFactor {
                d,
                signature: auth::sign(&auth_sk, &signed_message(&digest, &d), rng),
            };
            Credential {
                local: MhacCredential {
                    holder,
                    a_sig: a,
                    e_share: e_shares[holder],
                    prv_shares: shares.iter().map(|s| s[holder]).collect(),
                },
                certificate,
                public_attrs: public_attrs.clone(),
            }
        })
        .collect();
    Ok(Dealer {
        x2,
        auth_vk,
        lsss: CompiledLsss::new(lsss),
        credentials,
        prv: prv.to_vec(),
        public_attrs,
    })
}
