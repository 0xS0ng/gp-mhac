//! Schnorr implementation of Auth for signing and verifying row factors.

use crate::ops::{self, SuspendGuard};
use crate::primitives::hash::hash_to_zp;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::Group;
use ark_ff::{UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

const DOMAIN_SCHNORR: &[u8] = b"GP-MHAC-SCHNORR-v1";

/// Schnorr signing scalar.
#[derive(Clone, Debug)]
pub struct SecretKey(pub Fr);

/// Schnorr verification point in G1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub G1Projective);

/// Compressed Schnorr commitment and scalar response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub commitment: G1Projective,
    pub response: Fr,
}

impl Signature {
    /// Compressed commitment (48 bytes) followed by the response scalar (32 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        self.commitment
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.response
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        bytes
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

fn challenge(public_key: &PublicKey, commitment: &G1Projective, message: &[u8]) -> Fr {
    let mut input = Vec::new();
    public_key
        .0
        .serialize_compressed(&mut input)
        .expect("Vec serialization cannot fail");
    commitment
        .serialize_compressed(&mut input)
        .expect("Vec serialization cannot fail");
    input.extend_from_slice(&(message.len() as u64).to_be_bytes());
    input.extend_from_slice(message);
    hash_to_zp(DOMAIN_SCHNORR, &input)
}

/// Samples a nonzero secret scalar and derives its public key.
pub fn keygen<R: Rng + ?Sized>(rng: &mut R) -> (SecretKey, PublicKey) {
    let _suspend = SuspendGuard::new();
    let secret = nonzero_scalar(rng);
    let public = ops::g1_mul(&G1Projective::generator(), &secret);
    (SecretKey(secret), PublicKey(public))
}

/// Signs a byte string under the secret key with a fresh nonce.
pub fn sign<R: Rng + ?Sized>(secret_key: &SecretKey, message: &[u8], rng: &mut R) -> Signature {
    ops::count_s_sig();
    let _suspend = SuspendGuard::new();
    let nonce = nonzero_scalar(rng);
    let generator = G1Projective::generator();
    let commitment = ops::g1_mul(&generator, &nonce);
    let public_key = PublicKey(ops::g1_mul(&generator, &secret_key.0));
    let c = challenge(&public_key, &commitment, message);
    Signature {
        commitment,
        response: nonce + c * secret_key.0,
    }
}

/// Checks the Schnorr equation for this message and public key.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    ops::count_v_sig();
    let _suspend = SuspendGuard::new();
    let c = challenge(public_key, &signature.commitment, message);
    let lhs = ops::g1_mul(&G1Projective::generator(), &signature.response);
    let rhs = signature.commitment + ops::g1_mul(&public_key.0, &c);
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{reset, snapshot, OpCounts};
    use ark_std::test_rng;

    #[test]
    fn schnorr_round_trip_and_opaque_counts() {
        let mut rng = test_rng();
        let (secret_key, public_key) = keygen(&mut rng);
        let signature = sign(&secret_key, b"credential", &mut rng);
        reset();
        assert!(verify(&public_key, b"credential", &signature));
        assert_eq!(
            snapshot(),
            OpCounts {
                v_sig: 1,
                ..OpCounts::default()
            }
        );
        assert!(!verify(&public_key, b"tampered", &signature));
    }

    #[test]
    fn signing_is_one_opaque_operation() {
        let mut rng = test_rng();
        let (secret_key, _) = keygen(&mut rng);
        reset();
        let _ = sign(&secret_key, b"credential", &mut rng);
        assert_eq!(
            snapshot(),
            OpCounts {
                s_sig: 1,
                ..OpCounts::default()
            }
        );
    }
}
