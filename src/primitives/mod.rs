//! Group hashes and Auth signatures used in issuance, presentation and detection.

pub mod auth;
pub mod hash;

use ark_ec::Group;
use ark_std::rand::Rng;

/// In a prime-order group, each nonidentity element is a generator.
pub(crate) fn sample_generator<G: Group, R: Rng + ?Sized>(rng: &mut R) -> G {
    loop {
        let point = G::rand(rng);
        if !point.is_zero() {
            return point;
        }
    }
}
