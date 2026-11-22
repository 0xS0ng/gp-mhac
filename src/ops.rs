//! Protocol-operation accounting and the only counted group-operation entry points.

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::Group;
use ark_ff::PrimeField;
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

/// Counts group operations, hashes, pseudorandom function calls, signatures and signature verifications.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpCounts {
    pub e1: u64,
    pub e2: u64,
    pub et: u64,
    pub pairing: u64,
    pub h: u64,
    pub h_g: u64,
    pub prf: u64,
    pub s_sig: u64,
    pub v_sig: u64,
}

thread_local! {
    static COUNTS: Cell<OpCounts> = Cell::new(OpCounts::default());
    static SUSPEND_DEPTH: Cell<u32> = const { Cell::new(0) };
}

fn bump(update: impl FnOnce(&mut OpCounts)) {
    SUSPEND_DEPTH.with(|depth| {
        if depth.get() == 0 {
            COUNTS.with(|counts| {
                let mut value = counts.get();
                update(&mut value);
                counts.set(value);
            });
        }
    });
}

/// Clears the current thread's counters without changing its suspension depth.
pub fn reset() {
    COUNTS.with(|counts| counts.set(OpCounts::default()));
}

/// Returns a copy of the current thread's operation counts.
pub fn snapshot() -> OpCounts {
    COUNTS.with(Cell::get)
}

pub(crate) fn count_h() {
    bump(|counts| counts.h += 1);
}

pub(crate) fn count_h_g() {
    bump(|counts| counts.h_g += 1);
}

pub(crate) fn count_s_sig() {
    bump(|counts| counts.s_sig += 1);
}

pub(crate) fn count_v_sig() {
    bump(|counts| counts.v_sig += 1);
}

/// Pauses all operation accounting until the guard is dropped. Guards may nest.
#[must_use]
pub struct SuspendGuard {
    // A thread-local guard must not be dropped on a different thread.
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl SuspendGuard {
    /// Suspends counting on the current thread until the guard is dropped.
    pub fn new() -> Self {
        SUSPEND_DEPTH.with(|depth| depth.set(depth.get().checked_add(1).expect("suspend depth")));
        Self {
            _not_send_or_sync: PhantomData,
        }
    }
}

impl Default for SuspendGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SuspendGuard {
    fn drop(&mut self) {
        SUSPEND_DEPTH.with(|depth| {
            let old = depth.get();
            debug_assert!(old > 0);
            depth.set(old - 1);
        });
    }
}

/// Returns the G1 scalar product and charges one E1.
pub fn g1_mul(point: &G1Projective, scalar: &Fr) -> G1Projective {
    bump(|counts| counts.e1 += 1);
    point.mul_bigint(scalar.into_bigint())
}

/// Returns the G2 scalar product and charges one E2.
pub fn g2_mul(point: &G2Projective, scalar: &Fr) -> G2Projective {
    bump(|counts| counts.e2 += 1);
    point.mul_bigint(scalar.into_bigint())
}

/// Returns a target-group exponentiation and charges one ET.
pub fn gt_exp(point: &PairingOutput<Bls12_381>, scalar: &Fr) -> PairingOutput<Bls12_381> {
    bump(|counts| counts.et += 1);
    point.mul_bigint(scalar.into_bigint())
}

/// Pairs one G1 element with one G2 element and charges one pairing.
pub fn pair(point_g1: &G1Projective, point_g2: &G2Projective) -> PairingOutput<Bls12_381> {
    bump(|counts| counts.pairing += 1);
    Bls12_381::pairing(point_g1, point_g2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::Group;
    use ark_ff::One;

    #[test]
    fn increments_and_reset_work() {
        reset();
        let one = Fr::one();
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let gt = pair(&g1, &g2);
        let _ = g1_mul(&g1, &one);
        let _ = g2_mul(&g2, &one);
        let _ = gt_exp(&gt, &one);
        let _ = pair(&g1, &g2);
        assert_eq!(
            snapshot(),
            OpCounts {
                e1: 1,
                e2: 1,
                et: 1,
                pairing: 2,
                ..OpCounts::default()
            }
        );
        reset();
        assert_eq!(snapshot(), OpCounts::default());
    }

    #[test]
    fn suspend_guard_suppresses_and_nests() {
        reset();
        let one = Fr::one();
        let g1 = G1Projective::generator();
        {
            let _outer = SuspendGuard::new();
            let _ = g1_mul(&g1, &one);
            {
                let _inner = SuspendGuard::new();
                let _ = g1_mul(&g1, &one);
            }
            let _ = g1_mul(&g1, &one);
        }
        assert_eq!(snapshot(), OpCounts::default());
        let _ = g1_mul(&g1, &one);
        assert_eq!(snapshot().e1, 1);
    }
}
