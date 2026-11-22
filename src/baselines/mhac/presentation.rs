//! MHAC presentation from *Multi-Holder Anonymous Credentials from BBS Signatures* (CRYPTO 2025).
//! Holders broadcast in process; after collecting valid messages, each receiver verifies the
//! final presentation before checking certified factors and responses on the blame path.
use crate::baselines::mhac::issuance::{credential_digest, verify_bound_factor, Dealer};
use crate::baselines::mhac::{
    self as f, Error, MhacPresentation, Step2Output, Step3Commitment, Step4Opening, Step6Response,
};
use crate::issuance::Parameters;
use crate::ops;
use crate::primitives::auth::Signature;
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, Zero};
use ark_std::rand::Rng;
use std::collections::BTreeSet;
use std::time::Instant;

/// Synthetic input cases used only in this local authenticated-broadcast harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    MissingRandomizer,
    MissingCommitment(usize),
    MissingOpening(usize),
    MissingResponse(usize),
    BadOpening(usize),
    BadFactor(usize),
    BadSignature(usize),
    BadResponse(usize),
    MalformedResponse(usize),
    DuplicateResponse(usize),
    BadSignatureAndResponse(usize),
    BadResponsePair(usize, usize),
    BadSignatureAndOtherResponse(usize, usize),
}

/// Operation counts, diagnosis time and logical broadcast payload.
#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub signature_checks: usize,
    pub opening_checks: usize,
    pub response_checks: usize,
    pub final_checks: usize,
    /// Time in post-failure diagnosis across all receivers, excluding
    /// the triggering final verification. A structural rejection before final verification leaves this zero.
    pub diagnostic_ns: u128,
    pub wire_bytes: usize,
}

/// Accepted presentation or attributed holders, including the resulting diagnosis and costs.
#[derive(Debug)]
pub struct Outcome {
    pub presentation: Option<MhacPresentation>,
    pub blame: Vec<usize>,
    pub stats: Stats,
    pub diagnosis: Diagnosis,
}

/// Distinguishes acceptance, evidence-based attribution and inconclusive failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Diagnosis {
    NotNeeded,
    Attributed,
    /// The final verifier rejected but no authenticated sender evidence failed.
    /// Never convert a generic verification failure into an accusation.
    Inconclusive,
}

fn aborted(blame: BTreeSet<usize>, stats: Stats) -> Outcome {
    Outcome {
        presentation: None,
        blame: blame.into_iter().collect(),
        stats,
        diagnosis: Diagnosis::Attributed,
    }
}

/// The transport authenticates the sender of each broadcast slot.
/// The signature on h || D does not include a sender identifier.
#[derive(Clone)]
struct Envelope<T> {
    sender: usize,
    payload: T,
}

fn slot_errors<T>(messages: &[Envelope<T>], expected: &[usize]) -> BTreeSet<usize> {
    let mut issues = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for m in messages {
        if expected.binary_search(&m.sender).is_err() || !seen.insert(m.sender) {
            issues.insert(m.sender);
        }
    }
    for h in expected {
        if !seen.contains(h) {
            issues.insert(*h);
        }
    }
    issues
}

#[derive(Clone)]
struct Step3Broadcast {
    com: Step3Commitment,
    factor: (G1Projective, Signature),
}

/// Session-independent state for measurements with or without a cache:
/// stores public bases, canonical coefficients and the credential digest. Received factors are not cached.
pub struct Prepared<'a> {
    params: &'a Parameters,
    dealer: &'a Dealer,
    active: Vec<usize>,
    rev: Vec<usize>,
    hidden: Vec<usize>,
    attrs: Vec<Fr>,
    revealed: Vec<(usize, Fr)>,
    coeff: Vec<(usize, Fr)>,

    c_rev: G1Projective,
    public_base: G1Projective,
    digest: [u8; 32],
}

impl<'a> Prepared<'a> {
    /// Prepares public bases, coefficients and the credential digest; rejects malformed partitions, credentials or committees.
    pub fn new(
        params: &'a Parameters,
        dealer: &'a Dealer,
        active: &[usize],
        rev: &[usize],
    ) -> Result<Self, Error> {
        let first = *active.first().ok_or(Error::InvalidActiveSet)?;
        if !active.windows(2).all(|w| w[0] < w[1])
            || active.iter().any(|&i| {
                dealer
                    .credentials
                    .get(i)
                    .is_none_or(|c| c.local.holder != i)
            })
        {
            return Err(Error::InvalidActiveSet);
        }
        // The MHAC protocol here is the t-of-n variant with exactly t speakers.
        if dealer.lsss.matrix.first().map(Vec::len) != Some(active.len()) {
            return Err(Error::InvalidActiveSet);
        }
        let coeff = dealer
            .lsss
            .recon_coeffs(active)
            .ok_or(Error::InvalidActiveSet)?;
        if coeff.iter().map(|&(i, _)| i).ne(active.iter().copied()) {
            return Err(Error::InvalidActiveSet);
        }
        let prv = &dealer.prv;
        if prv.is_empty()
            || !prv.windows(2).all(|w| w[0] < w[1])
            || !rev.windows(2).all(|w| w[0] < w[1])
            || prv.iter().chain(rev).any(|&i| i >= params.h.len())
            || rev.iter().any(|i| prv.binary_search(i).is_ok())
        {
            return Err(Error::InvalidPrivateOrRevealedSet);
        }
        let exemplar = &dealer.credentials[first];
        let public = &exemplar.public_attrs;
        if public
            .iter()
            .map(|x| x.0)
            .ne((0..params.h.len()).filter(|i| prv.binary_search(i).is_err()))
        {
            return Err(Error::InvalidPrivateOrRevealedSet);
        }
        let mut attrs = vec![Fr::zero(); params.h.len()]; // private positions are never read
        let mut public_base = params.g1;
        let mut c_rev = params.g1;
        let mut revealed = Vec::new();
        for &(i, v) in public {
            attrs[i] = v;
            let term = ops::g1_mul(&params.h[i], &v);
            public_base += term;
            if rev.binary_search(&i).is_ok() {
                c_rev += term;
                revealed.push((i, v));
            }
        }
        let hidden = (0..params.h.len())
            .filter(|i| rev.binary_search(i).is_err())
            .collect();
        for &h in active {
            let c = &dealer.credentials[h];
            if c.public_attrs != *public
                || c.local.a_sig != exemplar.local.a_sig
                || c.local.prv_shares.len() != prv.len()
            {
                return Err(Error::InvalidResponses);
            }
        }
        let digest = credential_digest(params, &dealer.x2, &exemplar.local.a_sig, public);
        Ok(Self {
            params,
            dealer,
            active: active.to_vec(),
            rev: rev.to_vec(),
            hidden,
            attrs,
            revealed,
            coeff,

            c_rev,
            public_base,
            digest,
        })
    }

    fn check_certificates(
        &self,
        packets: &[Envelope<Step3Broadcast>],
        s: &mut Stats,
    ) -> Result<BTreeSet<usize>, Error> {
        let mut bad = BTreeSet::new();
        let digest = &self.digest;
        for &receiver in &self.active {
            for p in packets {
                if receiver == p.sender {
                    continue;
                }
                let (d, sig) = &p.payload.factor;
                s.signature_checks += 1;
                if !verify_bound_factor(digest, d, sig, &self.dealer.auth_vk) {
                    bad.insert(p.sender);
                }
            }
        }
        Ok(bad)
    }

    fn build_bases(
        &self,
        pos: usize,
        r: Fr,
        a_bar: G1Projective,
        packets: &[Envelope<Step3Broadcast>],
        individual: bool,
    ) -> Result<Step2Output, Error> {
        let holder = self.active[pos];
        let mut b = self.public_base;
        let mut terms = Vec::new();
        for (k, &(sender, lambda)) in self.coeff.iter().enumerate() {
            let d = packets
                .get(k)
                .filter(|p| p.sender == sender)
                .ok_or(Error::MissingFactor)?
                .payload
                .factor
                .0;
            if individual {
                let factor = if k == 0 {
                    ops::g1_mul(&(self.public_base + ops::g1_mul(&d, &lambda)), &r)
                } else {
                    ops::g1_mul(&d, &(lambda * r))
                };
                terms.push((sender, factor));
            } else {
                b += ops::g1_mul(&d, &lambda);
            }
        }
        let b_bar = if individual {
            terms
                .iter()
                .fold(G1Projective::zero(), |sum, (_, v)| sum + v)
        } else {
            ops::g1_mul(&b, &r)
        };
        Ok(Step2Output {
            holder,
            a_bar,
            b_bar,
            c_revealed: self.c_rev,
            b_tilde: terms,
        })
    }

    /// Check each received response against the *locally derived* challenge,
    /// rather than trusting an additional challenge from the sender.
    fn check_equations(
        &self,
        role: &Step2Output,
        openings: &[Step4Opening],
        responses: &[Step6Response],
        ch: Fr,
        s: &mut Stats,
    ) -> BTreeSet<usize> {
        let mut bad = BTreeSet::new();
        for (k, &sender) in self.active.iter().enumerate() {
            // The Primary also checks its own representation. Only a non-Primary's own equation is skipped.
            if sender == role.holder && sender != self.active[0] {
                continue;
            }
            s.response_checks += 1;
            let z = &responses[k];
            let lhs = openings[k].u + ops::g1_mul(&role.b_tilde[k].1, &ch);
            let mut rhs = ops::g1_mul(&role.a_bar, &z.z_e);
            for &(j, v) in z.z_prv.iter().chain(&z.z_other) {
                rhs += ops::g1_mul(&self.params.h[j], &v);
            }
            if let Some(v) = z.z_r {
                rhs += ops::g1_mul(&role.c_revealed, &v);
            }
            if lhs != rhs {
                bad.insert(sender);
            }
        }
        bad
    }

    /// Runs the prepared presentation for the session and nonce and returns its decision; invalid active holders or inconsistent inputs return an error.
    pub fn present<R: Rng + ?Sized>(
        &self,
        ssid: &[u8],
        nonce: [u8; 32],
        fault: Fault,
        rng: &mut R,
    ) -> Result<Outcome, Error> {
        let primary = self.active[0];
        let n = self.active.len();
        let mut s = Stats::default();
        if n < 2 && fault != Fault::None {
            // A sole corrupted holder has no honest peer to observe its message.
            return Err(Error::InvalidActiveSet);
        }
        let target = match fault {
            Fault::None | Fault::MissingRandomizer => None,
            Fault::BadResponsePair(a, b) | Fault::BadSignatureAndOtherResponse(a, b) => {
                if a == b || self.active.binary_search(&b).is_err() || n < 3 {
                    return Err(Error::InvalidActiveSet);
                }
                Some(a)
            }
            Fault::MissingCommitment(h)
            | Fault::MissingOpening(h)
            | Fault::MissingResponse(h)
            | Fault::BadOpening(h)
            | Fault::BadResponse(h)
            | Fault::MalformedResponse(h)
            | Fault::BadSignature(h)
            | Fault::DuplicateResponse(h)
            | Fault::BadFactor(h)
            | Fault::BadSignatureAndResponse(h) => Some(h),
        };
        if target.is_some_and(|h| self.active.binary_search(&h).is_err()) {
            return Err(Error::InvalidActiveSet);
        }
        // The authenticated transcript orders messages by sender.
        let randomizer: Vec<_> = if fault == Fault::MissingRandomizer {
            vec![]
        } else {
            vec![Envelope {
                sender: primary,
                payload: f::step1_primary(rng),
            }]
        };
        let b = slot_errors(&randomizer, &[primary]);
        if !b.is_empty() {
            return Ok(aborted(b, s));
        }
        let r = randomizer[0].payload;
        s.wire_bytes += 32;
        let mut roles = Vec::with_capacity(n);
        let mut states = Vec::with_capacity(n);
        let mut packets = Vec::with_capacity(n);
        for &h in &self.active {
            let c = &self.dealer.credentials[h];
            let a_bar = ops::g1_mul(&c.local.a_sig, &r);
            // Remote factors are received after this commitment.
            let early = Step2Output {
                holder: h,
                a_bar,
                c_revealed: self.c_rev,
                b_bar: G1Projective::zero(),
                b_tilde: vec![],
            };
            let (com, st) = f::step3_commit(
                self.params,
                &c.local,
                &early,
                &self.dealer.prv,
                &self.rev,
                primary,
                ssid,
                nonce,
                rng,
            )?;
            roles.push(early);
            states.push(st);
            if fault == Fault::MissingCommitment(h) {
                continue;
            }
            let mut factor = (c.certificate.d, c.certificate.signature.clone());
            {
                let (d, sig) = &mut factor;
                if fault == Fault::BadFactor(h) {
                    *d += self.params.g1;
                }
                if fault == Fault::BadSignature(h)
                    || fault == Fault::BadSignatureAndResponse(h)
                    || matches!(fault,Fault::BadSignatureAndOtherResponse(a,_) if a==h)
                {
                    sig.response += Fr::one();
                }
            }
            s.wire_bytes += 32 + 48 + 80;
            packets.push(Envelope {
                sender: h,
                payload: Step3Broadcast { com, factor },
            });
        }
        let b = slot_errors(&packets, &self.active);
        if !b.is_empty() {
            return Ok(aborted(b, s));
        }
        for (i, role) in roles.iter_mut().enumerate() {
            *role = self.build_bases(i, r, role.a_bar, &packets, false)?;
        }
        let commitments: Vec<_> = packets.iter().map(|p| p.payload.com.clone()).collect();
        let mut opens = Vec::with_capacity(n);
        for (&h, st) in self.active.iter().zip(&states) {
            if fault == Fault::MissingOpening(h) {
                continue;
            }
            let mut op = f::step4_open(st);
            if fault == Fault::BadOpening(h) {
                op.u += self.params.g1;
            }
            s.wire_bytes += 48;
            opens.push(Envelope {
                sender: h,
                payload: op,
            });
        }
        let b = slot_errors(&opens, &self.active);
        if !b.is_empty() {
            return Ok(aborted(b, s));
        }
        let openings: Vec<_> = opens.into_iter().map(|x| x.payload).collect();
        let mut bad = BTreeSet::new();
        for &receiver in &self.active {
            s.opening_checks += n - 1;
            bad.extend(f::step5_check_commitments(
                receiver,
                &self.active,
                &commitments,
                &openings,
                ssid,
                nonce,
            ));
        }
        if !bad.is_empty() {
            return Ok(aborted(bad, s));
        } // before *any* honest response
        let mut replies = Vec::with_capacity(n);
        let mut challenges = Vec::with_capacity(n);
        for ((&h, st), role) in self.active.iter().zip(&states).zip(&roles) {
            let mut z = f::step6_respond(
                &self.dealer.credentials[h].local,
                st,
                role,
                &self.attrs,
                &self.dealer.prv,
                &self.coeff,
                primary,
                r,
                &openings,
                &self.revealed,
                ssid,
                nonce,
            )?;
            challenges.push(z.ch); // holder-local value, not a wire field
            if fault == Fault::MissingResponse(h) {
                continue;
            }
            if fault == Fault::BadResponse(h)
                || fault == Fault::BadSignatureAndResponse(h)
                || matches!(fault,Fault::BadSignatureAndOtherResponse(_,b) if b==h)
                || matches!(fault,Fault::BadResponsePair(a,b) if a==h || b==h)
            {
                if let Some(zr) = &mut z.z_r {
                    *zr += Fr::one();
                } else {
                    z.z_e += Fr::one();
                }
            }
            if fault == Fault::MalformedResponse(h) {
                z.z_prv.pop();
            }
            let len = 32 * (1 + z.z_prv.len() + z.z_other.len() + usize::from(z.z_r.is_some()));
            for _ in 0..if fault == Fault::DuplicateResponse(h) {
                2
            } else {
                1
            } {
                s.wire_bytes += len;
                replies.push(Envelope {
                    sender: h,
                    payload: z.clone(),
                });
            }
        }
        let mut b = slot_errors(&replies, &self.active);
        for msg in &replies {
            let z = &msg.payload;
            if z.holder != msg.sender
                || z.z_prv
                    .iter()
                    .map(|p| p.0)
                    .ne(self.dealer.prv.iter().copied())
                || z.z_r.is_some() != (msg.sender == primary)
                || (msg.sender == primary
                    && z.z_other.iter().map(|p| p.0).ne(self
                        .hidden
                        .iter()
                        .copied()
                        .filter(|j| self.dealer.prv.binary_search(j).is_err())))
                || (msg.sender != primary && !z.z_other.is_empty())
            {
                b.insert(msg.sender);
            }
        }
        if !b.is_empty() {
            return Ok(aborted(b, s));
        }
        let responses: Vec<_> = replies.into_iter().map(|m| m.payload).collect();
        let mut output = None;
        let mut failed = false;
        for role in &roles {
            let pres = f::assemble(role, &responses, &self.hidden, &self.dealer.prv, primary)?;
            s.final_checks += 1;
            failed |= !f::mhac_verify(
                self.params,
                &self.dealer.x2,
                &pres,
                &self.revealed,
                ssid,
                nonce,
            );
            output = Some(pres);
        }
        if failed {
            let timer = Instant::now();
            let uncertified = self.check_certificates(&packets, &mut s)?;
            let mut bad = uncertified;
            // A local term uses only its own sender's factor, r, the public
            // attributes and the Lagrange coefficients. A bad certificate for
            // A must not suppress separately verifiable evidence against B.
            for (i, (role, &ch)) in roles.iter().zip(&challenges).enumerate() {
                let detail = self.build_bases(i, r, role.a_bar, &packets, true)?;
                bad.extend(self.check_equations(&detail, &openings, &responses, ch, &mut s));
            }
            s.diagnostic_ns = timer.elapsed().as_nanos();
            if bad.is_empty() {
                return Ok(Outcome {
                    presentation: None,
                    blame: vec![],
                    stats: s,
                    diagnosis: Diagnosis::Inconclusive,
                });
            }
            return Ok(aborted(bad, s));
        }
        Ok(Outcome {
            presentation: output,
            blame: vec![],
            stats: s,
            diagnosis: Diagnosis::NotNeeded,
        })
    }
}

/// Presents without cached state; use `Prepared` to measure only online work.
#[allow(clippy::too_many_arguments)]
pub fn present<R: Rng + ?Sized>(
    params: &Parameters,
    dealer: &Dealer,
    active: &[usize],
    rev: &[usize],
    ssid: &[u8],
    nonce: [u8; 32],
    fault: Fault,
    rng: &mut R,
) -> Result<Outcome, Error> {
    Prepared::new(params, dealer, active, rev)?.present(ssid, nonce, fault, rng)
}
