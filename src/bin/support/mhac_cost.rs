//! MHAC per-role cost without cached state and honest-path detection on an authenticated transcript.
#[path = "mhac_counts.rs"]
pub mod counts;
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, Zero};
use ark_std::rand::{rngs::OsRng, RngCore};
use gp_mhac::workload::{Business, Workload};
use gp_mhac::{
    baselines::mhac as f,
    baselines::mhac::issuance::{self as iss, CertifiedFactor, Dealer},
    issuance::Parameters,
    ops,
};
use std::{collections::BTreeSet, hint::black_box, io::Write, time::Instant};
const SID: &[u8] = b"bench/mhac-presentation";

pub struct MhacFixture {
    pp: Parameters,
    w: Workload,
    d: Dealer,
    a: Vec<usize>,
}
struct RequestBases {
    weights: Vec<(usize, Fr)>,
    bp: G1Projective,
    cr: G1Projective,
    rev: Vec<(usize, Fr)>,
    hidden: Vec<usize>,
    pubvec: Vec<Fr>,
}
impl MhacFixture {
    pub fn new(biz: &Business, n: usize) -> Self {
        let w = biz.mhac();
        let pp = iss::setup(w.attrs.len(), &mut OsRng);
        let d = iss::issue(&pp, &w.attrs, &w.prv, n / 2, n, &mut OsRng).unwrap();
        Self {
            pp,
            w,
            d,
            a: Vec::new(),
        }
    }
    pub fn select(&mut self, rows: &[usize]) {
        self.a.clear();
        self.a.extend_from_slice(rows);
    }
    pub fn show(&self) -> (f::MhacPresentation, [u8; 32]) {
        let (tr, pres) = build_transcript(self);
        (pres, tr.nonce)
    }
    pub fn verify(&self, pres: &f::MhacPresentation, nonce: [u8; 32]) -> bool {
        let rev = self
            .w
            .rev
            .iter()
            .map(|&i| (i, self.w.attrs[i]))
            .collect::<Vec<_>>();
        f::mhac_verify(&self.pp, &self.d.x2, pres, &rev, SID, nonce)
    }
    fn uncached_bases(&self, id: usize) -> RequestBases {
        let weights = self.d.lsss.recon_coeffs(&self.a).unwrap();
        let (mut bp, mut cr) = (self.pp.g1, self.pp.g1);
        let mut rev = vec![];
        let mut pubvec = vec![Fr::zero(); self.w.attrs.len()];
        for &(j, v) in &self.d.credentials[id].public_attrs {
            pubvec[j] = v;
            let term = ops::g1_mul(&self.pp.h[j], &v);
            bp += term;
            if self.w.rev.contains(&j) {
                cr += term;
                rev.push((j, v));
            }
        }
        let hidden = (0..pubvec.len())
            .filter(|i| !self.w.rev.contains(i))
            .collect();
        RequestBases {
            weights,
            bp,
            cr,
            rev,
            hidden,
            pubvec,
        }
    }
    fn cert(&self, id: usize) -> &CertifiedFactor {
        &self.d.credentials[id].certificate
    }
}
struct TranscriptFixture {
    nonce: [u8; 32],
    generation_ms: [f64; 2],
    states: Vec<f::RoleState>,
    r: Fr,
    cs: Vec<f::Step3Commitment>,
    os: Vec<f::Step4Opening>,
    zs: Vec<f::Step6Response>,
    ds: Vec<CertifiedFactor>,
}
fn early(c: &MhacFixture, p: &RequestBases, id: usize, r: Fr) -> f::Step2Output {
    f::Step2Output {
        holder: id,
        a_bar: ops::g1_mul(&c.d.credentials[id].local.a_sig, &r),
        b_bar: G1Projective::zero(),
        c_revealed: p.cr,
        b_tilde: vec![],
    }
}
fn bases(p: &RequestBases, r: Fr, role: &mut f::Step2Output, ds: &[CertifiedFactor], detail: bool) {
    if detail {
        role.b_tilde = p
            .weights
            .iter()
            .zip(ds)
            .enumerate()
            .map(|(k, (&(h, l), c))| {
                (
                    h,
                    if k == 0 {
                        ops::g1_mul(&(p.bp + ops::g1_mul(&c.d, &l)), &r)
                    } else {
                        ops::g1_mul(&c.d, &(l * r))
                    },
                )
            })
            .collect();
        role.b_bar = role.b_tilde.iter().map(|v| v.1).sum();
    } else {
        role.b_bar = ops::g1_mul(
            &p.weights
                .iter()
                .zip(ds)
                .fold(p.bp, |b, (&(_, l), c)| b + ops::g1_mul(&c.d, &l)),
            &r,
        );
    }
}
fn seed() -> [u8; 32] {
    let mut s = [0; 32];
    OsRng.fill_bytes(&mut s);
    s
}
fn build_transcript(c: &MhacFixture) -> (TranscriptFixture, f::MhacPresentation) {
    let nonce = seed();
    let start = Instant::now();
    let r = f::step1_primary(&mut OsRng);
    let mut generation_ms = [start.elapsed().as_secs_f64() * 1e3, 0.];
    let ds: Vec<_> = c.a.iter().map(|&i| c.cert(i).clone()).collect();
    let primary = c.a[0];
    let p = c.uncached_bases(primary);
    let mut role = early(c, &p, primary, r);
    bases(&p, r, &mut role, &ds, false);
    let mut cs = vec![];
    let mut states = vec![];
    for (slot, &id) in c.a.iter().enumerate() {
        role.holder = id;
        let stage = Instant::now();
        let (cm, st) = f::step3_commit(
            &c.pp,
            &c.d.credentials[id].local,
            &role,
            &c.w.prv,
            &c.w.rev,
            primary,
            SID,
            nonce,
            &mut OsRng,
        )
        .unwrap();
        if slot < 2 {
            generation_ms[slot] += stage.elapsed().as_secs_f64() * 1e3;
        }
        cs.push(cm);
        states.push(st);
    }
    let os = states
        .iter()
        .enumerate()
        .map(|(slot, st)| {
            let stage = Instant::now();
            let op = f::step4_open(st);
            if slot < 2 {
                generation_ms[slot] += stage.elapsed().as_secs_f64() * 1e3;
            }
            op
        })
        .collect::<Vec<_>>();
    let zs =
        c.a.iter()
            .enumerate()
            .map(|(slot, &i)| {
                role.holder = i;
                f::step6_respond(
                    &c.d.credentials[i].local,
                    &states[slot],
                    &role,
                    &p.pubvec,
                    &c.w.prv,
                    &p.weights,
                    primary,
                    r,
                    &os,
                    &p.rev,
                    SID,
                    nonce,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
    let pres = f::assemble(&role, &zs, &p.hidden, &c.w.prv, primary).unwrap();
    (
        TranscriptFixture {
            nonce,
            generation_ms,
            states,
            r,
            cs,
            os,
            zs,
            ds,
        },
        pres,
    )
}
fn transcript(c: &MhacFixture) -> TranscriptFixture {
    let (tr, pres) = build_transcript(c);
    assert!(c.verify(&pres, tr.nonce));
    tr
}
fn certs(c: &MhacFixture, id: usize, t: &TranscriptFixture) -> BTreeSet<usize> {
    let own = &c.d.credentials[id];
    let digest = iss::credential_digest(&c.pp, &c.d.x2, &own.local.a_sig, &own.public_attrs);
    c.a.iter()
        .copied()
        .zip(&t.ds)
        .filter(|(i, cert)| {
            *i != id && !iss::verify_bound_factor(&digest, &cert.d, &cert.signature, &c.d.auth_vk)
        })
        .map(|(i, _)| i)
        .collect()
}
// Canonical authenticated receiver slots. The challenge is receiver-local, not
// a serialized scalar; packet decoding rejects duplicate/unknown sender IDs.
fn check_slots(c: &MhacFixture, t: &TranscriptFixture, zs: &[f::Step6Response], ch: Fr) -> bool {
    t.cs.len() == c.a.len()
        && t.os.len() == c.a.len()
        && zs.len() == c.a.len()
        && zs.iter().zip(&c.a).enumerate().all(|(slot, (z, &id))| {
            z.holder == id
                && t.cs[slot].holder == id
                && t.os[slot].holder == id
                && z.ch == ch
                && z.z_prv.iter().map(|q| q.0).eq(c.w.prv.iter().copied())
                && z.z_r.is_some() == (id == c.a[0])
                && if id == c.a[0] {
                    z.z_other
                        .iter()
                        .map(|q| q.0)
                        .eq((0..c.pp.h.len())
                            .filter(|i| !c.w.prv.contains(i) && !c.w.rev.contains(i)))
                } else {
                    z.z_other.is_empty()
                }
        })
}
fn role(c: &MhacFixture, t: &TranscriptFixture, slot: usize, checked: bool) -> f64 {
    let id = c.a[slot];
    // Add the measured holder's disjoint generation and response windows.
    let tm = Instant::now();
    let p = c.uncached_bases(id);
    let r = t.r;
    let mut role = early(c, &p, id, r);
    bases(&p, r, &mut role, &t.ds, false);
    if checked {
        assert!(f::step5_check_commitments(id, &c.a, &t.cs, &t.os, SID, t.nonce).is_empty());
    }
    let z = f::step6_respond(
        &c.d.credentials[id].local,
        &t.states[slot],
        &role,
        &p.pubvec,
        &c.w.prv,
        &p.weights,
        c.a[0],
        r,
        &t.os,
        &p.rev,
        SID,
        t.nonce,
    )
    .unwrap();
    if checked {
        assert!(check_slots(c, t, &t.zs, z.ch));
        let pres = f::assemble(&role, &t.zs, &p.hidden, &c.w.prv, c.a[0]).unwrap();
        assert!(f::mhac_verify(&c.pp, &c.d.x2, &pres, &p.rev, SID, t.nonce));
        black_box(pres);
    }
    let ms = tm.elapsed().as_secs_f64() * 1e3;
    assert_eq!(z, t.zs[slot]);
    ms + t.generation_ms[slot]
}
fn detection(c: &MhacFixture, t: &TranscriptFixture, scenario: &str) -> f64 {
    let id = c.a[2]; // The third active holder observes both fault cases.
    let mut zs = t.zs.clone();
    if scenario == "full_blame" {
        *zs[0].z_r.as_mut().unwrap() += Fr::one();
    }
    let cs: Vec<_> =
        t.cs.iter()
            .filter(|cm| scenario != "withhold" || cm.holder != c.a[1])
            .collect();
    // Detector-only costs exclude the request-local challenge and aggregate base.
    let context = (scenario != "withhold").then(|| {
        let p = c.uncached_bases(id);
        let mut step = early(c, &p, id, t.r);
        bases(&p, t.r, &mut step, &t.ds, false);
        let ch = t.zs[2].ch;
        (p, step, ch)
    });
    let tm = Instant::now();
    assert!(!t.r.is_zero());
    let slots = cs.iter().map(|cm| cm.holder).collect::<BTreeSet<_>>();
    let missing =
        c.a.iter()
            .copied()
            .filter(|i| !slots.contains(i))
            .collect::<BTreeSet<_>>();
    if !missing.is_empty() {
        let elapsed = tm.elapsed().as_secs_f64() * 1e3;
        assert_eq!(scenario, "withhold");
        assert_eq!(missing, BTreeSet::from([c.a[1]]));
        return elapsed;
    }
    let (p, mut step, ch) = context.unwrap();
    assert!(f::step5_check_commitments(id, &c.a, &t.cs, &t.os, SID, t.nonce).is_empty());
    assert!(check_slots(c, t, &zs, ch));
    let mut bad = BTreeSet::new();
    let accepted = {
        let pres = f::assemble(&step, &zs, &p.hidden, &c.w.prv, c.a[0]).unwrap();
        let valid = f::mhac_verify(&c.pp, &c.d.x2, &pres, &p.rev, SID, t.nonce);
        if !valid {
            bad = certs(c, id, t);
            bases(&p, t.r, &mut step, &t.ds, true);
            bad.extend(f::step7_check_responses(
                id, &c.pp, &c.a, c.a[0], &c.w.prv, &c.w.rev, &step, &t.os, &zs,
            ));
        }
        black_box(pres);
        valid
    };
    let elapsed = tm.elapsed().as_secs_f64() * 1e3;
    match scenario {
        "full_blame" => {
            assert!(!accepted);
            assert_eq!(bad, BTreeSet::from([c.a[0]]));
        }
        "honest" => {
            assert!(accepted);
            assert!(bad.is_empty());
        }
        _ => panic!("unexpected complete detection path"),
    }
    elapsed
}
fn measured_bytes(t: &TranscriptFixture) -> usize {
    use ark_serialize::CanonicalSerialize;
    // Canonical payload only: sender/framing are transport metadata; the
    // challenge is locally derived and not sent; final presentation excluded.
    let mut wire = Vec::new();
    t.r.serialize_compressed(&mut wire).unwrap();
    for (cm, cert) in t.cs.iter().zip(&t.ds) {
        wire.extend(cm.commitment);
        cert.d.serialize_compressed(&mut wire).unwrap();
        wire.extend(cert.signature.to_bytes());
    }
    for op in &t.os {
        op.u.serialize_compressed(&mut wire).unwrap();
    }
    for z in &t.zs {
        z.z_e.serialize_compressed(&mut wire).unwrap();
        for (_, v) in z.z_prv.iter().chain(&z.z_other) {
            v.serialize_compressed(&mut wire).unwrap();
        }
        if let Some(r) = z.z_r {
            r.serialize_compressed(&mut wire).unwrap();
        }
    }
    wire.len()
}
impl MhacFixture {
    pub fn measure_roles(&self, round: usize) -> Vec<(&'static str, f64)> {
        let t = transcript(self);
        (0..4)
            .map(|offset| {
                let k = (round + offset) % 4;
                let slot = usize::from(k < 2);
                let label = [
                    "holder_plain",
                    "holder_checked",
                    "primary_plain",
                    "primary_checked",
                ][k];
                (label, role(self, &t, slot, k % 2 == 1))
            })
            .collect()
    }
    pub fn measure_detection(&self, round: usize) -> Vec<(&'static str, f64)> {
        let t = transcript(self);
        (0..3)
            .map(|offset| {
                let name = ["honest", "withhold", "full_blame"][(round + offset) % 3];
                (name, detection(self, &t, name))
            })
            .collect()
    }
}
/// Emits MHAC credential-storage and canonical payload lengths.
pub fn measure_sizes(n: usize, warm: usize, count: usize, out: &mut impl Write) {
    for private in [2, 4] {
        let mut c = MhacFixture::new(&Business::fixture(14, private, 8), n);
        for j in 0..warm + count {
            c.select(&gp_mhac::workload::draw_threshold(n, n / 2, j));
            let t = transcript(&c);
            let mut emit = |series: &str, v: usize| {
                if j >= warm {
                    writeln!(
                        out,
                        "sizes,mhac,{series},{n},{},{:.9},bytes",
                        j - warm,
                        v as f64
                    )
                    .unwrap();
                }
            };
            if private == 2 {
                emit(
                    "storage",
                    black_box(c.d.credentials[c.a[1]].counted_bytes()).len(),
                );
            }
            emit(
                if private == 2 { "private2" } else { "private4" },
                measured_bytes(&t),
            );
        }
    }
}
