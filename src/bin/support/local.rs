//! Local issuance, presentation, verification, storage and detector measurements.
use super::mhac_cost::MhacFixture;
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, Zero};
use ark_std::rand::rngs::OsRng;
use gp_mhac::workload::{draw_index, draw_threshold, Business, Workload};
use gp_mhac::{
    access::{compile_access, CompiledAccess, Reconstruction},
    detect::{
        detect_cached, envelopes_from_transcript, AuthenticatedEnvelope, DecodedMessage as D,
        DetectOutcome,
    },
    issuance::{self, cred_iss, IssuerKeys, Parameters, PreCred},
    lsss::{compile_formula, disjunction, dnf_chain, threshold, Formula, Lsss},
    presentation::*,
};
use gp_mhac::{baselines::tz23, primitives::hash::hash_to_g1};
use std::{
    collections::BTreeSet,
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    time::Instant,
};

const GRID: [usize; 6] = [6, 10, 20, 40, 70, 100];
const CTX: &[u8] = b"bench/application";

fn timed<T>(operation: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    let val = black_box(operation());
    (val, start.elapsed().as_secs_f64() * 1000.)
}

#[derive(Clone, Copy)]
enum Policy {
    Threshold(usize, usize),
    Case(char),
}
impl Policy {
    fn make(self) -> (Lsss, usize) {
        match self {
            Self::Threshold(t, n) => (threshold(t, n), n),
            Self::Case('A') => Self::Threshold(3, 6).make(),
            Self::Case('B') => Self::Threshold(6, 12).make(),
            Self::Case('C') => (disjunction(12, 1), 12),
            Self::Case('D') => (dnf_chain(4), 12),
            Self::Case('E') => (
                Lsss {
                    matrix: threshold(6, 12).matrix,
                    rho: (0..12).map(|i| i / 2).collect(),
                },
                12,
            ),
            Self::Case('F') => {
                let a = Formula::Thr(3, (0..6).map(Formula::Leaf).collect());
                let b = Formula::Thr(2, (6..12).map(Formula::Leaf).collect());
                (compile_formula(&Formula::Thr(2, vec![a, b])), 12)
            }
            _ => unreachable!(),
        }
    }
    fn draw(self, round: usize) -> Vec<usize> {
        match self {
            Self::Threshold(t, n) => draw_threshold(n, t, round),
            Self::Case('A') => draw_threshold(6, 3, round),
            Self::Case('B') => draw_threshold(12, 6, round),
            Self::Case('C') => vec![draw_index(12, round, 0x0043_4153_4543)],
            Self::Case('D') => {
                let first = 3 * draw_index(4, round, 0x0043_4153_4544);
                (first..first + 3).collect()
            }
            Self::Case('E') => draw_threshold(6, 3, round)
                .into_iter()
                .flat_map(|h| [2 * h, 2 * h + 1])
                .collect(),
            Self::Case('F') => {
                let mut rows = draw_threshold(6, 3, round);
                rows.extend(draw_threshold(6, 2, round).into_iter().map(|h| h + 6));
                rows
            }
            _ => unreachable!(),
        }
    }
}
struct GpFixture {
    w: Workload,
    pi: Parameters,
    sk: IssuerKeys,
    access: CompiledAccess,
    rows: Vec<usize>,
    cred: Vec<PreCred>,
}
impl GpFixture {
    fn new(w: Workload, policy: Policy) -> Self {
        let (l, n) = policy.make();
        let access = compile_access(l, n);
        let pi = issuance::setup(w.attrs.len(), &mut OsRng);
        let sk = issuance::iss_keygen(&pi, &mut OsRng);
        let cred = cred_iss(&pi, &sk, &w.attrs, &w.prv, &access, &mut OsRng).unwrap();
        assert_eq!(w.j_pid, Some(0));
        assert!(!w.attrs[0].is_zero());
        Self {
            w,
            pi,
            sk,
            access,
            rows: Vec::new(),
            cred,
        }
    }
    fn revealed(&self) -> Vec<(usize, Fr)> {
        self.w.rev.iter().map(|&i| (i, self.w.attrs[i])).collect()
    }
    fn show(&self, nonce: [u8; 32]) -> (Presentation, Transcript) {
        cred_pres(
            &self.pi,
            &self.sk.ipk,
            &self.cred,
            &self.w.attrs,
            &self.w.prv,
            &self.access,
            &self.rows,
            &self.w.rev,
            CTX,
            nonce,
            &mut OsRng,
        )
        .unwrap()
    }
    fn verify(&self, p: &Presentation, nonce: [u8; 32]) -> bool {
        vf_pres(
            &self.pi,
            &self.sk.ipk,
            p,
            &self.revealed(),
            self.w.j_pid.unwrap(),
            CTX,
            nonce,
        )
    }
    fn detect(
        &self,
        holder: usize,
        op: &G1Projective,
        env: &[AuthenticatedEnvelope],
        coin: &VerifiedCoin,
        reconstruction: &Reconstruction,
        nonce: [u8; 32],
    ) -> DetectOutcome {
        detect_cached(
            &self.pi,
            &self.sk.ipk,
            &self.cred[holder].a_sig,
            op,
            &self.access,
            &self.rows,
            reconstruction,
            env,
            coin,
            &self.revealed(),
            &self.cred[holder].pub_attrs,
            &self.w.prv,
            self.w.j_pid.unwrap(),
            CTX,
            nonce,
        )
    }
}
fn nonce(i: usize) -> [u8; 32] {
    let mut n = [0x5A; 32];
    n[..8].copy_from_slice(&(i as u64).to_le_bytes());
    n
}
fn context_base() -> G1Projective {
    hash_to_g1(b"GP-MHAC-NYM-v1", CTX)
}
fn round2_aggregate(open: &[Round1Opening]) -> Round2Public {
    Round2Public {
        c_prv: open.iter().fold(G1Projective::zero(), |s, x| s + x.c_hat),
        nym: open.iter().fold(G1Projective::zero(), |s, x| s + x.n),
    }
}
fn env(r: u8, sender: usize, p: D) -> AuthenticatedEnvelope {
    AuthenticatedEnvelope {
        round: r,
        sender,
        payload: Ok(p),
    }
}

// Time the actual local work of the Primary and the first non-Primary on one
// consistent fresh execution. Other parties' work and orchestrator bookkeeping
// are outside both role clocks. Each measured role derives its state without caching.
fn roles(g: &GpFixture, nonce: [u8; 32]) -> [(f64, f64); 2] {
    let (w, l) = (&g.w, &g.access.lsss);
    // Schedule actors from the support. Each holder still reconstructs from the request on its own clock.
    let schedule = g.access.reconstruct(&g.rows).unwrap();
    let rows = schedule.rows();
    let active = rows
        .iter()
        .map(|&r| l.rho[r])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let primary = active[0];
    assert!(active.len() >= 2);
    let targets = [primary, active[1]];
    let mut base = [0.; 2];
    let (mut messages, mut states, mut prep) = (Vec::new(), Vec::new(), Vec::new());
    for (i, &h) in active.iter().enumerate() {
        let ((msg, state, omega, ssid, base_point, reconstruction), ms) = timed(|| {
            let reconstruction = g.access.reconstruct(&g.rows).unwrap();
            let rows = reconstruction.rows();
            let weight = reconstruction.coefficients();
            let omega = rows
                .iter()
                .map(|&r| {
                    (
                        r,
                        weight
                            .iter()
                            .find(|(j, _)| *j == r)
                            .map(|(_, v)| *v)
                            .unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>();
            let ssid = derive_ssid(
                &g.sk.ipk.header(CTX),
                &g.cred[h].asid,
                &g.cred[h].a_sig,
                rows,
                &w.rev,
                &nonce,
            );
            let base_point = context_base();
            let (msg, state) = round1_holder_cached(
                &base_point,
                &g.pi,
                &g.cred[h],
                h,
                rows,
                &omega,
                &w.prv,
                &ssid,
                &mut OsRng,
            )
            .unwrap();
            (msg, state, omega, ssid, base_point, reconstruction)
        });
        if i < 2 {
            base[i] += ms;
        }
        states.push(state);
        messages.push(msg);
        prep.push((omega, ssid, base_point, reconstruction));
    }
    let mut open = Vec::new();
    let mut seeds = Vec::new();
    for (i, s) in states.iter().enumerate() {
        let ((a, b), ms) = timed(|| (s.opening(), s.seed_opening()));
        if i < 2 {
            base[i] += ms;
        }
        open.push(a);
        seeds.push(b);
    }
    let ((r3, primary_state), ms) = timed(|| {
        // A presenting party has the public attribute coordinates and its own
        // row shares, not the issuer's underlying private attribute values.
        let mut public_view = vec![Fr::zero(); g.pi.h.len()];
        for &(idx, value) in &g.cred[primary].pub_attrs {
            public_view[idx] = value;
        }
        round3_primary(
            &g.pi,
            &g.cred[primary].a_sig,
            &public_view,
            &w.prv,
            &w.rev,
            rows,
            &prep[0].0,
            &messages,
            &open,
            CTX,
            &prep[0].1,
            nonce,
            &mut OsRng,
        )
        .unwrap()
    });
    base[0] += ms;
    let mut envelopes = Vec::new();
    envelopes.extend(
        messages
            .iter()
            .map(|x| env(1, x.holder, D::Round1(x.clone()))),
    );
    envelopes.extend(open.iter().map(|x| env(2, x.holder, D::Round2(x.clone()))));
    envelopes.push(env(3, primary, D::Round3(r3.clone())));
    envelopes.extend(
        seeds
            .iter()
            .map(|x| env(4, x.holder, D::Round4Seed(x.clone()))),
    );
    let mut coins = Vec::new();
    for (i, &h) in active.iter().enumerate() {
        let ((c, payload), ms) = timed(|| {
            let r2 = round2_aggregate(&open);
            let ah: Vec<_> = messages.iter().map(|m| m.holder).collect();
            let c = verify_round4_coin(
                &g.sk.ipk,
                &messages,
                &seeds,
                rows,
                &ah,
                &r2,
                &r3,
                &g.revealed(),
                CTX,
                &prep[i].1,
                nonce,
            )
            .unwrap();
            let payload = if i == 0 {
                let (holder, primary) = round5_primary(&states[i], &primary_state, &c);
                D::Round5Primary { holder, primary }
            } else {
                D::Round5Holder(round5_holder(&states[i], &c))
            };
            (c, payload)
        });
        if i < 2 {
            base[i] += ms;
            coins.push(c);
        }
        envelopes.push(env(5, h, payload));
    }
    std::array::from_fn(|i| {
        let (out, det) = timed(|| {
            g.detect(
                targets[i], &prep[i].2, &envelopes, &coins[i], &prep[i].3, nonce,
            )
        });
        assert!(matches!(out, DetectOutcome::Pres(_)));
        (base[i], base[i] + det)
    })
}

type Values = Vec<(&'static str, f64)>;
struct Out {
    file: BufWriter<File>,
    warm: usize,
    samples: usize,
    experiment: &'static str,
}
impl Out {
    fn open(path: &std::path::Path, experiment: &'static str, warm: usize, samples: usize) -> Self {
        let mut file = BufWriter::new(
            File::options()
                .write(true)
                .create_new(true)
                .open(path)
                .expect("new output CSV"),
        );
        writeln!(file, "experiment,scheme,series,x,sample,value,unit").unwrap();
        Self {
            file,
            experiment,
            warm,
            samples,
        }
    }
    fn record(&mut self, s: &str, x: impl std::fmt::Display, i: usize, values: Values) {
        if i >= self.warm {
            for (series, v) in values {
                assert!(v.is_finite() && v >= 0.);
                writeln!(
                    self.file,
                    "{},{s},{series},{x},{},{v:.9},ms",
                    self.experiment,
                    i - self.warm
                )
                .unwrap();
            }
        }
    }
    fn run(
        &mut self,
        e: &str,
        s: &str,
        x: impl ToString,
        u: &str,
        mut f: impl FnMut(usize) -> Vec<(&'static str, f64)>,
    ) {
        let x = x.to_string();
        eprintln!("{e}/{s}/{x}");
        for i in 0..self.warm + self.samples {
            let r = f(i);
            if i >= self.warm {
                for (series, val) in r {
                    assert!(val.is_finite() && val >= 0.);
                    writeln!(
                        self.file,
                        "{e},{s},{series},{x},{},{val:.9},{u}",
                        i - self.warm
                    )
                    .unwrap();
                }
            }
        }
        self.file.flush().unwrap();
    }
    fn want(&self, name: &str) -> bool {
        self.experiment == name
    }
}

fn policy_trial(e: &str, p: Policy, g: &mut GpFixture, i: usize) -> Values {
    g.rows = p.draw(i);
    let n = nonce(i);
    let mut vals = Vec::new();
    if e == "access" {
        let (_, ms) = timed(|| {
            let params = issuance::setup(g.w.attrs.len(), &mut OsRng);
            let k = issuance::iss_keygen(&params, &mut OsRng);
            (params, k)
        });
        vals.push(("iss_setup", ms));
    }
    let (_, ms) = timed(|| {
        let (l, n) = p.make();
        compile_access(l, n)
    });
    vals.push(("compile_access", ms));
    let (_, ms) =
        timed(|| cred_iss(&g.pi, &g.sk, &g.w.attrs, &g.w.prv, &g.access, &mut OsRng).unwrap());
    vals.push(("iss", ms));
    // Joint CredPres is serial here; the network driver times separate holders.
    let ((pres, trace), ms) = timed(|| g.show(n));
    vals.push(("end_to_end", ms));
    let envelopes = envelopes_from_transcript(&g.access, &g.rows, &trace);
    // The caller supplies the hash base established during this presentation.
    let base = context_base();
    let (out, ms) = timed(|| {
        g.detect(
            trace.primary,
            &base,
            &envelopes,
            trace.verified_coin(),
            trace.reconstruction().unwrap(),
            n,
        )
    });
    assert!(matches!(out, DetectOutcome::Pres(_)));
    vals.push(("detect_total", ms));
    let (valid, ms) = timed(|| g.verify(&pres, n));
    assert!(valid);
    vals.push(("verify", ms));
    vals
}

fn gp_detection(g: &GpFixture, i: usize) -> Values {
    let nonce = nonce(i);
    let (_, tr) = g.show(nonce);
    let honest = envelopes_from_transcript(&g.access, &g.rows, &tr);
    let culprit = tr.active_holders[1];
    let pr = tr.primary;
    let prefix = honest
        .iter()
        .filter(|m| m.round < 2 || (m.round == 2 && m.sender != culprit))
        .cloned()
        .collect::<Vec<_>>();
    let mut full = honest.clone();
    match &mut full
        .iter_mut()
        .find(|m| m.round == 5 && m.sender == pr)
        .unwrap()
        .payload
    {
        Ok(D::Round5Primary { primary, .. }) => primary.z_first_randomizer += Fr::one(),
        _ => unreachable!(),
    }
    let cases = [
        ("honest", honest, None),
        ("withhold", prefix, Some(culprit)),
        ("full_blame", full, Some(pr)),
    ];
    // The round-1 base belongs to this request (all detectors already
    // computed it online). Rotating path order avoids a fixed FIFO bias.
    let base = context_base();
    let mut out = Vec::new();
    for j in 0..3 {
        let (name, ref inp, who) = cases[(i + j) % 3];
        let (result, ms) = timed(|| {
            g.detect(
                tr.active_holders[2],
                &base,
                inp,
                tr.verified_coin(),
                tr.reconstruction().unwrap(),
                nonce,
            )
        });
        match (result, who) {
            (DetectOutcome::Pres(_), None) => (),
            (DetectOutcome::Abort(b), Some(h)) => assert_eq!(b, BTreeSet::from([h])),
            _ => panic!("wrong GP-MHAC detection path"),
        }
        out.push((name, ms));
    }
    out
}

struct TzFixture {
    w: Workload,
    pp: tz23::Parameters,
    vk: tz23::VerificationKey,
    sig: tz23::Signature,
}
impl TzFixture {
    fn new(b: &Business) -> Self {
        let w = b.tz();
        let pp = tz23::setup(w.attrs.len(), &mut OsRng);
        let (sk, vk) = tz23::keygen(&pp, &mut OsRng);
        let sig = tz23::sign(&pp, &sk, &w.attrs, &mut OsRng).unwrap();
        Self { w, pp, vk, sig }
    }
    fn show(&self) -> tz23::PokProof {
        tz23::pok_prove(
            &self.pp,
            &self.vk,
            &self.w.attrs,
            &self.sig,
            &self.w.rev,
            &mut OsRng,
        )
        .unwrap()
    }
    fn verify(&self, p: &tz23::PokProof) -> bool {
        let vals: Vec<_> = self.w.rev.iter().map(|&j| self.w.attrs[j]).collect();
        tz23::pok_verify(&self.pp, &self.vk, &self.w.rev, &vals, p)
    }
}
fn order(round: usize, grid: usize, k: usize, count: usize) -> usize {
    (round + grid + k) % count
}
fn compared_grid(experiment: &str) -> &'static [usize] {
    match experiment {
        "roles" => &GRID,
        "detection" => &[10, 40, 100],
        _ => unreachable!(),
    }
}
fn local_comparison(o: &mut Out, b: &Business, n: usize, grid_index: usize) {
    let p = Policy::Threshold(n / 2, n);
    let mut gp = GpFixture::new(b.gp(&mut OsRng), p);
    let mut mh = MhacFixture::new(b, n);
    let z = TzFixture::new(b);
    let count = if o.want("roles") { 3 } else { 2 };
    for i in 0..o.samples + o.warm {
        gp.rows = p.draw(i);
        mh.select(&gp.rows);
        for step in 0..count {
            let scheme = order(i, grid_index, step, count);
            let values = match (o.experiment, scheme) {
                ("roles", 0) => {
                    let [pr, ho] = roles(&gp, nonce(i));
                    vec![
                        ("holder_plain", ho.0),
                        ("holder_checked", ho.1),
                        ("primary_plain", pr.0),
                        ("primary_checked", pr.1),
                    ]
                }
                ("roles", 1) => mh.measure_roles(i),
                ("roles", 2) => {
                    let (q, ms) = timed(|| z.show());
                    assert!(z.verify(&q));
                    vec![("holder_plain", ms)]
                }
                ("detection", 0) => gp_detection(&gp, i),
                ("detection", 1) => mh.measure_detection(i),
                _ => unreachable!(),
            };
            o.record(["gp-mhac", "mhac", "tz23"][scheme], n, i, values);
        }
    }
    o.file.flush().unwrap();
}
fn verify_grid(o: &mut Out, b: &Business, n: usize, x: usize, grid_index: usize) {
    let p = Policy::Threshold(n / 2, n);
    let mut gp = GpFixture::new(b.gp(&mut OsRng), p);
    let mut mh = MhacFixture::new(b, n);
    let z = TzFixture::new(b);
    for i in 0..o.samples + o.warm {
        gp.rows = p.draw(i);
        mh.select(&gp.rows);
        let nn = nonce(i);
        let (mut a, mut b, mut c) = (None, None, None);
        for step in 0..3 {
            match order(i / 3, grid_index, step, 3) {
                0 => a = Some(gp.show(nn).0),
                1 => b = Some(mh.show()),
                2 => c = Some(z.show()),
                _ => unreachable!(),
            }
        }
        let (gp_pf, (mh_pf, mh_nonce), tz_pf) = (a.unwrap(), b.unwrap(), c.unwrap());
        let mut times = [0.; 3];
        for step in 0..3 {
            let scheme = order(i, grid_index, step, 3);
            let (ok, ms) = timed(|| match scheme {
                0 => gp.verify(&gp_pf, nn),
                1 => mh.verify(&mh_pf, mh_nonce),
                2 => z.verify(&tz_pf),
                _ => unreachable!(),
            });
            assert!(ok);
            times[scheme] = ms;
        }
        for step in 0..3 {
            let scheme = order(i, grid_index, step, 3);
            o.record(
                ["gp-mhac", "mhac", "tz23"][scheme],
                x,
                i,
                vec![("verify", times[scheme])],
            );
        }
    }
    o.file.flush().unwrap();
}
fn sizes(o: &mut Out, biz: &Business) {
    for n in GRID {
        let p = Policy::Threshold(n / 2, n);
        {
            let g = GpFixture::new(biz.gp(&mut OsRng), p);
            o.run("sizes", "gp-mhac", n, "bytes", |i| {
                let c = &g.cred[i % n];
                let bytes = c.credential_bytes().len();
                assert_eq!(bytes, issuance::credential_size_bytes(c, g.w.prv.len()));
                vec![("storage", bytes as f64)]
            });
            let z = biz.tz();
            let zp = tz23::setup(z.attrs.len(), &mut OsRng);
            let (sk, _) = tz23::keygen(&zp, &mut OsRng);
            o.run("sizes", "tz23", n, "bytes", |_| {
                let q = tz23::sign(&zp, &sk, &z.attrs, &mut OsRng).unwrap();
                vec![("storage", q.to_bytes().len() as f64)]
            });
        }
        {
            for k in [2, 4] {
                let b = Business::fixture(14, k, 8);
                let mut g = GpFixture::new(b.gp(&mut OsRng), p);
                let name = if k == 2 { "private2" } else { "private4" };
                o.run("sizes", "gp-mhac", n, "bytes", |i| {
                    g.rows = p.draw(i);
                    let (_, tr) = g.show(nonce(i));
                    let bytes =
                        transcript_bytes(&tr, g.w.prv.len(), g.w.attrs.len() - g.w.rev.len());
                    vec![(name, bytes as f64)]
                });
            }
        }
    }
    for n in GRID {
        super::mhac_cost::measure_sizes(n, o.warm, o.samples, &mut o.file);
    }
}
/// Measures the requested local costs, retaining all post-warmup observations.
pub fn run(experiment: &'static str) {
    let args: Vec<_> = env::args_os().collect();
    assert_eq!(args.len(), 2, "expected an output CSV path");
    let path = std::path::Path::new(&args[1]);
    let count = |k: &str, d| env::var(k).ok().map(|s| s.parse().unwrap()).unwrap_or(d);
    let mut o = Out::open(
        path,
        experiment,
        count("GP_MHAC_WARMUP", 10),
        count("GP_MHAC_SAMPLES", 100),
    );
    let biz = Business::fixture(14, 2, 8);
    match experiment {
        "roles" | "detection" => {
            for (k, &n) in compared_grid(experiment).iter().enumerate() {
                eprintln!("{experiment}/{n}");
                local_comparison(&mut o, &biz, n, k);
            }
        }
        "sizes" => sizes(&mut o, &biz),
        "verify" => {
            for (k, m) in [8, 16, 24, 32, 48, 64].into_iter().enumerate() {
                eprintln!("verify/attributes/{m}");
                verify_grid(&mut o, &Business::fixture(m, 2, m / 2), 10, m, k);
            }
            let mut sweep = Out::open(
                &path.with_file_name("verify_committee.csv"),
                "verify_committee",
                o.warm,
                o.samples,
            );
            for (k, n) in GRID.into_iter().enumerate() {
                eprintln!("verify/committee/{n}");
                verify_grid(&mut sweep, &biz, n, n, k);
            }
        }
        "access" | "policy" => {
            let configs: Vec<_> = if experiment == "access" {
                ['A', 'B', 'C', 'D', 'E', 'F']
                    .into_iter()
                    .map(|c| (c.to_string(), Policy::Case(c)))
                    .collect()
            } else {
                [4, 8, 12, 16, 24]
                    .into_iter()
                    .map(|d| (d.to_string(), Policy::Threshold(3, d)))
                    .collect()
            };
            let mut fixtures: Vec<_> = configs
                .into_iter()
                .map(|(x, p)| (x, p, GpFixture::new(biz.gp(&mut OsRng), p)))
                .collect();
            for i in 0..o.warm + o.samples {
                for j in 0..fixtures.len() {
                    let k = order(i, 0, j, fixtures.len());
                    let (x, p, g) = &mut fixtures[k];
                    let vals = policy_trial(experiment, *p, g, i);
                    o.record("gp-mhac", x, i, vals);
                }
            }
            o.file.flush().unwrap();
        }
        _ => unreachable!(),
    }
}
#[cfg(test)]
mod schedule_tests {
    use super::*;
    #[test]
    fn detection_alternates_the_first_scheme_across_sizes() {
        let first = compared_grid("detection")
            .iter()
            .enumerate()
            .map(|(k, &n)| (n, order(10, k, 0, 2)))
            .collect::<Vec<_>>();
        assert_eq!(first, [(10, 0), (40, 1), (100, 0)]);
    }
    #[test]
    fn sparse_committees_keep_their_sender_ids() {
        let b = Business::fixture(14, 2, 8);
        let p = Policy::Threshold(3, 6);
        let round = (0..110).find(|&i| p.draw(i)[0] > 0).unwrap();
        let mut gp = GpFixture::new(b.gp(&mut OsRng), p);
        gp.rows = p.draw(round);
        let mut mh = MhacFixture::new(&b, 6);
        mh.select(&gp.rows);
        let (_, tr) = gp.show(nonce(round));
        assert_eq!(tr.primary, gp.rows[0]);
        assert_eq!(tr.active_holders, gp.rows);
        assert_eq!(gp_detection(&gp, round).len(), 3);
        assert_eq!(mh.measure_detection(round).len(), 3);
        assert_eq!(mh.measure_roles(round).len(), 4);
    }
    #[test]
    fn rotation_visits_each_cell_once_and_balances_leads() {
        for count in [2, 3, 5, 6] {
            let mut all = vec![0; count];
            for grid in 0..6 {
                let mut lead = vec![0; count];
                for i in 0..110 {
                    let mut entries = (0..count)
                        .map(|k| order(i, grid, k, count))
                        .collect::<Vec<_>>();
                    if i >= 10 {
                        lead[entries[0]] += 1;
                    }
                    entries.sort_unstable();
                    assert_eq!(entries, (0..count).collect::<Vec<_>>());
                }
                assert!(lead.iter().max().unwrap() - lead.iter().min().unwrap() <= 1);
                for (a, l) in all.iter_mut().zip(lead) {
                    *a += l;
                }
            }
            assert!(all.iter().all(|&v| v == 600 / count));
        }
    }
    #[test]
    fn policy_draws_have_the_specified_support_and_holders() {
        for (p, ds, ns) in [
            (Policy::Case('A'), 3, 3),
            (Policy::Case('B'), 6, 6),
            (Policy::Case('C'), 1, 1),
            (Policy::Case('D'), 3, 3),
            (Policy::Case('E'), 6, 3),
            (Policy::Case('F'), 5, 5),
            (Policy::Threshold(3, 24), 3, 3),
        ] {
            let (l, _) = p.make();
            let mut draws = BTreeSet::new();
            for i in 0..110 {
                let rows = p.draw(i);
                assert_eq!(rows.len(), ds);
                assert!(rows.windows(2).all(|v| v[0] < v[1]));
                assert_eq!(
                    rows.iter()
                        .map(|&r| l.rho[r])
                        .collect::<BTreeSet<_>>()
                        .len(),
                    ns
                );
                let w = l.recon_coeffs(&rows).unwrap();
                assert!(w.iter().map(|x| x.0).eq(rows.iter().copied()));
                draws.insert(rows);
            }
            assert!(draws.len() > 1);
            if let Policy::Case('D') = p {
                assert_eq!(draws.len(), 4);
            }
        }
    }
}
