//! Verify symbolic costs against group-operation counters and canonical wire encoders.
use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::workload::Business;
use gp_mhac::{
    access::compile_access,
    detect::{detect_cached, envelopes_from_transcript, DetectOutcome},
    issuance::{self, PreCred},
    lsss::{threshold, Lsss},
    ops,
    presentation::*,
    primitives::hash::hash_to_g1,
};
use std::{collections::BTreeSet, env, fs, io::Write, path::PathBuf};

const CTX: &[u8] = b"bench/gp";
type Counts = [usize; 3]; // E1,E2,P
fn measure<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    ops::reset();
    let val = f();
    let c = ops::snapshot();
    (val, [c.e1 as usize, c.e2 as usize, c.pairing as usize])
}
fn enc<T: CanonicalSerialize>(buf: &mut Vec<u8>, x: &T) {
    x.serialize_compressed(buf).unwrap();
}

// Serialize each sender's payload to measure its length independently of the formula.
fn wire(tr: &Transcript, id: usize) -> [usize; 5] {
    let mut b: [Vec<u8>; 5] = Default::default();
    let commitment = tr.round1.iter().find(|x| x.holder == id).unwrap();
    for row in &commitment.rows {
        enc(&mut b[0], &row.d_factor);
        b[0].extend_from_slice(&row.tag.to_bytes());
    }
    b[0].extend_from_slice(&commitment.commitment);
    b[0].extend_from_slice(&commitment.seed_commitment);
    let o = tr.openings.iter().find(|x| x.holder == id).unwrap();
    for x in [&o.c_hat, &o.n, &o.v, &o.u_hat, &o.u_prime] {
        enc(&mut b[1], x);
    }
    b[1].extend_from_slice(&o.randomness);
    if id == tr.primary {
        let r = &tr.round3;
        for x in [
            &r.a_bar, &r.b_bar, &r.d, &r.v_prime, &r.u_i, &r.u_ii, &r.u_iii,
        ] {
            enc(&mut b[2], x);
        }
        enc(&mut b[2], &r.lift.c);
        enc(&mut b[2], &r.lift.z);
    }
    let s = tr.seed_openings.iter().find(|x| x.holder == id).unwrap();
    b[3].extend_from_slice(&s.kappa);
    b[3].extend_from_slice(&s.randomness);
    let r = tr.holder_responses.iter().find(|x| x.holder == id).unwrap();
    enc(&mut b[4], &r.z_e);
    for (_, x) in &r.z_prv {
        enc(&mut b[4], x);
    }
    if id == tr.primary {
        enc(&mut b[4], &tr.primary_response.z_first_randomizer);
        enc(&mut b[4], &tr.primary_response.z_r3);
        for (_, x) in &tr.primary_response.z_other {
            enc(&mut b[4], x);
        }
    }
    b.map(|v| v.len())
}

fn test_case(t: usize, k: usize, business_m: usize, rev: usize, kind: &str, out: &mut [String; 2]) {
    let multi = kind == "multi";
    let redundant = kind == "redundant";
    let mut rng = StdRng::seed_from_u64(0xc30000 + t as u64 * 128 + k as u64 + 32 * multi as u64);
    let w = Business::fixture(business_m, k, rev).gp(&mut rng);
    let m = w.attrs.len();
    let p = w.prv.len();
    let hidden: Vec<_> = (0..m).filter(|i| !w.rev.contains(i)).collect();
    let h = hidden.len();
    let revealed: Vec<_> = w.rev.iter().map(|&i| (i, w.attrs[i])).collect();
    let (policy, n) = if multi {
        (
            Lsss {
                matrix: threshold(5, 8).matrix,
                rho: vec![0, 0, 1, 1, 2, 0, 1, 3],
            },
            4,
        )
    } else {
        (threshold(t, 2 * t), 2 * t)
    };
    let candidates: Vec<_> = (0..t + usize::from(redundant)).collect();
    let access = compile_access(policy, n);
    let witness = access.reconstruct(&candidates).unwrap();
    let rows = witness.rows();
    let holders: Vec<_> = rows
        .iter()
        .map(|r| access.lsss.rho[*r])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let ns = holders.len();
    let ds = rows.len();
    assert_eq!(ds, t);
    let label = if multi || redundant {
        kind.to_owned()
    } else {
        format!("t{t}")
    };
    let params = issuance::setup(m, &mut rng);
    let sk = issuance::iss_keygen(&params, &mut rng);
    let creds: Vec<PreCred> =
        issuance::cred_iss(&params, &sk, &w.attrs, &w.prv, &access, &mut rng).unwrap();
    let nonce = [0x33; 32];
    let primary = holders[0];
    let (mut msgs, mut states, mut prep, mut per_actor) = (vec![], vec![], vec![], vec![]);
    // Each actor derives its own request-dependent inputs.
    for &id in &holders {
        let ((msg, state, local, ssid, op), c1) = measure(|| {
            let local = access.reconstruct(&candidates).unwrap();
            let coeffs = local.coefficients();
            assert_eq!(
                local.rows(),
                rows,
                "each actor must recover the same nonzero support"
            );
            let ssid = derive_ssid(
                &sk.ipk.header(CTX),
                &creds[id].asid,
                &creds[id].a_sig,
                rows,
                &w.rev,
                &nonce,
            );
            let op = hash_to_g1(b"GP-MHAC-NYM-v1", CTX);
            let (msg, state) = round1_holder_cached(
                &op, &params, &creds[id], id, rows, coeffs, &w.prv, &ssid, &mut rng,
            )
            .unwrap();
            (msg, state, local, ssid, op)
        });
        msgs.push(msg);
        states.push(state);
        prep.push((local, ssid, op));
        per_actor.push(c1);
    }
    let ((open, agg), c2) = measure(|| round2_open(&states));
    assert_eq!(c2, [0; 3]);
    let ((r3, ps), c3) = measure(|| {
        let mut pub_view = vec![Fr::zero(); m];
        for &(i, x) in &creds[primary].pub_attrs {
            pub_view[i] = x;
        }
        round3_primary(
            &params,
            &creds[primary].a_sig,
            &pub_view,
            &w.prv,
            &w.rev,
            rows,
            prep[0].0.coefficients(),
            &msgs,
            &open,
            CTX,
            &prep[0].1,
            nonce,
            &mut rng,
        )
        .unwrap()
    });
    for j in 0..3 {
        per_actor[0][j] += c3[j];
    }
    let (seeds, cs) = measure(|| round4_open(&states));
    assert_eq!(cs, [0; 3]);
    let (mut all_responses, mut primary_response, mut coins) = (vec![], None, vec![]);
    for (i, _) in holders.iter().enumerate() {
        let ((coin, holder_resp, extra), c45) = measure(|| {
            let coin = verify_round4_coin(
                &sk.ipk, &msgs, &seeds, rows, &holders, &agg, &r3, &revealed, CTX, &prep[i].1,
                nonce,
            )
            .unwrap();
            let (holder_resp, extra) = if i == 0 {
                let (a, b) = round5_primary(&states[i], &ps, &coin);
                (a, Some(b))
            } else {
                (round5_holder(&states[i], &coin), None)
            };
            (coin, holder_resp, extra)
        });
        for j in 0..3 {
            per_actor[i][j] += c45[j];
        }
        all_responses.push(holder_resp);
        if let Some(a) = extra {
            primary_response = Some(a);
        }
        coins.push(coin);
    }
    let (pres, ca) = measure(|| {
        assemble(
            &agg,
            &r3,
            &coins[0],
            &all_responses,
            &primary_response.unwrap(),
            &hidden,
            &w.prv,
        )
        .unwrap()
    });
    assert_eq!(ca, [0; 3]);
    let (valid, cv) = measure(|| vf_pres(&params, &sk.ipk, &pres, &revealed, 0, CTX, nonce));
    assert!(valid);
    let (p2, tr) = cred_pres(
        &params,
        &sk.ipk,
        &creds,
        &w.attrs,
        &w.prv,
        &access,
        &candidates,
        &w.rev,
        CTX,
        nonce,
        &mut rng,
    )
    .unwrap();
    let envs = envelopes_from_transcript(&access, &candidates, &tr);
    let sent_rows: usize = tr.round1.iter().map(|msg| msg.rows.len()).sum();
    let senders = tr.round1.len();
    assert_eq!((sent_rows, senders), (ds, ns));
    let desc =
        format!("{label},{business_m},{k},{m},{p},{h},{rev},{n},{ns},{ds},{senders},{sent_rows}");
    let push_ops = |out: &mut String,
                    role: &str,
                    id: &str,
                    di: usize,
                    ai: usize,
                    got: Counts,
                    want: Counts| {
        assert_eq!(got, want, "{desc}/{role}/{id}");
        out.push_str(&format!(
            "{desc},{role},{id},{di},{ai},{},{},{},{},{},{}\n",
            got[0], got[1], got[2], want[0], want[1], want[2]
        ));
    };
    push_ops(&mut out[0], "verifier", "NA", 0, 0, cv, [m + 7, 0, 2]);
    let mut sum = [0; 5];
    for (i, &id) in holders.iter().enumerate() {
        let di = creds[id].rows.len();
        let ai = rows.iter().filter(|&&r| access.lsss.rho[r] == id).count();
        let role = if id == primary {
            "primary"
        } else {
            "non_primary"
        };
        let expected_e1 = if id == primary {
            m + h + ds + 11
        } else {
            2 * p + 3
        };
        push_ops(
            &mut out[0],
            role,
            &id.to_string(),
            di,
            ai,
            per_actor[i],
            [expected_e1, 0, 0],
        );
        let (res, cd) = measure(|| {
            detect_cached(
                &params,
                &sk.ipk,
                &creds[id].a_sig,
                &prep[i].2,
                &access,
                &candidates,
                tr.reconstruction().unwrap(),
                &envs,
                tr.verified_coin(),
                &revealed,
                &creds[id].pub_attrs,
                &w.prv,
                0,
                CTX,
                nonce,
            )
        });
        assert!(matches!(res,DetectOutcome::Pres(ref actual) if **actual==p2));
        push_ops(
            &mut out[0],
            "honest_detector",
            &id.to_string(),
            di,
            ai,
            cd,
            [m + 7, 0, 2],
        );
        let real = wire(&tr, id);
        let expected = [
            ai * (48 + 80) + 64,
            272,
            400 * usize::from(id == primary),
            64,
            32 * (p + 1 + usize::from(id == primary) * (h - p + 2)),
        ];
        assert_eq!(real, expected, "{desc}/{role}/{id}");
        let stored = creds[id].credential_bytes().len();
        let es = 48 + di * (48 + 32 * (p + 1) + 80);
        assert_eq!(stored, es);
        assert_eq!(stored, issuance::credential_size_bytes(&creds[id], p));
        let proof = p2.to_bytes().len();
        let ep = 4 * 48 + (h + 4) * 32 + 32;
        assert_eq!(proof, ep);
        let mut row = format!("{desc},{role},{id},{di},{ai},{stored},{es}");
        for j in 0..5 {
            sum[j] += real[j];
            row.push_str(&format!(",{},{}", real[j], expected[j]));
        }
        row.push_str(&format!(",{proof},{ep}\n"));
        out[1].push_str(&row);
    }
    assert_eq!(sum, transcript_round_bytes(&tr, p, h));
    let total = sum.iter().sum::<usize>();
    assert_eq!(
        total,
        (ds + 5 * ns + 7) * 48 + ds * 80 + (ns * (p + 1) + h - p + 4) * 32 + 5 * ns * 32
    );
    eprintln!("{label} k={k}: {ns} active senders, rounds 1–5 {sum:?} = {total} bytes");
}
#[path = "support/mhac_cost.rs"]
pub mod mhac_cost;
fn main() {
    let dir = PathBuf::from(env::args_os().nth(1).expect("output directory"));
    let prefix = "policy,business_m,business_private,m,p,h,rev,n,n_s,d_s,transmitted_holders,transmitted_rows,role,holder,d_i,active_i";
    let mut out=[format!("{prefix},E1,E2,P,expected_E1,expected_E2,expected_P\n"),format!("{prefix},credential_B,expected_credential_B,round1_B,expected_round1_B,round2_B,expected_round2_B,round3_B,expected_round3_B,round4_B,expected_round4_B,round5_B,expected_round5_B,proof_B,expected_proof_B\n")];
    for (t, k, business_m, rev, kind) in [
        (5, 2, 14, 8, "threshold"),
        (20, 2, 14, 8, "threshold"),
        (50, 2, 14, 8, "threshold"),
        (5, 4, 14, 8, "threshold"),
        (5, 2, 14, 8, "multi"),
        (7, 3, 18, 5, "threshold"),
        (2, 2, 14, 8, "redundant"),
    ] {
        test_case(t, k, business_m, rev, kind, &mut out);
    }
    fs::create_dir_all(&dir).unwrap();
    mhac_cost::counts::run(&dir);
    for (file, data) in ["gp_ops.csv", "gp_bytes.csv"].iter().zip(out) {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dir.join(file))
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();
    }
}
