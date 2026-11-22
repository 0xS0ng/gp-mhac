//! Check holder cost formulas and encoded lengths for MHAC and TZ23.
use super::*;
use ark_serialize::CanonicalSerialize;
use gp_mhac::baselines::tz23;
use std::{fmt::Write as FmtWrite, fs::OpenOptions, path::Path};

type Cost = [u64; 3];
fn measured<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    ops::reset();
    let v = f();
    let c = ops::snapshot();
    assert_eq!(
        (c.et, c.s_sig, c.v_sig),
        (0, 0, 0),
        "no hidden signature or GT primitive in the honest path"
    );
    (v, [c.e1, c.e2, c.pairing])
}
fn sum(a: Cost, b: Cost) -> Cost {
    std::array::from_fn(|i| a[i] + b[i])
}
fn dif(a: Cost, b: Cost) -> Cost {
    std::array::from_fn(|i| a[i].checked_sub(b[i]).unwrap())
}
fn serialize(buf: &mut Vec<u8>, x: &impl CanonicalSerialize) {
    x.serialize_compressed(buf).unwrap()
}
struct Rows {
    ops: String,
    bytes: String,
}
impl Rows {
    fn op(&mut self, key: &str, stage: &str, actual: Cost, formula: Cost) {
        assert_eq!(actual, formula, "{key},{stage}");
        writeln!(
            &mut self.ops,
            "{key},{stage},{},{},{},{},{},{}",
            actual[0], actual[1], actual[2], formula[0], formula[1], formula[2]
        )
        .unwrap();
    }
    fn size(&mut self, key: &str, who: &str, stage: &str, actual: usize, formula: usize) {
        assert_eq!(actual, formula, "{key},{who},{stage}");
        writeln!(&mut self.bytes, "{key},{who},{stage},{actual},{formula}").unwrap();
    }
}

fn check_mhac(out: &mut Rows, biz: &Business, b: usize, t: usize, k: usize) {
    let w = biz.mhac();
    let pp = iss::setup(w.attrs.len(), &mut OsRng);
    let d = iss::issue(&pp, &w.attrs, &w.prv, t, 2 * t, &mut OsRng).unwrap();
    let c = MhacFixture {
        pp,
        w,
        d,
        a: (0..t).collect(),
    };
    let tr = transcript(&c); // Setup, remote messages and independent proof sanity test are outside the counters.
    let (m, p, r) = (c.pp.h.len(), c.w.prv.len(), c.w.rev.len());
    let h = m - r;
    let key = format!("mhac,{b},{k},{t},{m},{p},{h},{r}");
    for id in [1, 0] {
        let who = if id == 0 { "primary" } else { "holder" };
        let ctx = c.uncached_bases(id);
        let rmsg = early(&c, &ctx, id, tr.r);
        // Count the measured role's randomizer, commitment and opening once.
        let ((_, _), gen) = measured(|| {
            if id == 0 {
                black_box(f::step1_primary(&mut OsRng));
            }
            let (cm, st) = f::step3_commit(
                &c.pp,
                &c.d.credentials[id].local,
                &rmsg,
                &c.w.prv,
                &c.w.rev,
                0,
                SID,
                tr.nonce,
                &mut OsRng,
            )
            .unwrap();
            (cm, f::step4_open(&st))
        });
        let (_, plain) = measured(|| role(&c, &tr, id, false));
        let (_, checked) = measured(|| role(&c, &tr, id, true));
        let exp = (if id == 0 {
            m - p + t + h + 4
        } else {
            m + t + 3
        }) as u64;
        out.op(&key, &format!("{who}_plain"), sum(gen, plain), [exp, 0, 0]);
        out.op(
            &key,
            &format!("{who}_checked"),
            sum(gen, checked),
            [exp + m as u64 + 3, 0, 2],
        );
        out.op(
            &key,
            &format!("{who}_honest_detector_increment"),
            dif(checked, plain),
            [m as u64 + 3, 0, 2],
        );
    }
    // The detector receives the challenge and bases derived from this request.
    let ctx = c.uncached_bases(1);
    let mut role = early(&c, &ctx, 1, tr.r);
    bases(&ctx, tr.r, &mut role, &tr.ds, false);
    let (show, ct) = measured(|| {
        assert!(f::step5_check_commitments(1, &c.a, &tr.cs, &tr.os, SID, tr.nonce).is_empty());
        assert!(check_slots(&c, &tr, &tr.zs, tr.zs[1].ch));
        let pf = f::assemble(&role, &tr.zs, &ctx.hidden, &c.w.prv, 0).unwrap();
        assert!(f::mhac_verify(&c.pp, &c.d.x2, &pf, &ctx.rev, SID, tr.nonce));
        pf
    });
    out.op(&key, "honest_detector", ct, [m as u64 + 3, 0, 2]);
    let (ok, ct) = measured(|| f::mhac_verify(&c.pp, &c.d.x2, &show, &ctx.rev, SID, tr.nonce));
    assert!(ok);
    out.op(&key, "verifier", ct, [m as u64 + 3, 0, 2]);
    let mut grand = 0;
    for &id in &c.a {
        let who = if id == 0 { "primary" } else { "holder" };
        let mut rounds: [Vec<u8>; 4] = std::array::from_fn(|_| Vec::new());
        if id == 0 {
            serialize(&mut rounds[0], &tr.r);
        }
        rounds[1].extend_from_slice(&tr.cs[id].commitment);
        serialize(&mut rounds[1], &tr.ds[id].d);
        rounds[1].extend_from_slice(&tr.ds[id].signature.to_bytes());
        serialize(&mut rounds[2], &tr.os[id].u);
        let z = &tr.zs[id];
        serialize(&mut rounds[3], &z.z_e);
        for (_, v) in &z.z_prv {
            serialize(&mut rounds[3], v);
        }
        if let Some(v) = z.z_r {
            serialize(&mut rounds[3], &v);
        }
        for (_, v) in &z.z_other {
            serialize(&mut rounds[3], v);
        }
        let expected = [
            if id == 0 { 32 } else { 0 },
            160,
            48,
            32 * (if id == 0 { h + 2 } else { p + 1 }),
        ];
        let lens = rounds.map(|r| r.len());
        assert_eq!(lens, expected);
        // Check the round lengths for every sender; emit per-role records only for the Primary and first holder.
        if id < 2 {
            for (i, &v) in lens.iter().enumerate() {
                out.size(&key, who, &format!("round{}", i + 1), v, expected[i]);
            }
            out.size(
                &key,
                who,
                "all_rounds",
                lens.iter().sum(),
                expected.iter().sum(),
            );
            out.size(
                &key,
                who,
                "stored_share",
                c.d.credentials[id].counted_bytes().len(),
                208 + 32 * p,
            );
        }
        grand += lens.iter().sum::<usize>();
    }
    assert_eq!(grand, measured_bytes(&tr));
    out.size(
        &key,
        "committee",
        "joint_excluding_final",
        grand,
        (240 + 32 * p) * t + 32 * (h - p + 2),
    );
    out.size(
        &key,
        "external",
        "final_proof",
        show.to_bytes().len(),
        96 + 32 * (h + 3),
    );
}

fn check_tz(out: &mut Rows, biz: &Business, b: usize, t: usize, k: usize) {
    let z = biz.tz();
    let m = z.attrs.len();
    let r = z.rev.len();
    let h = m - r;
    let key = format!("tz23,{b},{k},{t},{m},NA,{h},{r}"); // t labels the paired MHAC case only
    let pp = tz23::setup(m, &mut OsRng);
    let (sk, vk) = tz23::keygen(&pp, &mut OsRng);
    let sig = tz23::sign(&pp, &sk, &z.attrs, &mut OsRng).unwrap();
    let (pf, ct) =
        measured(|| tz23::pok_prove(&pp, &vk, &z.attrs, &sig, &z.rev, &mut OsRng).unwrap());
    out.op(&key, "single_holder", ct, [(m + h + 5) as u64, 0, 0]);
    let disc = z.rev.iter().map(|&j| z.attrs[j]).collect::<Vec<_>>();
    let (ok, ct) = measured(|| tz23::pok_verify(&pp, &vk, &z.rev, &disc, &pf));
    assert!(ok);
    out.op(&key, "verifier", ct, [(m + 3) as u64, 0, 2]);
    out.size(
        &key,
        "single_holder",
        "stored_signature",
        sig.to_bytes().len(),
        80,
    );
    out.size(
        &key,
        "external",
        "final_proof",
        pf.to_bytes().len(),
        96 + 32 * (h + 3),
    );
}

/// Check each size and operation formula and save observed versus expected counts.
pub fn run(dir: &Path) {
    let mut out=Rows{ops:"scheme,business_m,business_private,paired_t,m,prv,hid,rev,window,actual_e1,actual_e2,actual_p,expected_e1,expected_e2,expected_p\n".into(),
 bytes:"scheme,business_m,business_private,paired_t,m,prv,hid,rev,who,object,actual_bytes,expected_bytes\n".into()};
    // Last control also changes disclosure ratio and m: it discriminates a
    // genuine symbolic formula from a constant specialized to m=15, h=7.
    for (b, k, r, t) in [
        (14, 2, 8, 5),
        (14, 2, 8, 20),
        (14, 2, 8, 50),
        (14, 4, 8, 5),
        (18, 3, 5, 7),
    ] {
        let biz = Business::fixture(b, k, r);
        check_mhac(&mut out, &biz, b, t, k);
        check_tz(&mut out, &biz, b, t, k);
    }
    for (name, data) in [
        ("mhac_tz_ops.csv", out.ops),
        ("mhac_tz_lengths.csv", out.bytes),
    ] {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dir.join(name))
            .unwrap();
        f.write_all(data.as_bytes()).unwrap();
    }
}
