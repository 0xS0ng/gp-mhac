//! Balanced randomized complete blocks over local, LAN and WAN conditions.
use super::*;
use ark_std::rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    fs::{File, OpenOptions},
    io::BufWriter,
};

const NS: [usize; 6] = [6, 10, 20, 40, 70, 100];
const SEED: u64 = 2026112103;
const PREFIX: &str = "block,phase,sample,order,scheme,n,condition,pool_id";
const CONDITIONS: [&str; 3] = ["LOCAL", "LAN", "WAN"];
const MODELS: [Model; 3] = [
    Model {
        rtt_ms: 0.,
        mbps: 0.,
    },
    Model {
        rtt_ms: 1.,
        mbps: 1000.,
    },
    Model {
        rtt_ms: 20.,
        mbps: 200.,
    },
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Trial {
    block: usize,
    order: usize,
    cell: usize,
    condition: usize,
}
fn scheme(cell: usize) -> &'static str {
    if cell < 6 {
        "gp-mhac"
    } else {
        "mhac"
    }
}
fn n(cell: usize) -> usize {
    NS[cell % 6]
}
fn active_for(tr: Trial) -> Vec<usize> {
    let holders = n(tr.cell);
    gp_mhac::workload::draw_threshold(holders, holders / 2, tr.block)
}
fn schedule(warm: usize, reps: usize) -> Vec<Trial> {
    // In each phase and cell, each aligned group of six blocks uses all six condition orders once.
    // A final partial group uses a prefix of a freshly shuffled permutation list.
    let perm = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut result = Vec::new();
    for (offset, size) in [(0, warm), (warm, reps)] {
        let mut bags = [perm; 12];
        for i in 0..size {
            if i % 6 == 0 {
                for b in &mut bags {
                    b.shuffle(&mut rng);
                }
            }
            let mut cells: Vec<usize> = (0..12).collect();
            cells.shuffle(&mut rng);
            for cell in cells {
                for condition in bags[cell][i % 6] {
                    result.push(Trial {
                        block: offset + i,
                        order: result.len(),
                        cell,
                        condition,
                    });
                }
            }
        }
    }
    result
}
fn prefix(tr: Trial, warm: usize) -> String {
    let (phase, sample) = if tr.block < warm {
        ("warmup", String::new())
    } else {
        ("measured", (tr.block - warm).to_string())
    };
    format!(
        "{},{phase},{sample},{},{},{},{},p{:02}",
        tr.block,
        tr.order,
        scheme(tr.cell),
        n(tr.cell),
        CONDITIONS[tr.condition],
        tr.cell
    )
}
fn open_new(dir: &Path, name: &str) -> io::Result<BufWriter<File>> {
    Ok(BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))?,
    ))
}
fn manifest(dir: &Path, trials: &[Trial], warm: usize) -> io::Result<()> {
    let mut file = open_new(dir, "plan.csv")?;
    writeln!(file, "{PREFIX}")?;
    for &tr in trials {
        writeln!(file, "{}", prefix(tr, warm))?;
    }
    file.flush()?;
    file.get_ref().sync_all()
}
struct Pool {
    peers: Vec<Peer>,
    bytes: Vec<usize>,
}
pub(super) fn campaign(args: &[String]) -> io::Result<()> {
    check(
        args.len() == 1 || args.len() == 3,
        "usage: bench_network NEW_DIR [WARMUPS REPS]",
    )?;
    let (warm, reps) = if args.len() == 3 {
        (
            args[1].parse::<usize>().map_err(invalid)?,
            args[2].parse::<usize>().map_err(invalid)?,
        )
    } else {
        (10, 100)
    };
    check(
        reps > 0 && warm <= 10000 && reps <= 10000,
        "invalid warmups/repetitions",
    )?;
    let dir = Path::new(&args[0]);
    // A directory is exclusively owned by a single invocation. Never append
    // another campaign to a partial data set if the machine/run was interrupted.
    fs::create_dir(dir)?;
    let trials = schedule(warm, reps);
    manifest(dir, &trials, warm)?;
    let mut pool_table = open_new(dir, "pools.csv")?;
    writeln!(pool_table, "pool_id,scheme,n,holder,pid")?;
    let mut pools = Vec::new();
    for cell in 0..12 {
        let peers = start(scheme(cell), n(cell))?;
        for p in &peers {
            writeln!(
                pool_table,
                "p{cell:02},{},{},{},{}",
                scheme(cell),
                n(cell),
                p.id,
                p.child.0.id()
            )?;
        }
        pools.push(Pool {
            peers,
            bytes: round_bytes(cell < 6, n(cell) / 2),
        });
    }
    pool_table.flush()?;
    pool_table.get_ref().sync_all()?;
    drop(pool_table);
    let mut raw = open_new(dir, "raw.partial")?;
    writeln!(raw,"{PREFIX},elapsed_ms,wait_ms,nonwait_ms,barriers,logical_bytes,model_floor_ms,wait1_ms,wait2_ms,wait3_ms,wait4_ms,wait5_ms")?;
    for tr in &trials {
        let model = MODELS[tr.condition];
        let p = &mut pools[tr.cell];
        let active = active_for(*tr);
        let (elapsed, waits) = timed_sample(&mut p.peers, &active, tr.cell < 6, model, &p.bytes)?;
        let logical = p.bytes.iter().sum::<usize>();
        let count = p.bytes.len();
        let floor = if tr.condition == 0 {
            0.
        } else {
            model.rtt_ms * count as f64 + logical as f64 * 8. / (1000. * model.mbps)
        };
        let wait = waits.iter().sum::<f64>();
        let nonwait = elapsed - wait;
        // Clock granularity/Duration nanosecond rounding: at most 0.5ns per
        // converted barrier. Actual elapsed must cover every measured span.
        check(
            wait + 0.000005 >= floor && nonwait > 0. && nonwait.is_finite(),
            "invalid injected/elapsed timing",
        )?;
        write!(
            raw,
            "{},{elapsed:.9},{wait:.9},{nonwait:.9},{count},{logical},{floor:.9}",
            prefix(*tr, warm)
        )?;
        for (k, v) in waits.iter().enumerate() {
            if k < count {
                write!(raw, ",{v:.9}")?;
            } else {
                write!(raw, ",")?;
            }
        }
        writeln!(raw)?;
        if (tr.order + 1) % 36 == 0 {
            raw.flush()?;
            if (tr.block + 1) % 5 == 0 || tr.block + 1 == warm + reps {
                eprintln!("Complete blocks: {}/{}", tr.block + 1, warm + reps);
            }
        }
    }
    raw.flush()?;
    raw.get_ref().sync_all()?;
    drop(raw);
    for pool in &mut pools {
        for peer in &mut pool.peers {
            write_frame(&mut peer.s, b"STOP")?;
        }
    }
    for pool in pools {
        for mut peer in pool.peers {
            check(
                peer.child.0.wait()?.success(),
                "holder process exit failure",
            )?;
        }
    }
    fs::rename(dir.join("raw.partial"), dir.join("network.csv"))?;
    let network = fs::read_to_string(dir.join("network.csv"))?;
    let mut local = open_new(dir, "e2e.csv")?;
    for (index, row) in network.lines().enumerate() {
        if index == 0 || row.split(',').nth(6) == Some("LOCAL") {
            writeln!(local, "{row}")?;
        }
    }
    local.flush()?;
    local.get_ref().sync_all()?;
    eprintln!(
        "Completed: {} samples including {} warmups; {} measured; seed={SEED}",
        trials.len(),
        warm * 36,
        reps * 36
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn committee_is_shared_by_schemes_and_link_models() {
        for block in schedule(10, 100).chunks_exact(36) {
            let mut sets: [Option<Vec<usize>>; 6] = Default::default();
            for &trial in block {
                let active = active_for(trial);
                assert!(valid_committee(&active, n(trial.cell)));
                let entry = &mut sets[trial.cell % 6];
                assert_eq!(entry.get_or_insert_with(|| active.clone()), &active);
            }
            assert!(sets.iter().all(Option::is_some));
        }
        for cell in 0..6 {
            let sampled: BTreeSet<_> = (0..110)
                .map(|block| {
                    active_for(Trial {
                        block,
                        order: 0,
                        cell,
                        condition: 0,
                    })
                })
                .collect();
            assert!(sampled.len() > 1);
            assert!(sampled.iter().any(|ids| ids[0] > 0));
            assert!(sampled.iter().flatten().any(|id| *id >= n(cell) / 2));
        }
    }

    #[test]
    fn schedule_is_complete_reproducible_and_balanced() {
        let tt = schedule(10, 100);
        assert_eq!(tt.len(), 3960);
        assert_eq!(tt, schedule(10, 100));
        for (b, block) in tt.chunks_exact(36).enumerate() {
            let mut seen = BTreeSet::new();
            for (k, r) in block.iter().enumerate() {
                assert_eq!(r.block, b);
                assert_eq!(r.order, b * 36 + k);
                assert!(seen.insert((r.cell, r.condition)));
            }
            for g in block.chunks_exact(3) {
                assert!(g.iter().all(|x| x.cell == g[0].cell));
            }
        }
        for cell in 0..12 {
            for phase in [&tt[..360], &tt[360..]] {
                let orders: Vec<_> = phase
                    .chunks_exact(3)
                    .filter(|g| g[0].cell == cell)
                    .map(|g| (g[0].condition, g[1].condition, g[2].condition))
                    .collect();
                for six in orders.chunks_exact(6) {
                    assert_eq!(six.iter().collect::<BTreeSet<_>>().len(), 6);
                }
            }
        }
    }
}
