use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::pipeline::{Bucket, DEFAULT_MARSHAL, Tally, run_case};
use crate::rng::{GAMMA, SplitMix64};

pub struct BaseCase {
    pub name: String,
    pub quote: Vec<u8>,
    pub collateral: Vec<u8>,
    pub current_time: i64,
}

pub fn load_base(dir: &Path) -> BaseCase {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string());
    let quote = fs::read(dir.join("quote.bin"))
        .unwrap_or_else(|e| panic!("read {}/quote.bin: {e}", dir.display()));
    let collateral = fs::read(dir.join("collateral.json"))
        .unwrap_or_else(|e| panic!("read {}/collateral.json: {e}", dir.display()));
    let meta = fs::read(dir.join("meta.json"))
        .unwrap_or_else(|e| panic!("read {}/meta.json: {e}", dir.display()));
    let meta: serde_json::Value = serde_json::from_slice(&meta).expect("meta.json parses");
    let current_time = meta["current_time_unix"]
        .as_i64()
        .expect("meta.json has current_time_unix");
    BaseCase {
        name,
        quote,
        collateral,
        current_time,
    }
}

pub struct SweepOpts {
    pub iters: u64,
    pub seed: u64,
    pub bases: Vec<PathBuf>,
    pub default_bases: bool,
    pub only_iter: Option<u64>,
    pub out: PathBuf,
    /// Iterations of this seed recorded as dangerous in the allowlist (iter →
    /// finding id): each counts as known-dangerous when it fires and as
    /// vanished when it is in the run's window but no longer dangerous.
    pub allow_iters: BTreeMap<u64, String>,
}

pub struct MutatedCase {
    pub quote: Vec<u8>,
    pub collateral: Vec<u8>,
    pub current_time: i64,
    pub desc: String,
}

const QUOTE_CERT_TAIL_OFFSET: usize = 436;
const THREE_YEARS_SECS: u64 = 3 * 365 * 24 * 3600;

fn flip_random_bits(
    data: &mut [u8],
    rng: &mut SplitMix64,
    byte_lo: usize,
    byte_hi: usize,
) -> String {
    let count = 1 + rng.below(8) as usize;
    let bit_lo = byte_lo * 8;
    let bit_hi = byte_hi * 8;
    let mut positions = Vec::with_capacity(count);
    for _ in 0..count {
        let bit = bit_lo + rng.below((bit_hi - bit_lo) as u64) as usize;
        data[bit / 8] ^= 1 << (bit % 8);
        positions.push(bit);
    }
    format!("flip bits {positions:?}")
}

fn truncate(data: &mut Vec<u8>, rng: &mut SplitMix64) -> String {
    let new_len = rng.below(data.len() as u64) as usize;
    data.truncate(new_len);
    format!("truncate to {new_len}")
}

fn overwrite_region(data: &mut [u8], rng: &mut SplitMix64) -> String {
    let count = (1 + rng.below(32) as usize).min(data.len());
    let offset = rng.below((data.len() - count + 1) as u64) as usize;
    for slot in data.iter_mut().skip(offset).take(count) {
        *slot = rng.next() as u8;
    }
    format!("overwrite {count} bytes at {offset}")
}

// Byte range of the first "tcbLevels" array (the tcbInfo one; qe_identity's
// copy comes later in the file). String-aware bracket matching so quoted
// brackets cannot desync the depth counter.
fn tcb_levels_range(json: &[u8]) -> Option<(usize, usize)> {
    let needle = b"\"tcbLevels\"";
    let start = json.windows(needle.len()).position(|w| w == needle)?;
    let mut i = start + needle.len();
    while i < json.len() && json[i] != b'[' {
        i += 1;
    }
    let open = i;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while i < json.len() {
        let b = json[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((open, i + 1));
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn mutate_quote(quote: &mut Vec<u8>, strategy: u64, rng: &mut SplitMix64) -> String {
    let len = quote.len();
    match strategy {
        0 => format!("quote-bitflip: {}", flip_random_bits(quote, rng, 0, len)),
        1 => format!("quote-{}", truncate(quote, rng)),
        2 => format!("quote-{}", overwrite_region(quote, rng)),
        3 => {
            let lo = QUOTE_CERT_TAIL_OFFSET.min(len.saturating_sub(1));
            format!(
                "quote-cert-tail-bitflip: {}",
                flip_random_bits(quote, rng, lo, len)
            )
        }
        _ => unreachable!("quote strategies are 0..=3"),
    }
}

fn mutate_collateral(collateral: &mut Vec<u8>, strategy: u64, rng: &mut SplitMix64) -> String {
    let len = collateral.len();
    match strategy {
        4 => format!(
            "coll-bitflip: {}",
            flip_random_bits(collateral, rng, 0, len)
        ),
        5 => format!("coll-{}", truncate(collateral, rng)),
        6 => match tcb_levels_range(collateral) {
            Some((lo, hi)) => format!(
                "coll-tcblevels-bitflip range={lo}..{hi}: {}",
                flip_random_bits(collateral, rng, lo, hi)
            ),
            None => format!(
                "coll-bitflip (no tcbLevels found): {}",
                flip_random_bits(collateral, rng, 0, len)
            ),
        },
        _ => unreachable!("collateral strategies are 4..=6"),
    }
}

pub fn mutate(base: &BaseCase, strategy: u64, rng: &mut SplitMix64) -> MutatedCase {
    let mut quote = base.quote.clone();
    let mut collateral = base.collateral.clone();
    let mut current_time = base.current_time;
    let desc = match strategy {
        0..=3 => mutate_quote(&mut quote, strategy, rng),
        4..=6 => mutate_collateral(&mut collateral, strategy, rng),
        7 => {
            let delta = rng.below(2 * THREE_YEARS_SECS + 1) as i64 - THREE_YEARS_SECS as i64;
            current_time += delta;
            format!("time-jitter delta={delta}s -> {current_time}")
        }
        8 => {
            let quote_strategy = rng.below(4);
            let collateral_strategy = 4 + rng.below(3);
            let quote_desc = mutate_quote(&mut quote, quote_strategy, rng);
            let collateral_desc = mutate_collateral(&mut collateral, collateral_strategy, rng);
            format!("combo: {quote_desc}; {collateral_desc}")
        }
        _ => unreachable!("strategies are 0..=8"),
    };
    MutatedCase {
        quote,
        collateral,
        current_time,
        desc,
    }
}

pub fn run(opts: &SweepOpts) -> i32 {
    println!("seed = 0x{:X}", opts.seed);
    let bases: Vec<BaseCase> = opts.bases.iter().map(|dir| load_base(dir)).collect();
    fs::create_dir_all(&opts.out).expect("create out dir");
    let jsonl_path = opts.out.join(format!("sweep-{:x}.jsonl", opts.seed));
    let mut jsonl = fs::File::create(&jsonl_path).expect("create jsonl");

    let indices: Vec<u64> = match opts.only_iter {
        Some(k) => vec![k],
        None => (0..opts.iters).collect(),
    };

    let mut counts: BTreeMap<(u64, String), u64> = BTreeMap::new();
    let mut bucket_labels: BTreeSet<String> = BTreeSet::new();
    let mut tally = Tally::default();
    let mut reproduced: BTreeSet<u64> = BTreeSet::new();

    for &i in &indices {
        let mut rng = SplitMix64::new(opts.seed ^ i.wrapping_mul(GAMMA));
        let base = if opts.default_bases {
            // Default weighting: 80% prod-1, 20% base-debug-enclave.
            if rng.below(10) < 8 {
                &bases[0]
            } else {
                &bases[1]
            }
        } else {
            &bases[rng.below(bases.len() as u64) as usize]
        };
        let strategy = rng.below(9);
        let case = mutate(base, strategy, &mut rng);
        let record = run_case(
            &case.quote,
            &case.collateral,
            case.current_time,
            DEFAULT_MARSHAL,
        );

        let allowlisted =
            matches!(record.bucket, Bucket::Dangerous(_)) && opts.allow_iters.contains_key(&i);
        if allowlisted {
            tally.dangerous_known += 1;
            reproduced.insert(i);
        } else {
            tally.add(&record.bucket);
        }
        let label = if allowlisted {
            "known-dangerous".to_string()
        } else {
            record.bucket.label()
        };
        bucket_labels.insert(label.clone());
        *counts.entry((strategy, label.clone())).or_insert(0) += 1;

        if !record.bucket.is_agreement() {
            let line = json!({
                "iter": i,
                "base": base.name,
                "strategy": strategy,
                "mutation_desc": case.desc,
                "current_time": case.current_time,
                "dcap": record.dcap.to_json(),
                "qvl": record.qvl.to_json(),
                "bucket": label,
                "repro": format!(
                    "dcap-differ sweep --seed 0x{:X} --iters 1 --only-iter {i}",
                    opts.seed
                ),
            });
            writeln!(jsonl, "{line}").expect("write jsonl");
        }
        if record.bucket.is_finding() {
            let case_dir = opts.out.join(format!("case-{i}"));
            fs::create_dir_all(&case_dir).expect("create case dir");
            fs::write(case_dir.join("quote.bin"), &case.quote).expect("dump quote");
            fs::write(case_dir.join("collateral.json"), &case.collateral).expect("dump collateral");
            let meta = json!({
                "iter": i,
                "base": base.name,
                "strategy": strategy,
                "mutation_desc": case.desc,
                "current_time": case.current_time,
                "bucket": label,
            });
            fs::write(
                case_dir.join("meta.json"),
                serde_json::to_string_pretty(&meta).expect("meta serializes"),
            )
            .expect("dump meta");
            println!(
                "FINDING iter={i} base={} strategy={strategy} bucket={label} dcap={} qvl={}",
                base.name,
                record.dcap.label(),
                record.qvl.label()
            );
        }
    }

    for (&k, finding) in &opts.allow_iters {
        let in_window = match opts.only_iter {
            Some(only) => k == only,
            None => k < opts.iters,
        };
        if in_window && !reproduced.contains(&k) {
            tally.vanished += 1;
            println!(
                "VANISHED iter={k} ({finding}) — allowlisted as dangerous but no longer reproduces; update FINDINGS.md and the allowlist together"
            );
        }
    }

    print_summary(&counts, &bucket_labels, indices.len());
    println!("findings jsonl: {}", jsonl_path.display());
    println!();
    tally.print_verdict()
}

fn print_summary(
    counts: &BTreeMap<(u64, String), u64>,
    bucket_labels: &BTreeSet<String>,
    total: usize,
) {
    println!();
    println!("=== sweep summary ({total} iterations) ===");
    let width = bucket_labels.iter().map(|l| l.len()).max().unwrap_or(12) + 2;
    print!("{:<10}", "strategy");
    for label in bucket_labels {
        print!("{label:>width$}");
    }
    println!();
    for strategy in 0..9 {
        print!("{strategy:<10}");
        for label in bucket_labels {
            let n = counts.get(&(strategy, label.clone())).copied().unwrap_or(0);
            print!("{n:>width$}");
        }
        println!();
    }
    print!("{:<10}", "total");
    for label in bucket_labels {
        let n: u64 = (0..9)
            .map(|s| counts.get(&(s, label.clone())).copied().unwrap_or(0))
            .sum();
        print!("{n:>width$}");
    }
    println!();

    let sum_for = |pred: &dyn Fn(&str) -> bool| -> u64 {
        counts
            .iter()
            .filter(|((_, l), _)| pred(l))
            .map(|(_, n)| n)
            .sum()
    };
    println!();
    println!(
        "agreements: {} (accept {}, reject {})",
        sum_for(&|l| l.starts_with("agree-")),
        sum_for(&|l| l == "agree-accept"),
        sum_for(&|l| l == "agree-reject"),
    );
    for label in bucket_labels {
        if let Some(kind) = label
            .strip_prefix("known-delta(")
            .and_then(|s| s.strip_suffix(")"))
        {
            println!("known delta {kind}: {}", sum_for(&|l| l == label));
        }
    }
    println!(
        "unexplained-safe: {}",
        sum_for(&|l| l == "unexplained-safe")
    );
    println!(
        "standing-mismatch: {}",
        sum_for(&|l| l == "standing-mismatch")
    );
    println!("dcap-panic: {}", sum_for(&|l| l == "dcap-panic"));
    println!("DANGEROUS: {}", sum_for(&|l| l.starts_with("DANGEROUS")));
}
