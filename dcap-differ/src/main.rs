mod pipeline;
mod rng;
mod sweep;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

use intel_tee_quote_verification_rs::{sgx_ql_qv_result_t, tee_verify_quote};
use serde::Deserialize;

use pipeline::{
    Bucket, CrlForm, DEFAULT_MARSHAL, MarshalConfig, RawCollateral, Tally, build_quote_collateral,
    install_panic_hook, run_case,
};

const DEFAULT_SEED: u64 = 0xDCAF00000001;

const USAGE: &str = "usage:
  dcap-differ calibrate [--case DIR]
  dcap-differ fixtures [--root DIR] [--allow FILE]
  dcap-differ sweep --iters N [--seed HEX] [--base DIR ...] [--only-iter K] [--out DIR] [--allow FILE]";

fn fixtures_root_default() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent dir")
        .join("fixtures")
}

fn reports_default() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("reports")
}

fn parse_hex_u64(s: &str) -> u64 {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(digits, 16).unwrap_or_else(|e| {
        eprintln!("bad hex value {s:?}: {e}");
        exit(2);
    })
}

fn flag_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> &'a str {
    *i += 1;
    args.get(*i).map(String::as_str).unwrap_or_else(|| {
        eprintln!("{flag} requires a value");
        exit(2);
    })
}

fn main() {
    install_panic_hook();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("calibrate") => calibrate_cmd(&args[1..]),
        Some("fixtures") => fixtures_cmd(&args[1..]),
        Some("sweep") => sweep_cmd(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            exit(2);
        }
    }
}

#[derive(Deserialize)]
struct Meta {
    current_time_unix: i64,
    verdict: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    tcb_standing: Option<serde_json::Value>,
}

impl Meta {
    fn expected_label(&self) -> String {
        if let Some(category) = &self.category {
            return format!("{}({category})", self.verdict);
        }
        let standing = self.tcb_standing.as_ref().and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(map) => map.keys().next().cloned(),
            _ => None,
        });
        match standing {
            Some(s) => format!("{}({s})", self.verdict),
            None => self.verdict.clone(),
        }
    }
}

fn load_meta(dir: &Path) -> Meta {
    let bytes = fs::read(dir.join("meta.json"))
        .unwrap_or_else(|e| panic!("read {}/meta.json: {e}", dir.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse {}/meta.json: {e}", dir.display()))
}

/// Recorded dangerous-polarity findings (FINDINGS.md): `sweep` entries pin a
/// seed + iteration, `cases` entries pin a fixture-corpus dir name. A matched
/// dangerous record counts as known-dangerous; an in-scope entry that no longer
/// fires counts as vanished. Both sides keep the exit code honest.
#[derive(Deserialize, Default)]
struct Allowlist {
    #[serde(default)]
    sweep: Vec<AllowSweep>,
    #[serde(default)]
    cases: Vec<AllowCase>,
}

#[derive(Deserialize)]
struct AllowSweep {
    finding: String,
    seed: String,
    iter: u64,
}

#[derive(Deserialize)]
struct AllowCase {
    finding: String,
    case: String,
}

fn load_allowlist(path: &Path) -> Allowlist {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read allowlist {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse allowlist {}: {e}", path.display()))
}

fn calibrate_cmd(args: &[String]) {
    let mut case_dir = fixtures_root_default().join("prod-1");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--case" => case_dir = PathBuf::from(flag_value(args, &mut i, "--case")),
            other => {
                eprintln!("unknown calibrate flag {other:?}\n{USAGE}");
                exit(2);
            }
        }
        i += 1;
    }

    let quote = fs::read(case_dir.join("quote.bin")).expect("read quote.bin");
    let collateral_json = fs::read(case_dir.join("collateral.json")).expect("read collateral.json");
    let meta = load_meta(&case_dir);
    let raw: RawCollateral =
        serde_json::from_slice(&collateral_json).expect("collateral.json parses as RawCollateral");

    println!(
        "calibrating on {} at t={}",
        case_dir.display(),
        meta.current_time_unix
    );
    println!("{:<10} {:<6} {:<10} outcome", "version", "crl", "tee_type");

    let mut passing: Vec<MarshalConfig> = Vec::new();
    for (major, minor) in [(1u16, 0u16), (3, 0), (3, 1), (4, 0)] {
        for crl_form in [CrlForm::Pem, CrlForm::Der] {
            let cfg = MarshalConfig {
                major,
                minor,
                tee_type: 0,
                crl_form,
            };
            let outcome = match build_quote_collateral(&raw, cfg) {
                Ok(collateral) => match tee_verify_quote(
                    &quote,
                    Some(&collateral),
                    meta.current_time_unix,
                    None,
                    None,
                ) {
                    Ok((exp_status, result)) => {
                        if result
                            == sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED
                        {
                            passing.push(cfg);
                        }
                        format!("exp={exp_status} {result:?}")
                    }
                    Err(code) => format!("err({code:?})"),
                },
                Err(e) => format!("marshal-failed: {e}"),
            };
            println!(
                "{:<10} {:<6} {:<10} {outcome}",
                format!("{major}.{minor}"),
                crl_form.label(),
                0
            );
        }
    }

    // Prefer the hardcoded default when it passes so "chosen" and "default" agree.
    let winner = passing
        .iter()
        .find(|cfg| cfg.label() == DEFAULT_MARSHAL.label())
        .or_else(|| passing.first());
    match winner {
        Some(cfg) => {
            println!(
                "chosen marshaling config: {} ({} cells passed)",
                cfg.label(),
                passing.len()
            );
            println!("hardcoded default:        {}", DEFAULT_MARSHAL.label());
        }
        None => {
            println!("calibration FAILED: no cell yielded CONFIG_AND_SW_HARDENING_NEEDED");
            exit(1);
        }
    }
}

fn fixtures_cmd(args: &[String]) {
    let mut root = fixtures_root_default();
    let mut allow: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => root = PathBuf::from(flag_value(args, &mut i, "--root")),
            "--allow" => allow = Some(PathBuf::from(flag_value(args, &mut i, "--allow"))),
            other => {
                eprintln!("unknown fixtures flag {other:?}\n{USAGE}");
                exit(2);
            }
        }
        i += 1;
    }
    let allowed: BTreeMap<String, String> = allow
        .map(|p| load_allowlist(&p))
        .unwrap_or_default()
        .cases
        .into_iter()
        .map(|c| (c.case, c.finding))
        .collect();

    let mut cases: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("read fixtures root {}: {e}", root.display()))
        .filter_map(|entry| {
            let path = entry.expect("read dir entry").path();
            (path.join("meta.json").is_file() && path.join("quote.bin").is_file()).then_some(path)
        })
        .collect();
    cases.sort();

    println!(
        "{:<28} {:<50} {:<28} {:<50} meta-expected",
        "case", "dcap", "qvl", "bucket"
    );
    let mut tally = Tally::default();
    let mut reproduced: BTreeSet<String> = BTreeSet::new();
    for case_dir in &cases {
        let name = case_dir.file_name().unwrap().to_string_lossy();
        let quote = fs::read(case_dir.join("quote.bin")).expect("read quote.bin");
        let collateral_json =
            fs::read(case_dir.join("collateral.json")).expect("read collateral.json");
        let meta = load_meta(case_dir);
        let record = run_case(
            &quote,
            &collateral_json,
            meta.current_time_unix,
            DEFAULT_MARSHAL,
        );
        let allowlisted = if matches!(record.bucket, Bucket::Dangerous(_)) {
            allowed.get(name.as_ref())
        } else {
            None
        };
        let bucket_label = match allowlisted {
            Some(finding) => {
                tally.dangerous_known += 1;
                reproduced.insert(name.clone().into_owned());
                format!("known-dangerous({finding})")
            }
            None => {
                tally.add(&record.bucket);
                record.bucket.label()
            }
        };
        println!(
            "{:<28} {:<50} {:<28} {:<50} {}",
            name,
            record.dcap.label(),
            record.qvl.label(),
            bucket_label,
            meta.expected_label()
        );
    }
    for (case, finding) in &allowed {
        let present = cases
            .iter()
            .any(|dir| dir.file_name().unwrap().to_string_lossy() == *case);
        if present && !reproduced.contains(case) {
            tally.vanished += 1;
            println!(
                "VANISHED {case} ({finding}) — allowlisted as dangerous but no longer reproduces; update FINDINGS.md and the allowlist together"
            );
        }
    }
    println!();
    exit(tally.print_verdict());
}

fn sweep_cmd(args: &[String]) {
    let mut iters: Option<u64> = None;
    let mut seed = DEFAULT_SEED;
    let mut bases: Vec<PathBuf> = Vec::new();
    let mut only_iter: Option<u64> = None;
    let mut out = reports_default();
    let mut allow: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = Some(
                    flag_value(args, &mut i, "--iters")
                        .parse()
                        .expect("--iters takes a number"),
                )
            }
            "--seed" => seed = parse_hex_u64(flag_value(args, &mut i, "--seed")),
            "--base" => bases.push(PathBuf::from(flag_value(args, &mut i, "--base"))),
            "--only-iter" => {
                only_iter = Some(
                    flag_value(args, &mut i, "--only-iter")
                        .parse()
                        .expect("--only-iter takes a number"),
                )
            }
            "--out" => out = PathBuf::from(flag_value(args, &mut i, "--out")),
            "--allow" => allow = Some(PathBuf::from(flag_value(args, &mut i, "--allow"))),
            other => {
                eprintln!("unknown sweep flag {other:?}\n{USAGE}");
                exit(2);
            }
        }
        i += 1;
    }
    let Some(iters) = iters else {
        eprintln!("sweep requires --iters N\n{USAGE}");
        exit(2);
    };
    let default_bases = bases.is_empty();
    if default_bases {
        let root = fixtures_root_default();
        bases = vec![root.join("prod-1"), root.join("base-debug-enclave")];
    }
    let allow_iters: BTreeMap<u64, String> = allow
        .map(|p| load_allowlist(&p))
        .unwrap_or_default()
        .sweep
        .into_iter()
        .filter(|e| parse_hex_u64(&e.seed) == seed)
        .map(|e| (e.iter, e.finding))
        .collect();
    let code = sweep::run(&sweep::SweepOpts {
        iters,
        seed,
        bases,
        default_bases,
        only_iter,
        out,
        allow_iters,
    });
    exit(code);
}
