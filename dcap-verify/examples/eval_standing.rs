use std::time::{Duration, SystemTime};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: eval_standing <collateral.json> <quote.bin> <mrenclave-hex|auto> <unix-time|now>"
        );
        eprintln!(
            "  auto  pin the MRENCLAVE the quote itself reports (identity is then not verified)"
        );
        eprintln!("  now   evaluate at the current system time");
        eprintln!("Runs the full dcap-verify pipeline (evaluation-round floor 0) and prints the");
        eprintln!("TCB standing on accept, or the rejection category. Exit 1 on reject.");
        std::process::exit(2);
    }

    let collateral_bytes = std::fs::read(&args[1]).expect("read collateral");
    let collateral: dcap_verify::SgxCollateral =
        serde_json::from_slice(&collateral_bytes).expect("parse collateral");

    let quote_bytes = std::fs::read(&args[2]).expect("read quote");
    let quote = dcap_verify::SgxQuote::read(&mut &quote_bytes[..]).expect("parse quote");

    let mrenclave: dcap_verify::MREnclave = if args[3] == "auto" {
        *dcap_verify::peek_mrenclave(&quote_bytes).expect("quote shorter than the MRENCLAVE field")
    } else {
        hex::decode(&args[3])
            .expect("decode mrenclave hex")
            .as_slice()
            .try_into()
            .expect("mrenclave must be 32 bytes")
    };

    let time = if args[4] == "now" {
        SystemTime::now()
    } else {
        SystemTime::UNIX_EPOCH + Duration::from_secs(args[4].parse().expect("parse unix time"))
    };

    match dcap_verify::verify_remote_attestation(time, collateral, quote, &mrenclave, 0) {
        Ok((standing, _report)) => {
            println!(
                "OK {}",
                serde_json::to_string(&standing).expect("serialize standing")
            );
        }
        Err(e) => {
            println!("ERR category={} detail={}", e.category.as_str(), e.detail);
            std::process::exit(1);
        }
    }
}
