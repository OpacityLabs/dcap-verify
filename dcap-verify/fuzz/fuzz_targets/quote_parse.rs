#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    let _ = dcap_verify::SgxQuote::read(&mut cursor);
});
