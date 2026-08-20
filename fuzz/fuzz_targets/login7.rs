#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::{batch, login7, rpc};

fuzz_target!(|data: &[u8]| {
    let _ = login7::parse(data);
    let _ = batch::strip_all_headers(data);
    let _ = batch::decode(data, 64 * 1024);
    let _ = rpc::parse(data, 64 * 1024);
});
