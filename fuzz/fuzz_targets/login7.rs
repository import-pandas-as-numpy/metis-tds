#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::{all_headers, batch, fedauth, login, login7, rpc, sspi, transaction};

fuzz_target!(|data: &[u8]| {
    let _ = login7::parse(data);
    let _ = login7::parse_for_telemetry(data);
    let _ = login7::sspi_token(data);
    let _ = login::parse_for_telemetry(data);
    let _ = fedauth::parse(data, false);
    let _ = sspi::parse(data);
    let _ = all_headers::parse(data);
    let _ = transaction::parse(data);
    let _ = batch::strip_all_headers(data);
    let _ = batch::decode(data, 64 * 1024);
    let _ = rpc::parse(data, 64 * 1024);
});
