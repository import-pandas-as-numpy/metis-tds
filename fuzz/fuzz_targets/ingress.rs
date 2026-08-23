#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::{
    all_headers, batch, bulk, fedauth, login, login7, prelogin, rpc, smp, sspi, tds5,
    transaction,
};
use metis_tds::tds::{all_headers::StreamKind, enclave::LengthEncoding};

fuzz_target!(|data: &[u8]| {
    let _ = prelogin::parse(data);
    let _ = prelogin::parse_for_telemetry(data);
    let _ = login::parse(data);
    let _ = login::parse_for_telemetry(data);
    let _ = login7::parse(data);
    let _ = login7::parse_for_telemetry(data);
    let _ = login7::sspi_token(data);
    let _ = fedauth::parse(data, false);
    let _ = fedauth::parse(data, true);
    let _ = sspi::parse(data);
    let _ = all_headers::parse(data);
    for (tds72, tds74) in [(false, false), (true, false), (true, true)] {
        let _ = all_headers::parse_for_version(data, tds72, tds74, StreamKind::SqlBatch);
        let _ = batch::parse_with_context(
            data,
            64 * 1024,
            tds72,
            tds74,
            LengthEncoding::None,
        );
        let _ = rpc::parse_with_context(
            data,
            64 * 1024,
            tds72,
            tds74,
            LengthEncoding::None,
        );
        let _ = transaction::parse_with_context(
            data,
            tds72,
            tds74,
            LengthEncoding::None,
        );
    }
    let _ = batch::parse(data, 64 * 1024);
    let _ = batch::parse_with_enclave_encoding(
        data,
        64 * 1024,
        LengthEncoding::MicrosoftU16,
    );
    let _ = batch::parse_with_enclave_encoding(data, 64 * 1024, LengthEncoding::SpecU32);
    let _ = rpc::parse(data, 64 * 1024);
    let _ = bulk::parse(data, 64 * 1024, false, 2);
    let _ = bulk::parse(data, 64 * 1024, true, 2);
    let _ = bulk::parse_message(data, 64 * 1024, false, 2);
    let _ = bulk::parse_message(data, 64 * 1024, true, 2);
    let _ = smp::parse(data, 64 * 1024);
    let _ = tds5::parse_authentication(data, 64 * 1024);
    let _ = transaction::parse(data);
});
