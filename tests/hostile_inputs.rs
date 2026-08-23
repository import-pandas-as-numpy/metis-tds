use metis_tds::tds::{
    all_headers, batch, bulk, data::Cursor, enclave::LengthEncoding, fedauth, login, login7,
    packet::Header, prelogin, rpc, smp, sspi, tds5, transaction,
};

#[test]
fn deterministic_parser_fuzz_smoke_has_no_panics() {
    let mut state = 0x6d65_7469_735f_7464_u64;
    for case in 0..20_000_usize {
        let length = (next(&mut state) as usize) % 4096;
        let mut input = vec![0_u8; length];
        for byte in &mut input {
            *byte = next(&mut state) as u8;
        }
        let _ = prelogin::parse(&input);
        let _ = prelogin::parse_for_telemetry(&input);
        let _ = login::parse(&input);
        let _ = login::parse_for_telemetry(&input);
        let _ = login7::parse(&input);
        let _ = login7::parse_for_telemetry(&input);
        let _ = login7::sspi_token(&input);
        let _ = fedauth::parse(&input, false);
        let _ = fedauth::parse(&input, true);
        let _ = sspi::parse(&input);
        let _ = all_headers::parse(&input);
        for stream in [
            all_headers::StreamKind::SqlBatch,
            all_headers::StreamKind::Rpc,
            all_headers::StreamKind::TransactionManager,
        ] {
            let _ = all_headers::parse_for_version(&input, true, true, stream);
        }
        let _ = transaction::parse(&input);
        for encoding in [
            LengthEncoding::None,
            LengthEncoding::MicrosoftU16,
            LengthEncoding::SpecU32,
        ] {
            let _ = transaction::parse_with_context(&input, true, true, encoding);
            let _ = batch::parse_with_context(&input, 4096, true, true, encoding);
            let _ = rpc::parse_with_context(&input, 4096, true, true, encoding);
        }
        let _ = rpc::parse(&input, 4096);
        let _ = rpc::parse_legacy42(&input, 4096);
        let _ = bulk::parse(&input, 4096, false, false, 2);
        let _ = bulk::parse(&input, 4096, true, false, 2);
        let _ = bulk::parse(&input, 4096, true, true, 2);
        let _ = bulk::parse_tds42_message(&input, 4096, 2);
        let _ = bulk::parse_tds5_rows(&input, 4096, 2);
        let _ = smp::parse(&input, 4096);
        let _ = tds5::parse_authentication(&input, 4096);
        let _ = tds5::parse_for_telemetry(&input, 4096);
        let _ = batch::decode(&input, 4096);
        let mut modern = Cursor::new(&input, 4096, "hostile modern TYPE_INFO");
        if let Ok(ty) = modern.type_info() {
            let _ = modern.value(&ty);
        }
        let mut legacy = Cursor::new(&input, 4096, "hostile legacy TYPE_INFO");
        if let Ok(ty) = legacy.type_info_legacy42() {
            let _ = legacy.value(&ty);
        }
        if input.len() >= 8 {
            let mut raw = [0_u8; 8];
            raw.copy_from_slice(&input[..8]);
            let _ = Header::decode(raw, 4096);
        }
        if case % 257 == 0 {
            let _ = prelogin::parse(&vec![0xff; case % 1024]);
        }
    }
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
