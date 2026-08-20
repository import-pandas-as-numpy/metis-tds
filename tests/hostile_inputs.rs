use metis_tds::tds::{batch, login7, packet::Header, prelogin, rpc};

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
        let _ = login7::parse(&input);
        let _ = rpc::parse(&input, 4096);
        let _ = batch::decode(&input, 4096);
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
