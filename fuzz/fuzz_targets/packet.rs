#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::packet::Header;

fuzz_target!(|data: &[u8]| {
    for raw in data.chunks_exact(8).take(64) {
        let raw: [u8; 8] = raw.try_into().expect("chunk size is fixed");
        let max_packet = data
            .first()
            .map_or(8, |byte| usize::from(*byte).saturating_mul(257).max(8));
        if let Ok(header) = Header::decode(raw, max_packet) {
            let encoded = header.encode();
            let decoded = Header::decode(encoded, max_packet)
                .expect("a successfully decoded header must round-trip");
            assert_eq!(decoded, header);
        }
    }
});
