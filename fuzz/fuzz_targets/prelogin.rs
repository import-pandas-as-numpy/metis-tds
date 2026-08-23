#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::prelogin::{self, Encryption};

fuzz_target!(|data: &[u8]| {
    let _ = prelogin::parse(data);

    for encryption in [
        Encryption::Off,
        Encryption::On,
        Encryption::NotSupported,
        Encryption::Required,
    ] {
        for instance_matches in [false, true] {
            let encoded = prelogin::encode_response(encryption, instance_matches);
            let parsed = prelogin::parse(&encoded).expect("encoded PRELOGIN response must parse");
            assert_eq!(parsed.encryption, Some(encryption));
        }
    }
});
