#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::prelogin::{self, Encryption};

fuzz_target!(|data: &[u8]| {
    let _ = prelogin::parse(data);

    let instance = String::from_utf8_lossy(data.get(..data.len().min(128)).unwrap_or(data));
    for encryption in [
        Encryption::Off,
        Encryption::On,
        Encryption::NotSupported,
        Encryption::Required,
    ] {
        let encoded = prelogin::encode_response(encryption, &instance);
        let parsed = prelogin::parse(&encoded).expect("encoded PRELOGIN response must parse");
        assert_eq!(parsed.encryption, Some(encryption));
    }
});
