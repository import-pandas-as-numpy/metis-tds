#![no_main]

use libfuzzer_sys::fuzz_target;
use metis_tds::tds::tokens::{self, ResultSet, SqlError};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data.get(..data.len().min(4096)).unwrap_or(data));
    let values: Vec<String> = text
        .as_bytes()
        .chunks(128)
        .take(16)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();

    let columns = values.iter().take(4).cloned().collect::<Vec<_>>();
    let width = columns.len();
    let rows = values
        .chunks(width.max(1))
        .take(8)
        .map(|chunk| {
            (0..width)
                .map(|index| chunk.get(index).cloned())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let result_set = ResultSet { columns, rows };
    let messages = values.iter().take(4).cloned().collect::<Vec<_>>();
    let error = SqlError {
        number: u32::from_le_bytes([
            data.first().copied().unwrap_or_default(),
            data.get(1).copied().unwrap_or_default(),
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]),
        state: data.get(4).copied().unwrap_or_default(),
        class: data.get(5).copied().unwrap_or_default(),
        message: text.into_owned(),
    };

    let _ = tokens::response(&[result_set], &messages, None, "METIS", false);
    let _ = tokens::response(&[], &messages, Some(&error), "METIS", true);
    let _ = tokens::login_success("master", "us_english", 4096, &error.message);
    let _ = tokens::login_failure("METIS", data.len() % 2 == 0);
});
