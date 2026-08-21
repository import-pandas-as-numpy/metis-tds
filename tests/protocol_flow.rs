use std::time::Duration;

use metis_tds::{
    Config,
    server::Server,
    tds::{
        self,
        packet::{read_message, write_message},
        prelogin::{Encryption, encode_response},
    },
};
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn plaintext_login_and_discovery_query_complete() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = Server::new(config).await.unwrap();
    let task = tokio::spawn(server.serve(listener, false));

    let mut client = TcpStream::connect(address).await.unwrap();
    let prelogin = encode_response(Encryption::Off, "MSSQLSERVER");
    write_message(&mut client, tds::PRELOGIN, &prelogin, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(response.packet_type, tds::TABULAR_RESULT);
    let parsed = tds::prelogin::parse(&response.payload).unwrap();
    assert_eq!(parsed.encryption, Some(Encryption::NotSupported));

    write_message(
        &mut client,
        tds::LOGIN7,
        &login7("scanner", "password", "indexer", "master"),
        4096,
    )
    .await
    .unwrap();
    let login = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(login.payload.contains(&0xad));

    let sql: Vec<u8> = "SELECT @@VERSION"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    write_message(&mut client, tds::SQL_BATCH, &sql, 4096)
        .await
        .unwrap();
    let result = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(result.payload.contains(&0x81));
    assert!(contains_utf16(&result.payload, "Microsoft SQL Server"));

    drop(client);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let telemetry = std::fs::read_to_string(&telemetry_path).unwrap();
    assert!(telemetry.contains("\"event_type\":\"connection_open\""));
    assert!(telemetry.contains("\"event_type\":\"login_attempt\""));
    assert!(telemetry.contains("\"raw_sql\":\"SELECT @@VERSION\""));
    assert!(telemetry.contains("\"event_type\":\"connection_close\""));
    task.abort();
}

#[tokio::test]
async fn rejected_login_never_echoes_password() {
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.personality.accept_unknown_logins = false;
    config.telemetry.jsonl_path = None;
    config.telemetry.stdout = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(
        &mut client,
        tds::PRELOGIN,
        &encode_response(Encryption::Off, ""),
        4096,
    )
    .await
    .unwrap();
    read_message(&mut client, 4096, 65_536).await.unwrap();
    write_message(
        &mut client,
        tds::LOGIN7,
        &login7("unknown", "SuperSecret!", "test", "master"),
        4096,
    )
    .await
    .unwrap();
    let failure = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(failure.payload.first(), Some(&0xaa));
    assert!(!contains_utf16(&failure.payload, "SuperSecret!"));
    task.abort();
}

#[tokio::test]
async fn malformed_packet_reports_source_stage_error_and_wire_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut client = TcpStream::connect(address).await.unwrap();
    // IGNORE without EOM is the one status combination MS-TDS explicitly
    // rejects. Undefined bits, by contrast, must be ignored by receivers.
    let malformed = [tds::PRELOGIN, 0x02, 0, 8, 0, 0, 0, 0];
    client.write_all(&malformed).await.unwrap();
    drop(client);

    let mut events = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        events = std::fs::read_to_string(&telemetry_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        if events
            .iter()
            .any(|event| event["event_type"] == "connection_close")
        {
            break;
        }
    }

    let malformed_event = events
        .iter()
        .find(|event| event["event_type"] == "malformed_tds_message")
        .expect("dedicated malformed event");
    assert_eq!(malformed_event["source_ip"], "127.0.0.1");
    assert_eq!(malformed_event["protocol_stage"], "prelogin_read");
    assert_eq!(malformed_event["error_kind"], "protocol");
    assert_eq!(malformed_event["bytes_read"], malformed.len());
    assert!(
        malformed_event["error"]
            .as_str()
            .unwrap()
            .contains("IGNORE status requires EOM")
    );

    let diagnostic = events
        .iter()
        .find(|event| event["event_type"] == "connection_failure")
        .expect("connection failure diagnostic");
    assert_eq!(diagnostic["stage_bytes_read"], malformed.len());
    assert_eq!(diagnostic["stage_bytes_written"], 0);
    assert_eq!(diagnostic["read_prefix_bytes"], malformed.len());
    assert_eq!(diagnostic["read_prefix_hex"], "1202000800000000");
    assert_eq!(diagnostic["read_prefix_truncated"], false);

    let close = events
        .iter()
        .find(|event| event["event_type"] == "connection_close")
        .expect("connection close event");
    assert_eq!(close["source_ip"], "127.0.0.1");
    assert_eq!(close["protocol_stage"], "prelogin_read");
    assert_eq!(close["error_kind"], "protocol");
    assert_eq!(close["parser_errors"], 1);
    assert_eq!(close["bytes_read"], malformed.len());
    task.abort();
}

fn login7(username: &str, password: &str, application: &str, database: &str) -> Vec<u8> {
    let mut packet = vec![0_u8; 94];
    packet[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
    packet[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    packet[24] = 0xe0;
    packet[25] = 0x03;
    let fields = [
        (36, "TESTCLIENT", false),
        (40, username, false),
        (44, password, true),
        (48, application, false),
        (52, "SQL-FIN-01", false),
        (60, "ODBC", false),
        (64, "us_english", false),
        (68, database, false),
    ];
    for (descriptor, value, password_field) in fields {
        let offset = u16::try_from(packet.len()).unwrap();
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if password_field {
            for byte in &mut encoded {
                *byte = byte.rotate_right(4) ^ 0xa5;
            }
        }
        let chars = u16::try_from(encoded.len() / 2).unwrap();
        packet[descriptor..descriptor + 2].copy_from_slice(&offset.to_le_bytes());
        packet[descriptor + 2..descriptor + 4].copy_from_slice(&chars.to_le_bytes());
        packet.extend_from_slice(&encoded);
    }
    let length = u32::try_from(packet.len()).unwrap();
    packet[0..4].copy_from_slice(&length.to_le_bytes());
    packet
}

fn contains_utf16(haystack: &[u8], needle: &str) -> bool {
    let needle: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
