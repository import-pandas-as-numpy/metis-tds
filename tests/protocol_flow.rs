use std::time::Duration;

use metis_tds::{
    Config,
    server::Server,
    tds::{
        self,
        packet::{read_message, write_message},
        prelogin::{Encryption, encode_request},
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
    let prelogin = encode_request(Encryption::Off, "MSSQLSERVER");
    write_message(&mut client, tds::PRELOGIN, &prelogin, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(response.packet_type, tds::TABULAR_RESULT);
    assert_eq!(response.payload.len(), 39);
    assert_eq!(response.payload[33], 0);
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
    assert!(telemetry.contains("\"instance_matches\":true"));
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
        &encode_request(Encryption::Off, ""),
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

#[tokio::test]
async fn direct_sql_login_captures_credentials_and_restricted_login7_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_directory = temp.path().join("payloads");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = true;
    config.payloads.capture_login_messages = true;
    config.payloads.directory = payload_directory.to_string_lossy().into_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let payload = login7("direct_probe", "Password123!", "legacy-client", "master");
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN7, &payload, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(response.payload.contains(&0xad));
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let candidate = events
        .iter()
        .find(|event| event["event_type"] == "direct_login_candidate")
        .expect("direct LOGIN7 candidate event");
    assert_eq!(candidate["packet_type"], tds::LOGIN7);
    let detected = events
        .iter()
        .find(|event| event["event_type"] == "direct_login_detected")
        .expect("fully framed direct LOGIN7 event");
    assert_eq!(detected["packet_type"], tds::LOGIN7);
    assert_eq!(detected["message_bytes"], payload.len());
    assert_eq!(detected["packet_count"], 1);
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("login attempt event");
    assert_eq!(login["transport"], "tds7_direct");
    assert_eq!(login["username"], "direct_probe");
    assert_eq!(login["password"], "Password123!");
    let capture = events
        .iter()
        .find(|event| event["event_type"] == "login_message_capture")
        .expect("LOGIN7 capture event");
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    let metadata = std::fs::metadata(&stored).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(std::fs::read(stored).unwrap(), payload);
    task.abort();
}

#[tokio::test]
async fn legacy_direct_login_captures_password_and_enters_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_directory = temp.path().join("payloads");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = true;
    config.payloads.capture_login_messages = true;
    config.payloads.directory = payload_directory.to_string_lossy().into_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let payload = legacy_login("203.0.113.10:1433", "sa", "gold", "pymssql");
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &payload, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_tds42_login_success(&response.payload);

    write_message(&mut client, tds::SQL_BATCH, b"SELECT @@VERSION", 4096)
        .await
        .unwrap();
    let result = read_message(&mut client, 4096, 65_536).await.unwrap();
    let (columns, rows) = parse_tds42_varchar_result(&result.payload);
    assert_eq!(columns, vec![""]);
    assert_eq!(rows.len(), 1);
    assert!(rows[0][0].starts_with("Microsoft SQL Server"));
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("legacy login attempt");
    assert_eq!(login["transport"], "tds42_direct");
    assert_eq!(login["login_format"], "tds42_login");
    assert_eq!(login["packet_type"], tds::LOGIN);
    assert_eq!(login["username"], "sa");
    assert_eq!(login["password"], "gold");
    assert_eq!(login["application_name"], "pymssql");
    assert_eq!(login["client_library"], "pymssql");
    assert_eq!(login["tds_version"], "0x04020000");
    let capture = events
        .iter()
        .find(|event| event["event_type"] == "login_message_capture")
        .expect("legacy login artifact");
    assert_eq!(capture["login_format"], "tds42_login");
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    assert_eq!(std::fs::read(stored).unwrap(), payload);
    task.abort();
}

#[tokio::test]
async fn malformed_legacy_login_is_archived_but_not_copied_to_failure_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_directory = temp.path().join("payloads");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.payloads.enabled = true;
    config.payloads.capture_login_messages = true;
    config.payloads.directory = payload_directory.to_string_lossy().into_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let payload = b"legacy-credential-marker";
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, payload, 4096)
        .await
        .unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    let capture = events
        .iter()
        .find(|event| event["event_type"] == "login_message_capture")
        .expect("pre-parse login artifact");
    assert_eq!(capture["packet_type"], tds::LOGIN);
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    assert_eq!(std::fs::read(stored).unwrap(), payload);
    let failure = events
        .iter()
        .find(|event| event["event_type"] == "connection_failure")
        .expect("connection failure event");
    assert_eq!(failure["protocol_stage"], "login_parse");
    assert!(failure["read_prefix_hex"].is_null());
    assert!(failure["read_prefix_bytes"].is_null());
    assert!(
        !std::fs::read_to_string(&telemetry_path)
            .unwrap()
            .contains("legacy-credential-marker")
    );
    task.abort();
}

#[tokio::test]
async fn source_is_admitted_only_after_configured_number_of_sql_auth_attempts() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.personality.accept_unknown_logins = false;
    config.personality.accept_source_after_attempts = Some(2);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    for (attempt, should_accept) in [(1, false), (2, false), (3, true)] {
        let mut client = TcpStream::connect(address).await.unwrap();
        let payload = legacy_login(
            "scanner",
            "unknown_user",
            &format!("wrong-{attempt}"),
            "pymssql",
        );
        write_message(&mut client, tds::LOGIN, &payload, 4096)
            .await
            .unwrap();
        let response = read_message(&mut client, 4096, 65_536).await.unwrap();
        assert_eq!(response.payload.contains(&0xad), should_accept);
    }

    let mut events = Vec::new();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        events = std::fs::read_to_string(&telemetry_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        if events
            .iter()
            .filter(|event| event["event_type"] == "login_attempt")
            .count()
            == 3
        {
            break;
        }
    }
    let attempts: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "login_attempt")
        .collect();
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0]["source_login_attempt_number"], 1);
    assert_eq!(attempts[0]["source_auth_bypass"], false);
    assert_eq!(attempts[1]["source_login_attempt_number"], 2);
    assert_eq!(attempts[1]["source_auth_bypass"], false);
    assert_eq!(attempts[2]["source_login_attempt_number"], 3);
    assert_eq!(attempts[2]["source_auth_bypass_threshold"], 2);
    assert_eq!(attempts[2]["source_auth_bypass"], true);
    assert_eq!(attempts[2]["accepted"], true);
    task.abort();
}

#[tokio::test]
async fn direct_ntlm_login_is_classified_without_putting_token_in_events() {
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

    let token = b"NTLMSSP\0\x01\0\0\0synthetic-negotiate";
    let payload = integrated_login7(token);
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN7, &payload, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(response.payload.first(), Some(&0xaa));
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("login attempt event");
    assert_eq!(login["transport"], "tds7_direct");
    assert_eq!(login["integrated_security"], true);
    assert_eq!(login["sspi_bytes"], token.len());
    assert_eq!(login["sspi_token_family"], "ntlmssp");
    assert!(
        !std::fs::read_to_string(&telemetry_path)
            .unwrap()
            .contains("synthetic-negotiate")
    );
    task.abort();
}

#[tokio::test]
async fn malformed_direct_login_never_enters_generic_wire_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN7, b"secret-marker", 4096)
        .await
        .unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "direct_login_candidate")
    );
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "direct_login_detected")
    );
    let failure = events
        .iter()
        .find(|event| event["event_type"] == "connection_failure")
        .expect("connection failure event");
    assert_eq!(failure["protocol_stage"], "login_parse");
    assert_eq!(failure["last_packet_type"], tds::LOGIN7);
    assert!(failure["read_prefix_hex"].is_null());
    assert!(failure["read_prefix_bytes"].is_null());
    assert!(
        !std::fs::read_to_string(&telemetry_path)
            .unwrap()
            .contains("secret-marker")
    );
    task.abort();
}

#[tokio::test]
async fn impossible_direct_login_header_is_only_a_candidate_with_safe_header_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let malformed_header = [tds::LOGIN7, 0x0f, 0x00, 0x04, 0xaa, 0xbb, 0x54, 0x00];
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&malformed_header).await.unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "direct_login_candidate")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "direct_login_detected")
    );
    let failure = events
        .iter()
        .find(|event| event["event_type"] == "connection_failure")
        .expect("connection failure event");
    assert_eq!(failure["protocol_stage"], "login_read");
    assert_eq!(
        failure["error"],
        "TDS protocol error: invalid TDS packet length 4 (type=0x10, status=0x0f, packet_id=84)"
    );
    assert!(failure["read_prefix_hex"].is_null());
    assert!(failure["read_prefix_bytes"].is_null());
    assert_eq!(failure["direct_login_header_hex"], "100f0004aabb5400");
    assert_eq!(failure["direct_login_header_bytes"], 8);
    assert_eq!(failure["direct_login_header_complete"], true);
    let malformed = events
        .iter()
        .find(|event| event["event_type"] == "malformed_tds_message")
        .expect("malformed TDS event");
    assert_eq!(malformed["direct_login_header_hex"], "100f0004aabb5400");
    task.abort();
}

#[tokio::test]
async fn framed_malformed_login7_is_detected_archived_and_field_diagnosed() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_directory = temp.path().join("payloads");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.payloads.enabled = true;
    config.payloads.capture_login_messages = true;
    config.payloads.directory = payload_directory.to_string_lossy().into_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut payload = vec![0_u8; 147];
    payload[0..4].copy_from_slice(&147_u32.to_le_bytes());
    payload[40..42].copy_from_slice(&146_u16.to_le_bytes());
    payload[42..44].copy_from_slice(&2_u16.to_le_bytes());
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN7, &payload, 4096)
        .await
        .unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "direct_login_candidate")
    );
    let detected = events
        .iter()
        .find(|event| event["event_type"] == "direct_login_detected")
        .expect("fully framed direct LOGIN7 event");
    assert_eq!(detected["message_bytes"], 147);
    let capture = events
        .iter()
        .find(|event| event["event_type"] == "login_message_capture")
        .expect("pre-parse LOGIN7 artifact");
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    assert_eq!(std::fs::read(stored).unwrap(), payload);
    let failure = events
        .iter()
        .find(|event| event["event_type"] == "connection_failure")
        .expect("connection failure event");
    assert_eq!(failure["protocol_stage"], "login_parse");
    assert_eq!(
        failure["error"],
        "TDS protocol error: LOGIN7 username field is outside message (offset=146, bytes=4, declared=147)"
    );
    assert!(failure["direct_login_header_hex"].is_null());
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "login_attempt")
    );
    task.abort();
}

async fn wait_for_events(path: &std::path::Path, event_type: &str) -> Vec<Value> {
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let events: Vec<Value> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if events.iter().any(|event| event["event_type"] == event_type) {
            return events;
        }
    }
    panic!("timed out waiting for {event_type}");
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

fn integrated_login7(token: &[u8]) -> Vec<u8> {
    let mut packet = vec![0_u8; 94];
    packet[4..8].copy_from_slice(&0x7100_0001_u32.to_le_bytes());
    packet[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    packet[25] = 0x80;
    packet[78..80].copy_from_slice(&(94_u16).to_le_bytes());
    packet[80..82].copy_from_slice(&(token.len() as u16).to_le_bytes());
    packet.extend_from_slice(token);
    let length = packet.len() as u32;
    packet[0..4].copy_from_slice(&length.to_le_bytes());
    packet
}

fn legacy_login(host: &str, username: &str, password: &str, application: &str) -> Vec<u8> {
    let mut payload = vec![0_u8; 572];
    put_legacy_field(&mut payload, 0, 30, host);
    put_legacy_field(&mut payload, 31, 61, username);
    put_legacy_field(&mut payload, 62, 92, password);
    payload[123] = 4;
    put_legacy_field(&mut payload, 140, 170, application);
    put_legacy_field(&mut payload, 171, 201, "203.0.113.10:1433");
    payload[458..462].copy_from_slice(&0x0402_0000_u32.to_be_bytes());
    put_legacy_field(&mut payload, 462, 472, "pymssql");
    put_legacy_field(&mut payload, 480, 510, "us_english");
    put_legacy_field(&mut payload, 557, 563, "4096");
    payload
}

fn put_legacy_field(payload: &mut [u8], offset: usize, length_offset: usize, value: &str) {
    payload[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    payload[length_offset] = value.len() as u8;
}

fn contains_utf16(haystack: &[u8], needle: &str) -> bool {
    let needle: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn assert_tds42_login_success(payload: &[u8]) {
    assert_eq!(payload.first(), Some(&0xad));
    let body_len = usize::from(u16::from_le_bytes([payload[1], payload[2]]));
    assert_eq!(body_len + 3 + 9, payload.len());
    assert_eq!(payload[3], 1);
    assert_eq!(&payload[4..8], &[0x04, 0x02, 0x00, 0x00]);
    let name_len = usize::from(payload[8]);
    assert_eq!(&payload[9..9 + name_len], b"Microsoft SQL Server");
    let version = 9 + name_len;
    assert_eq!(&payload[version..version + 4], &[95, 16, 0, 89]);
    assert_eq!(payload[version + 4], 0xfd);
    assert_eq!(&payload[version + 5..], &[0; 8]);
}

fn parse_tds42_varchar_result(payload: &[u8]) -> (Vec<String>, Vec<Vec<String>>) {
    let mut cursor = 0;
    assert_eq!(payload[cursor], 0xa0);
    cursor += 1;
    let names_len = take_u16(payload, &mut cursor);
    let names_end = cursor + names_len;
    let mut columns = Vec::new();
    while cursor < names_end {
        columns.push(take_legacy_string(payload, &mut cursor));
    }
    assert_eq!(cursor, names_end);

    assert_eq!(payload[cursor], 0xa1);
    cursor += 1;
    let formats_len = take_u16(payload, &mut cursor);
    assert_eq!(formats_len, columns.len() * 6);
    for _ in &columns {
        assert_eq!(take_u16(payload, &mut cursor), 2); // varchar user type
        assert_eq!(take_u16(payload, &mut cursor), 1); // nullable
        assert_eq!(payload[cursor], 0x27); // SYBVARCHAR
        assert_eq!(payload[cursor + 1], u8::MAX);
        cursor += 2;
    }

    let mut rows = Vec::new();
    while payload[cursor] == 0xd1 {
        cursor += 1;
        let mut row = Vec::new();
        for _ in &columns {
            row.push(take_legacy_string(payload, &mut cursor));
        }
        rows.push(row);
    }

    assert_eq!(payload[cursor], 0xfd);
    assert_eq!(payload.len() - cursor, 9);
    cursor += 1;
    let status = take_u16(payload, &mut cursor);
    assert_eq!(status & 0x10, 0x10);
    assert_eq!(take_u16(payload, &mut cursor), 0);
    let row_count = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().unwrap());
    assert_eq!(row_count as usize, rows.len());
    cursor += 4;
    assert_eq!(cursor, payload.len());
    (columns, rows)
}

fn take_u16(payload: &[u8], cursor: &mut usize) -> usize {
    let value = u16::from_le_bytes(payload[*cursor..*cursor + 2].try_into().unwrap());
    *cursor += 2;
    usize::from(value)
}

fn take_legacy_string(payload: &[u8], cursor: &mut usize) -> String {
    let len = usize::from(payload[*cursor]);
    *cursor += 1;
    let value = String::from_utf8(payload[*cursor..*cursor + len].to_vec()).unwrap();
    *cursor += len;
    value
}
