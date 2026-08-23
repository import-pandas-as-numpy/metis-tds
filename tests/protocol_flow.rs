use std::time::Duration;

use metis_tds::{
    Config,
    server::Server,
    tds::{
        self,
        packet::{read_message, write_message},
        prelogin::{Encryption, encode_request, encode_request_with_nonce},
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
    write_message(
        &mut client,
        tds::SQL_BATCH,
        &with_transaction_header(&sql),
        4096,
    )
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
async fn login7_feature_extensions_receive_live_acknowledgements() {
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.stdout = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(
        &mut client,
        tds::PRELOGIN,
        &encode_request(Encryption::Off, "MSSQLSERVER"),
        4096,
    )
    .await
    .unwrap();
    read_message(&mut client, 4096, 65_536).await.unwrap();
    write_message(
        &mut client,
        tds::LOGIN7,
        &login7_with_supported_features(),
        4096,
    )
    .await
    .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();

    let expected = [
        0xae, // FEATUREEXTACK
        0x04, 1, 0, 0, 0, 1, // COLUMNENCRYPTION, downgraded to baseline v1
        0x0a, 1, 0, 0, 0, 1, // UTF8_SUPPORT
        0x0d, 1, 0, 0, 0, 1, // JSON_SUPPORT
        0x0e, 1, 0, 0, 0, 2, // VECTOR_SUPPORT v2
        0x10, 1, 0, 0, 0, 1, // USERAGENT
        0xff,
    ];
    assert!(
        response
            .payload
            .windows(expected.len())
            .any(|window| window == expected)
    );
    task.abort();
}

#[tokio::test]
async fn truncated_fedauth_feature_remains_classified_and_losslessly_visible() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let payload = login7_with_truncated_fedauth();
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN7, &payload, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(response.payload.first(), Some(&0xaa));
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("login attempt");
    assert_eq!(login["federated_authentication"], true);
    assert_eq!(login["fedauth_partial"], true);
    assert_eq!(login["fedauth_library"], 1);
    assert_eq!(login["fedauth_echo"], false);
    assert!(login["source_login_attempt_number"].is_null());
    assert_eq!(login["structurally_valid"], false);
    assert_eq!(login["feature_extension_remainder"]["feature_id"], 2);
    assert_eq!(
        login["feature_extension_remainder"]["declared_data_bytes"],
        32
    );
    assert_eq!(
        login["feature_extension_remainder"]["available_data_bytes"],
        7
    );
    assert_eq!(
        login["feature_extension_remainder_material"],
        "hex:022000000001626561726572"
    );
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
async fn ambiguous_status_is_preserved_until_transport_semantics_are_known() {
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
    // 0x02 means IGNORE in MS-TDS but ATTNACK in legacy TDS. Before transport
    // negotiation the header is ambiguous, so reassembly preserves it and the
    // eventual EOF is an incomplete message rather than a parser rejection.
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

    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "malformed_tds_message")
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
    assert_eq!(close["error_kind"], "io");
    assert_eq!(close["parser_errors"], 0);
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
    assert_eq!(login["legacy_login"]["host_process"], "4242");
    assert_eq!(login["legacy_login"]["client_charset"], "iso_1");
    assert_eq!(login["legacy_login"]["fixed_record_expected_bytes"], 572);
    assert_eq!(login["legacy_login"]["fixed_record_present_bytes"], 572);
    assert_eq!(login["legacy_login"]["remote_password_present"], false);
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
async fn tds42_rpc_is_parsed_as_mbcs_and_fielded() {
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
    write_message(
        &mut client,
        tds::LOGIN,
        &legacy_login("rpc-probe", "sa", "gold", "db-lib"),
        4096,
    )
    .await
    .unwrap();
    read_message(&mut client, 4096, 65_536).await.unwrap();

    let mut rpc = Vec::new();
    rpc.push(10);
    rpc.extend_from_slice(b"p_alltypes");
    rpc.extend_from_slice(&0_u16.to_le_bytes());
    rpc.push(10);
    rpc.extend_from_slice(b"@bigintcol");
    rpc.push(0);
    rpc.push(0x34);
    rpc.extend_from_slice(&1_i16.to_le_bytes());
    write_message(&mut client, tds::RPC, &rpc, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(response.payload.contains(&0xfe));
    drop(client);

    let events = wait_for_events(&telemetry_path, "rpc_request").await;
    let request = events
        .iter()
        .find(|event| event["event_type"] == "rpc_request")
        .expect("legacy RPC telemetry");
    assert_eq!(request["wire_format"], "tds42");
    assert_eq!(request["procedure"], "p_alltypes");
    assert_eq!(request["parameter_names"][0], "@bigintcol");
    assert_eq!(request["parameter_values"][0], "1");
    task.abort();
}

#[tokio::test]
async fn tds46_login_is_identified_and_acknowledged_at_the_negotiated_version() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut login = legacy_login("tds46-probe", "sa", "gold", "db-lib");
    login[458..462].copy_from_slice(&0x0406_0000_u32.to_be_bytes());
    login.truncate(568);
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(
        response
            .payload
            .windows(8)
            .any(|window| window == [0xad, 30, 0, 1, 4, 6, 0, 0])
    );
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let event = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .unwrap();
    assert_eq!(event["login_format"], "tds46_login");
    assert_eq!(event["transport"], "tds46_direct");
    task.abort();
}

#[tokio::test]
async fn tds42_bcp_rows_are_fielded_without_modern_colmetadata() {
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
    write_message(
        &mut client,
        tds::LOGIN,
        &legacy_login("bcp-probe", "sa", "gold", "db-lib"),
        4096,
    )
    .await
    .unwrap();
    read_message(&mut client, 4096, 65_536).await.unwrap();
    let row = [
        0x17, 0x00, 0x01, 0x00, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17, 0x00, b'e', b'b', b'c',
        b'd', b'e', 0x02, 0x14, 0x0f,
    ];
    write_message(&mut client, tds::BULK_LOAD, &row, 4096)
        .await
        .unwrap();
    read_message(&mut client, 4096, 65_536).await.unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "bulk_load").await;
    let bulk = events
        .iter()
        .find(|event| event["event_type"] == "bulk_load")
        .unwrap();
    assert_eq!(bulk["bulk_format"], "tds42_bcp");
    assert_eq!(bulk["row_count"], 1);
    assert_eq!(bulk["sampled_rows"][0]["variable_value_lengths"][0], 5);
    task.abort();
}

#[tokio::test]
async fn unexpected_complete_initial_message_is_archived() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_directory = temp.path().join("payloads");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.payloads.enabled = true;
    config.payloads.directory = payload_directory.to_string_lossy().into_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let payload = b"SELECT complete_initial_probe";
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::SQL_BATCH, payload, 4096)
        .await
        .unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    let capture = events
        .iter()
        .find(|event| {
            event["event_type"] == "tds_message_artifact"
                && event["reason"] == "unexpected_initial_message"
        })
        .expect("unexpected initial message artifact");
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    assert_eq!(std::fs::read(stored).unwrap(), payload);
    task.abort();
}

#[tokio::test]
async fn direct_tds5_authentication_packet_families_reach_semantic_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    for packet_type in [tds::TDS5_NORMAL, tds::TDS5_COMMAND_SEQUENCE_LOGIN] {
        let mut client = TcpStream::connect(address).await.unwrap();
        write_message(&mut client, packet_type, &tds5_login_parameters(), 512)
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    }

    let mut completed = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let events: Vec<Value> = std::fs::read_to_string(&telemetry_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if events
            .iter()
            .filter(|event| event["event_type"] == "tds5_authentication_stream")
            .count()
            == 2
        {
            completed = Some(events);
            break;
        }
    }
    let events = completed.expect("two direct TDS 5 authentication stream events");
    let streams = events
        .iter()
        .filter(|event| event["event_type"] == "tds5_authentication_stream")
        .collect::<Vec<_>>();
    assert!(streams.iter().any(|event| {
        event["transport"] == "tds50_authentication_direct"
            && event["parameter_material"][0] == "identity"
    }));
    assert!(streams.iter().any(|event| {
        event["transport"] == "tds50_command_sequence_login_direct"
            && event["parameter_material"][0] == "identity"
    }));
    assert!(streams.iter().all(|event| {
        event["message_types"][0]["message_type"] == 25
            && event["message_types"][0]["name"] == "login_parameters"
    }));
    let inbound_authentication = events
        .iter()
        .filter(|event| {
            event["event_type"] == "tds_message"
                && event["protocol_stage"] == "login_read"
                && event["authentication_message"] == true
        })
        .count();
    assert_eq!(inbound_authentication, 2);
    task.abort();
}

#[tokio::test]
async fn unnegotiated_smp_cannot_hide_complete_or_truncated_login7() {
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

    let inner = tds_wire_message(
        tds::LOGIN7,
        &login7("smp-probe", "smp-password", "mars-client", "master"),
    );
    let mut complete = smp_control_frame(0x01, 7, 0);
    complete.extend_from_slice(&smp_data_frame(7, 1, &inner, inner.len()));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&complete).await.unwrap();
    client.shutdown().await.unwrap();

    let partial_inner = &inner[..12];
    let truncated = smp_data_frame(8, 2, partial_inner, inner.len());
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&truncated).await.unwrap();
    client.shutdown().await.unwrap();

    let mut completed = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let events: Vec<Value> = std::fs::read_to_string(&telemetry_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let semantic_count = events
            .iter()
            .filter(|event| event["event_type"] == "smp_embedded_authentication")
            .count();
        let capture_count = events
            .iter()
            .filter(|event| event["event_type"] == "incomplete_authentication_message_capture")
            .count();
        if semantic_count == 2 && capture_count == 2 {
            completed = Some(events);
            break;
        }
    }
    let events = completed.expect("complete and truncated SMP authentication telemetry");
    let semantic = events
        .iter()
        .find(|event| {
            event["event_type"] == "smp_embedded_authentication" && event["smp_session_id"] == 7
        })
        .expect("complete SMP LOGIN7 telemetry");
    assert_eq!(semantic["inner_message_complete"], true);
    assert_eq!(semantic["authentication_kind"], "login7");
    assert_eq!(semantic["username"], "smp-probe");
    assert_eq!(semantic["password"], "smp-password");
    let ingress = events
        .iter()
        .find(|event| {
            event["event_type"] == "smp_ingress"
                && event["frames"]
                    .as_array()
                    .is_some_and(|frames| frames.len() == 2)
        })
        .expect("SMP SYN and DATA inventory");
    assert_eq!(ingress["frames"][0]["flag_name"], "syn");
    assert_eq!(ingress["frames"][1]["flag_name"], "data");

    let partial = events
        .iter()
        .find(|event| {
            event["event_type"] == "smp_embedded_authentication" && event["smp_session_id"] == 8
        })
        .expect("truncated SMP LOGIN7 telemetry");
    assert_eq!(partial["inner_message_complete"], false);
    assert_eq!(partial["inner_packet_type"], tds::LOGIN7);
    assert!(partial["inner_parse_error"].as_str().is_some());

    let captures = events
        .iter()
        .filter(|event| event["event_type"] == "incomplete_authentication_message_capture")
        .collect::<Vec<_>>();
    assert_eq!(captures.len(), 2);
    assert!(events.iter().all(|event| {
        event["event_type"] != "incomplete_tds_message_capture" || event["first_byte"] != 0x53
    }));
    let complete_capture = captures
        .iter()
        .find(|event| event["size"] == complete.len())
        .expect("complete SMP authentication artifact");
    let stored = payload_directory.join(format!(
        "{}.bin",
        complete_capture["storage_id"].as_str().unwrap()
    ));
    assert_eq!(std::fs::read(stored).unwrap(), complete);
    task.abort();
}

#[tokio::test]
async fn tds50_login_negotiates_capabilities_and_fields_a_language_token() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(
        &mut client,
        tds::LOGIN,
        &tds50_login("ase-probe", "sa", "gold", "ct-lib"),
        512,
    )
    .await
    .unwrap();
    let login = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(
        login
            .payload
            .windows(8)
            .any(|window| window == [0xad, 30, 0, 5, 5, 0, 0, 0])
    );
    assert!(
        login
            .payload
            .windows(5)
            .any(|window| window == [0xe2, 18, 0, 1, 7])
    );

    let query = b"SELECT @@VERSION";
    let mut language = vec![0x21];
    language.extend_from_slice(&(query.len() as u32 + 1).to_le_bytes());
    language.push(0); // no parameters
    language.extend_from_slice(query);
    write_message(&mut client, tds::TDS5_NORMAL, &language, 512)
        .await
        .unwrap();
    let result = read_message(&mut client, 4096, 65_536).await.unwrap();
    let (_, rows) = parse_tds42_varchar_result(&result.payload);
    assert!(rows[0][0].starts_with("Microsoft SQL Server"));
    drop(client);

    let events = wait_for_events(&telemetry_path, "tds5_token_stream").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("TDS 5 login telemetry");
    assert_eq!(login["tds_version"], "0x05000000");
    assert_eq!(login["password"], "gold");
    let request = events
        .iter()
        .find(|event| event["event_type"] == "tds5_token_stream")
        .expect("TDS 5 request telemetry");
    assert_eq!(request["raw_sql"], "SELECT @@VERSION");
    assert_eq!(request["request_type"], "tds5_token_stream");
    task.abort();
}

#[tokio::test]
async fn tds50_secure_login_elicits_decrypts_and_records_the_password() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_directory = temp.path().join("payloads");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = true;
    config.payloads.directory = payload_directory.to_string_lossy().into_owned();
    config.payloads.capture_login_messages = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut login = tds50_login("secure-probe", "sa", "", "ct-lib");
    login[514] = 0xa0; // ENCRYPT2 | ENCRYPT3, as emitted by current FreeTDS.
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 512)
        .await
        .unwrap();
    let challenge = read_message(&mut client, 4096, 65_536).await.unwrap();
    let parsed = tds::tds5::parse_authentication(&challenge.payload, 65_536).unwrap();
    assert_eq!(parsed.message_types[0].message_type, 30);
    assert_eq!(parsed.parameter_value_bytes.len(), 3);
    let pem = std::str::from_utf8(parsed.parameter_value(1).unwrap()).unwrap();
    let nonce = parsed.parameter_value(2).unwrap();
    let plaintext = [nonce, b"Summer2026!"].concat();
    let ciphertext = encrypt_oaep_sha1_pem(pem, true, &plaintext);

    let mut continuation = vec![0x65, 3, 1, 31, 0];
    continuation.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    continuation.push(0xd7);
    continuation.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    continuation.extend_from_slice(&ciphertext);
    write_message(&mut client, tds::TDS5_NORMAL, &continuation, 512)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(
        response
            .payload
            .windows(4)
            .any(|window| window == [0xad, 30, 0, 5])
    );
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("secure TDS 5 login attempt");
    assert_eq!(login["login_format"], "tds50_login");
    assert_eq!(login["transport"], "tds50_direct");
    assert_eq!(login["tds5_secure_password_requested"], true);
    assert_eq!(login["tds5_secure_password_recovered"], true);
    assert_eq!(login["tds5_secure_password_protocol"], "rsa_epep_v3");
    assert_eq!(login["password"], "Summer2026!");
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "tds5_secure_login_continuation")
        .expect("EPEP v3 continuation telemetry");
    assert_eq!(continuation["secure_login_version"], 3);
    assert_eq!(continuation["password_recovered"], true);
    assert_eq!(continuation["symmetric_key_error"], Value::Null);
    assert!(events.iter().any(|event| {
        event["event_type"] == "authentication_message_capture"
            && event["protocol_stage"] == "tds5_secure_login_read"
            && event["packet_type"] == tds::TDS5_NORMAL
    }));
    task.abort();
}

#[tokio::test]
async fn tds50_extended_v2_login_elicits_decrypts_and_records_the_password() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut login = tds50_login("extended-v2-probe", "sa", "", "ct-lib");
    login[514] = 0x20; // ENCRYPT2 only.
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 512)
        .await
        .unwrap();
    let challenge = read_message(&mut client, 4096, 65_536).await.unwrap();
    let parsed = tds::tds5::parse_authentication(&challenge.payload, 65_536).unwrap();
    assert_eq!(parsed.message_types[0].message_type, 14);
    assert_eq!(parsed.parameter_values[0].value, "1");
    let public_pem = std::str::from_utf8(parsed.parameter_value(1).unwrap()).unwrap();
    let ciphertext = encrypt_oaep_sha1_pem(public_pem, false, b"Password1");

    let mut continuation = vec![0x65, 3, 1, 15, 0];
    continuation.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    continuation.push(0xd7);
    continuation.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    continuation.extend_from_slice(&ciphertext);
    write_message(&mut client, tds::TDS5_NORMAL, &continuation, 512)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(
        response
            .payload
            .windows(4)
            .any(|window| window == [0xad, 30, 0, 5])
    );
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("extended v2 login telemetry");
    assert_eq!(login["tds5_secure_password_protocol"], "rsa_extended_v2");
    assert_eq!(login["tds5_secure_password_recovered"], true);
    assert_eq!(login["password"], "Password1");
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "tds5_secure_login_continuation")
        .expect("extended v2 continuation telemetry");
    assert_eq!(continuation["secure_login_version"], 2);
    assert_eq!(continuation["message_types"][0]["message_type"], 15);
    assert_eq!(continuation["password_recovered"], true);
    task.abort();
}

#[tokio::test]
async fn tds50_proprietary_v1_login_elicits_and_records_ciphertext_without_false_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut login = tds50_login("proprietary-v1-probe", "sa", "", "ct-lib");
    login[514] = 0x01; // ENCRYPT: original proprietary secure-login protocol.
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 512)
        .await
        .unwrap();
    let challenge = read_message(&mut client, 4096, 65_536).await.unwrap();
    let parsed = tds::tds5::parse_authentication(&challenge.payload, 65_536).unwrap();
    assert_eq!(parsed.message_types[0].message_type, 1);
    assert_eq!(parsed.parameter_values[0].type_id, 0x25);
    assert_eq!(parsed.parameter_values[0].data_status, Some(0));
    assert_eq!(parsed.parameter_value(0).unwrap().len(), 16);

    let ciphertext = [0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40];
    let mut continuation = vec![0x65, 3, 1, 2, 0]; // TDS_MSG_SEC_LOGPWD
    continuation.extend_from_slice(&[0xec, 0x0b, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x25, 0xff, 0]);
    continuation.push(0xd7);
    continuation.push(ciphertext.len() as u8);
    continuation.extend_from_slice(&ciphertext);
    write_message(&mut client, tds::TDS5_NORMAL, &continuation, 512)
        .await
        .unwrap();
    let _ = read_message(&mut client, 4096, 65_536).await.unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let secure = events
        .iter()
        .find(|event| event["event_type"] == "tds5_secure_login_continuation")
        .expect("proprietary v1 continuation telemetry");
    assert_eq!(secure["secure_login_version"], 1);
    assert_eq!(secure["expected_response_message_type"], 2);
    assert_eq!(secure["response_message_present"], true);
    assert_eq!(secure["encrypted_password_bytes"], ciphertext.len());
    assert_eq!(secure["password_recovered"], false);
    assert_eq!(
        secure["password_recovery_status"],
        "ciphertext_captured_proprietary_cipher"
    );
    assert_eq!(secure["proprietary_challenge_key_bytes"], 16);
    assert!(
        secure["proprietary_challenge_key"]
            .as_str()
            .is_some_and(|value| value.starts_with("hex:"))
    );
    assert_eq!(secure["parameter_material"][0], "hex:deadbeef10203040");

    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("proprietary v1 login telemetry");
    assert_eq!(
        login["tds5_secure_password_protocol"],
        "proprietary_v1_ciphertext_capture"
    );
    assert_eq!(login["tds5_secure_password_requested"], true);
    assert_eq!(login["tds5_secure_password_recovered"], false);
    assert_eq!(login["accepted"], false);
    assert_eq!(login["password"], Value::Null);
    task.abort();
}

#[tokio::test]
async fn mismatched_tds50_secure_login_response_is_semantically_recorded() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut login = tds50_login("mismatched-secure-probe", "sa", "", "ct-lib");
    login[514] = 0x80; // ENCRYPT3, whose response must be message 31.
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 512)
        .await
        .unwrap();
    let challenge = read_message(&mut client, 4096, 65_536).await.unwrap();
    let parsed = tds::tds5::parse_authentication(&challenge.payload, 65_536).unwrap();
    assert_eq!(parsed.message_types[0].message_type, 30);

    let mut continuation = vec![0x65, 3, 1, 15, 0]; // Valid v2 response, wrong negotiation.
    continuation.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    continuation.extend_from_slice(&[0xd7, 3, 0, 0, 0, 1, 2, 3]);
    write_message(&mut client, tds::TDS5_NORMAL, &continuation, 512)
        .await
        .unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "tds5_secure_login_continuation").await;
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "tds5_secure_login_continuation")
        .expect("mismatched continuation telemetry");
    assert_eq!(continuation["secure_login_version"], 3);
    assert_eq!(continuation["expected_response_message_type"], 31);
    assert_eq!(continuation["response_message_present"], false);
    assert_eq!(continuation["message_types"][0]["message_type"], 15);
    assert_eq!(continuation["password_recovered"], false);
    assert!(
        continuation["password_error"]
            .as_str()
            .unwrap()
            .contains("message type 31")
    );
    assert_eq!(continuation["parameter_material"][0], "hex:010203");
    task.abort();
}

#[tokio::test]
async fn incomplete_tds50_secure_login_continuation_is_retained_as_authentication() {
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

    let mut login = tds50_login("truncated-secure-probe", "sa", "", "ct-lib");
    login[514] = 0x80; // ENCRYPT3
    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 512)
        .await
        .unwrap();
    read_message(&mut client, 4096, 65_536).await.unwrap();

    // Declare a 24-byte packet but close after only half of its body. Packet
    // type 0x0f is overloaded with ordinary TDS 5 streams, so only the
    // protocol stage proves that this is authentication material.
    client
        .write_all(&[tds::TDS5_NORMAL, 0x01, 0, 24, 0, 0, 1, 0])
        .await
        .unwrap();
    client
        .write_all(&[0x65, 3, 1, 31, 0, 0xec, 0, 0])
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    drop(client);

    let events =
        wait_for_events(&telemetry_path, "incomplete_authentication_message_capture").await;
    let capture = events
        .iter()
        .find(|event| event["event_type"] == "incomplete_authentication_message_capture")
        .expect("truncated EPEP continuation capture");
    assert_eq!(capture["packet_type"], tds::TDS5_NORMAL);
    assert_eq!(capture["packet_type_name"], "normal");
    assert_eq!(capture["wire_format"], "tds_packets_with_headers");
    assert_eq!(capture["size"], 16);
    assert!(
        payload_directory
            .join(format!("{}.bin", capture["storage_id"].as_str().unwrap()))
            .exists()
    );
    let request = events
        .iter()
        .find(|event| event["event_type"] == "tds5_login_security_request")
        .expect("pre-negotiation secure-login request telemetry");
    assert_eq!(request["username"], "sa");
    assert_eq!(request["tds5_secure_password_protocol"], "rsa_epep_v3");
    task.abort();
}

#[tokio::test]
async fn tds50_epep_login_negotiates_nonce_and_records_the_password() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    config.payloads.enabled = false;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut login = tds50_login("epep-probe", "sa", "", "ct-lib");
    login[514] = 0xa0; // ENCRYPT2 | ENCRYPT3
    login.truncate(568);
    let mut request = vec![0_u8; 14];
    request[0] = 0x04; // TDS_REQ_COMMAND_ENCRYPTION (capability 106)
    let response = [0_u8; 7];
    let mut capability = vec![1, request.len() as u8];
    capability.extend_from_slice(&request);
    capability.extend_from_slice(&[2, response.len() as u8]);
    capability.extend_from_slice(&response);
    login.push(0xe2);
    login.extend_from_slice(&(capability.len() as u16).to_le_bytes());
    login.extend_from_slice(&capability);

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &login, 512)
        .await
        .unwrap();
    let challenge = read_message(&mut client, 4096, 65_536).await.unwrap();
    let parsed = tds::tds5::parse_authentication(&challenge.payload, 65_536).unwrap();
    assert!(
        parsed
            .message_types
            .iter()
            .any(|message| message.message_type == 35)
    );
    let public_pem = std::str::from_utf8(parsed.parameter_value(1).unwrap()).unwrap();
    let nonce: [u8; 32] = parsed.parameter_value(2).unwrap().try_into().unwrap();
    let plaintext = [nonce.as_slice(), b"August2026!"].concat();
    let ciphertext = encrypt_oaep_sha1_pem(public_pem, true, &plaintext);
    let symmetric_key = [0x6d; 32];
    let symmetric_plaintext = [nonce.as_slice(), symmetric_key.as_slice()].concat();
    let symmetric_ciphertext = encrypt_oaep_sha1_pem(public_pem, true, &symmetric_plaintext);

    let mut continuation = vec![0x65, 3, 1, 31, 0];
    continuation.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    continuation.push(0xd7);
    continuation.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    continuation.extend_from_slice(&ciphertext);
    continuation.extend_from_slice(&[0x65, 3, 1, 34, 0]);
    continuation.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    continuation.push(0xd7);
    continuation.extend_from_slice(&(symmetric_ciphertext.len() as u32).to_le_bytes());
    continuation.extend_from_slice(&symmetric_ciphertext);
    write_message(&mut client, tds::TDS5_NORMAL, &continuation, 512)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert!(
        response
            .payload
            .windows(4)
            .any(|window| window == [0xad, 30, 0, 5])
    );
    client
        .write_all(&[tds::TDS5_NORMAL, 0x41, 0, 24, 0, 0, 1, 0])
        .await
        .unwrap();
    client.write_all(&[0xa5; 16]).await.unwrap();
    client.flush().await.unwrap();
    write_message(&mut client, 0x08, b"setup-probe", 512)
        .await
        .unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "legacy_tds_control_message").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("EPEP login telemetry");
    assert_eq!(login["tds5_command_encryption"], true);
    assert_eq!(login["tds5_secure_password_recovered"], true);
    assert_eq!(login["tds5_secure_password_protocol"], "rsa_epep_v4");
    assert_eq!(
        login["tds5_security_modes"],
        serde_json::json!(["encrypted_login_v2", "encrypted_login_v3_or_v4"])
    );
    assert!(
        login["legacy_capabilities"]["request_enabled"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(106))
    );
    assert_eq!(login["password"], "August2026!");
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "tds5_secure_login_continuation")
        .expect("EPEP continuation telemetry");
    assert_eq!(continuation["secure_login_version"], 4);
    assert_eq!(continuation["password_recovered"], true);
    assert_eq!(continuation["symmetric_key_recovered"], true);
    assert_eq!(continuation["symmetric_key_error"], serde_json::Value::Null);
    let material = continuation["parameter_material"].as_array().unwrap();
    assert_eq!(material.len(), 2);
    assert!(material.iter().all(|value| {
        value
            .as_str()
            .is_some_and(|value| value.starts_with("hex:"))
    }));
    let encrypted = events
        .iter()
        .find(|event| event["event_type"] == "tds5_encrypted_command")
        .expect("EPEP encrypted-command telemetry");
    assert_eq!(encrypted["symmetric_key_available"], true);
    assert_eq!(encrypted["symmetrically_encrypted_packets"], 1);
    assert_eq!(encrypted["packets"][0]["status"], 0x41);
    assert_eq!(encrypted["packets"][0]["body_offset"], 0);
    assert_eq!(encrypted["packets"][0]["body_bytes"], 16);
    assert_eq!(encrypted["encrypted_packet_shapes"][0]["body_bytes"], 16);
    assert_eq!(
        encrypted["encrypted_packet_shapes"][0]["ciphertext_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        encrypted["encrypted_packet_shapes"][0]["first_block"],
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
    );
    assert_eq!(
        encrypted["encrypted_packet_shapes"][0]["last_block"],
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
    );
    assert_eq!(
        encrypted["encrypted_packet_shapes"][0]["body_block_aligned"],
        true
    );
    assert_eq!(
        encrypted["encrypted_packet_shapes"][0]["body_after_iv_prefix_bytes"],
        0
    );
    assert_eq!(
        encrypted["encrypted_packet_shapes"][0]["body_after_iv_prefix_block_aligned"],
        false
    );
    assert_eq!(
        encrypted["decryption_status"],
        "ciphertext_preserved_pending_verified_iv_framing"
    );
    let setup = events
        .iter()
        .find(|event| {
            event["event_type"] == "legacy_tds_control_message" && event["packet_type"] == 0x08
        })
        .expect("ASE SETUP telemetry");
    assert_eq!(setup["packet_type_name"], "setup");
    assert!(!events.iter().any(|event| {
        event["event_type"] == "federated_authentication_token" && event["token_bytes"] == 11
    }));
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
async fn malformed_tds5_capability_prefix_does_not_hide_embedded_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut payload = tds50_login("capability-probe", "sa", "", "ct-lib");
    payload.truncate(568);
    payload.extend_from_slice(&[0x19, 0xde, 0xad]);
    payload.extend_from_slice(&[0x65, 3, 1, 31, 0]);
    payload.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    payload.extend_from_slice(&[0xd7, 4, 0, 0, 0, 1, 2, 3, 4]);

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN, &payload, 4096)
        .await
        .unwrap();
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(response.payload.first(), Some(&0xaa));
    drop(client);

    let events = wait_for_events(&telemetry_path, "login_attempt").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("malformed TDS 5 login telemetry");
    assert_eq!(login["structurally_valid"], false);
    assert_eq!(
        login["legacy_authentication"]["message_types"][0]["message_type"],
        31
    );
    assert_eq!(
        login["legacy_authentication"]["encrypted_login_password_bytes"],
        4
    );
    assert_eq!(login["legacy_authentication_material"][0], "hex:01020304");
    assert_eq!(
        login["legacy_authentication"]["unparsed_regions"][0]["bytes"],
        3
    );
    let security_request = events
        .iter()
        .find(|event| event["event_type"] == "tds5_login_security_request")
        .expect("embedded TDS 5 authentication telemetry before decision");
    assert_eq!(security_request["username"], "sa");
    assert_eq!(
        security_request["embedded_parameter_material"][0],
        "hex:01020304"
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
async fn direct_ntlm_login_captures_identity_and_challenge_response() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
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
    let challenge = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(challenge.payload.first(), Some(&0xed));
    write_message(
        &mut client,
        tds::SSPI,
        &ntlm_authenticate("CORP", "scanner", "WS-17"),
        4096,
    )
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
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "sspi_message" && event["phase"] == "continuation")
        .expect("SSPI continuation telemetry");
    assert_eq!(continuation["message_type"], 3);
    assert_eq!(continuation["domain"], "CORP");
    assert_eq!(continuation["username"], "scanner");
    assert_eq!(continuation["workstation"], "WS-17");
    assert_eq!(continuation["nt_response_variant"], "ntlmv2");
    assert_eq!(continuation["server_challenge"].as_str().unwrap().len(), 16);
    assert_eq!(continuation["lm_response"].as_str().unwrap().len(), 48);
    assert_eq!(continuation["nt_response"].as_str().unwrap().len(), 96);
    assert!(
        !std::fs::read_to_string(&telemetry_path)
            .unwrap()
            .contains("synthetic-negotiate")
    );
    task.abort();
}

#[tokio::test]
async fn adal_login_fields_and_archives_the_fedauth_continuation() {
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

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(&mut client, tds::LOGIN7, &adal_login7(), 4096)
        .await
        .unwrap();
    let information = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(information.payload.first(), Some(&0xee));
    assert!(contains_utf16(
        &information.payload,
        "https://login.microsoftonline.com/common/oauth2/token"
    ));
    assert!(contains_utf16(
        &information.payload,
        "https://database.windows.net/"
    ));

    let mut token = Vec::new();
    token.extend_from_slice(&7_u32.to_le_bytes());
    token.extend_from_slice(&3_u32.to_le_bytes());
    token.extend_from_slice(b"jwt");
    write_message(&mut client, tds::FEDAUTH_TOKEN, &token, 4096)
        .await
        .unwrap();
    let failure = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(failure.payload.first(), Some(&0xaa));
    drop(client);

    let events = wait_for_events(&telemetry_path, "federated_authentication_token").await;
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("federated login attempt");
    assert_eq!(login["federated_authentication"], true);
    assert_eq!(login["fedauth_library"], 2);
    assert_eq!(login["fedauth_workflow"], 1);
    assert!(login["source_login_attempt_number"].is_null());
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "federated_authentication_token")
        .expect("federated token telemetry");
    assert_eq!(continuation["phase"], "continuation");
    assert_eq!(continuation["token_bytes"], 3);
    let capture = events
        .iter()
        .find(|event| {
            event["event_type"] == "authentication_message_capture"
                && event["packet_type"] == tds::FEDAUTH_TOKEN
        })
        .expect("federated token artifact");
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    assert_eq!(std::fs::read(stored).unwrap(), token);
    task.abort();
}

#[tokio::test]
async fn adal_continuation_captures_token_and_validates_prelogin_nonce() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let mut config = Config::default();
    config.listener.address = "127.0.0.1:0".into();
    config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    config.telemetry.stdout = false;
    config.telemetry.capture_login_passwords = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(Server::new(config).await.unwrap().serve(listener, false));

    let mut client = TcpStream::connect(address).await.unwrap();
    write_message(
        &mut client,
        tds::PRELOGIN,
        &encode_request_with_nonce(Encryption::NotSupported, "MSSQLSERVER", Some([9; 32])),
        4096,
    )
    .await
    .unwrap();
    let prelogin_response = read_message(&mut client, 4096, 65_536).await.unwrap();
    let server_nonce = tds::prelogin::parse(&prelogin_response.payload)
        .unwrap()
        .nonce
        .expect("server nonce");
    assert_ne!(server_nonce, [9; 32]);

    write_message(&mut client, tds::LOGIN7, &adal_login7(), 4096)
        .await
        .unwrap();
    let information = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(information.payload.first(), Some(&0xee));

    let mut token = Vec::new();
    token.extend_from_slice(&39_u32.to_le_bytes());
    token.extend_from_slice(&3_u32.to_le_bytes());
    token.extend_from_slice(b"jwt");
    token.extend_from_slice(&server_nonce);
    write_message(&mut client, tds::FEDAUTH_TOKEN, &token, 4096)
        .await
        .unwrap();
    let failure = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(failure.payload.first(), Some(&0xaa));
    drop(client);

    let events = wait_for_events(&telemetry_path, "federated_authentication_token").await;
    let continuation = events
        .iter()
        .find(|event| event["event_type"] == "federated_authentication_token")
        .expect("federated token telemetry");
    assert_eq!(continuation["phase"], "continuation");
    assert_eq!(continuation["token"], "jwt");
    assert_eq!(continuation["nonce_present"], true);
    assert_eq!(continuation["nonce_matches"], true);
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
async fn incomplete_login7_is_archived_with_packet_headers() {
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

    let mut wire = vec![tds::LOGIN7, 1, 0, 64, 0, 0, 1, 0];
    wire.extend_from_slice(b"partial-login-secret");
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&wire).await.unwrap();
    drop(client);

    let events = wait_for_events(&telemetry_path, "connection_close").await;
    let capture = events
        .iter()
        .find(|event| event["event_type"] == "incomplete_authentication_message_capture")
        .expect("incomplete authentication artifact");
    assert_eq!(capture["packet_type"], tds::LOGIN7);
    assert_eq!(capture["wire_format"], "tds_packets_with_headers");
    let stored = payload_directory.join(format!("{}.bin", capture["storage_id"].as_str().unwrap()));
    assert_eq!(std::fs::read(stored).unwrap(), wire);
    assert!(
        !std::fs::read_to_string(&telemetry_path)
            .unwrap()
            .contains("partial-login-secret")
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
    let response = read_message(&mut client, 4096, 65_536).await.unwrap();
    assert_eq!(response.payload.first(), Some(&0xaa));
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
    let login = events
        .iter()
        .find(|event| event["event_type"] == "login_attempt")
        .expect("recoverable malformed login telemetry");
    assert_eq!(login["structurally_valid"], false);
    assert_eq!(login["accepted"], false);
    assert!(
        login["parse_warnings"][0]
            .as_str()
            .unwrap()
            .contains("username field is outside message")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "connection_failure")
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

fn encrypt_oaep_sha1_pem(pem: &str, pkcs1: bool, plaintext: &[u8]) -> Vec<u8> {
    use aws_lc_rs::rsa::{
        OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PublicEncryptingKey, PublicKey,
        PublicKeyComponents,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = STANDARD.decode(encoded).unwrap();
    let public = if pkcs1 {
        let parsed = PublicKey::from_der(&der).unwrap();
        let components = PublicKeyComponents::from(&parsed);
        components.try_into().unwrap()
    } else {
        PublicEncryptingKey::from_der(&der).unwrap()
    };
    let public = OaepPublicEncryptingKey::new(public).unwrap();
    let mut ciphertext = vec![0_u8; public.ciphertext_size()];
    public
        .encrypt(&OAEP_SHA1_MGF1SHA1, plaintext, &mut ciphertext, None)
        .unwrap()
        .to_vec()
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

fn tds5_login_parameters() -> Vec<u8> {
    let mut payload = vec![0x65, 3, 1, 25, 0];
    payload.extend_from_slice(&[
        0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
    ]);
    payload.extend_from_slice(&[0xd7, 8, 0, 0, 0]);
    payload.extend_from_slice(b"identity");
    payload
}

fn tds_wire_message(packet_type: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len() + 8).unwrap();
    let mut wire = vec![packet_type, 0x01];
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 1, 0]);
    wire.extend_from_slice(payload);
    wire
}

fn smp_data_frame(
    session_id: u16,
    sequence: u32,
    available_data: &[u8],
    declared_data_bytes: usize,
) -> Vec<u8> {
    let declared_length = u32::try_from(16 + declared_data_bytes).unwrap();
    let mut wire = vec![0x53, 0x08];
    wire.extend_from_slice(&session_id.to_le_bytes());
    wire.extend_from_slice(&declared_length.to_le_bytes());
    wire.extend_from_slice(&sequence.to_le_bytes());
    wire.extend_from_slice(&4_u32.to_le_bytes());
    wire.extend_from_slice(available_data);
    wire
}

fn smp_control_frame(flag: u8, session_id: u16, sequence: u32) -> Vec<u8> {
    let mut wire = vec![0x53, flag];
    wire.extend_from_slice(&session_id.to_le_bytes());
    wire.extend_from_slice(&16_u32.to_le_bytes());
    wire.extend_from_slice(&sequence.to_le_bytes());
    wire.extend_from_slice(&4_u32.to_le_bytes());
    wire
}

fn login7_with_supported_features() -> Vec<u8> {
    let mut packet = login7("feature-client", "Password1", "ODBC 18", "master");
    packet[27] |= 0x10;
    let pointer_offset = packet.len();
    packet[56..58].copy_from_slice(&(pointer_offset as u16).to_le_bytes());
    packet[58..60].copy_from_slice(&4_u16.to_le_bytes());
    let feature_offset = pointer_offset + 4;
    packet.extend_from_slice(&(feature_offset as u32).to_le_bytes());
    for (id, data) in [
        (0x04, vec![2]),
        (0x0a, vec![1]),
        (0x0d, vec![1]),
        (0x0e, vec![2]),
        {
            let encoded: Vec<u8> = "ODBC 18.5|linux"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let mut data = Vec::with_capacity(2 + encoded.len());
            data.extend_from_slice(&(encoded.len() as u16 / 2).to_le_bytes());
            data.extend_from_slice(&encoded);
            (0x10, data)
        },
    ] {
        packet.push(id);
        packet.extend_from_slice(&(data.len() as u32).to_le_bytes());
        packet.extend_from_slice(&data);
    }
    packet.push(0xff);
    let length = packet.len() as u32;
    packet[0..4].copy_from_slice(&length.to_le_bytes());
    packet
}

fn login7_with_truncated_fedauth() -> Vec<u8> {
    let mut packet = login7("", "", "ODBC", "master");
    packet[27] |= 0x10;
    let pointer_offset = packet.len();
    packet[56..58].copy_from_slice(&(pointer_offset as u16).to_le_bytes());
    packet[58..60].copy_from_slice(&4_u16.to_le_bytes());
    let feature_offset = pointer_offset + 4;
    packet.extend_from_slice(&(feature_offset as u32).to_le_bytes());
    packet.push(0x02); // FEDAUTH
    packet.extend_from_slice(&32_u32.to_le_bytes());
    packet.push(0x01); // Security Token library
    packet.extend_from_slice(b"bearer");
    let length = packet.len() as u32;
    packet[0..4].copy_from_slice(&length.to_le_bytes());
    packet
}

fn with_transaction_header(body: &[u8]) -> Vec<u8> {
    let mut payload = vec![22, 0, 0, 0, 18, 0, 0, 0, 2, 0];
    payload.extend_from_slice(&[0; 12]);
    payload.extend_from_slice(body);
    payload
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

fn adal_login7() -> Vec<u8> {
    let mut packet = login7("", "", "ODBC", "master");
    packet[27] |= 0x10;
    let pointer_offset = packet.len();
    packet[56..58].copy_from_slice(&(pointer_offset as u16).to_le_bytes());
    packet[58..60].copy_from_slice(&4_u16.to_le_bytes());
    let feature_offset = pointer_offset + 4;
    packet.extend_from_slice(&(feature_offset as u32).to_le_bytes());
    packet.push(0x02); // FEDAUTH
    packet.extend_from_slice(&2_u32.to_le_bytes());
    packet.extend_from_slice(&[0x02, 0x01]); // ADAL, username/password workflow
    packet.push(0xff);
    let length = packet.len() as u32;
    packet[0..4].copy_from_slice(&length.to_le_bytes());
    packet
}

fn ntlm_authenticate(domain: &str, username: &str, workstation: &str) -> Vec<u8> {
    fn encoded(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
    fn descriptor(packet: &mut [u8], at: usize, offset: usize, bytes: usize) {
        packet[at..at + 2].copy_from_slice(&(bytes as u16).to_le_bytes());
        packet[at + 2..at + 4].copy_from_slice(&(bytes as u16).to_le_bytes());
        packet[at + 4..at + 8].copy_from_slice(&(offset as u32).to_le_bytes());
    }

    let lm = vec![1; 24];
    let mut nt = vec![2; 48];
    nt[16..20].copy_from_slice(&[0x01, 0x01, 0x00, 0x00]);
    let domain = encoded(domain);
    let username = encoded(username);
    let workstation = encoded(workstation);
    let fields = [lm, nt, domain, username, workstation, Vec::new()];
    let mut packet = vec![0_u8; 64];
    packet[..8].copy_from_slice(b"NTLMSSP\0");
    packet[8..12].copy_from_slice(&3_u32.to_le_bytes());
    packet[60..64].copy_from_slice(&1_u32.to_le_bytes());
    for (index, value) in fields.into_iter().enumerate() {
        let offset = packet.len();
        descriptor(&mut packet, 12 + index * 8, offset, value.len());
        packet.extend(value);
    }
    packet
}

fn legacy_login(host: &str, username: &str, password: &str, application: &str) -> Vec<u8> {
    let mut payload = vec![0_u8; 572];
    put_legacy_field(&mut payload, 0, 30, host);
    put_legacy_field(&mut payload, 31, 61, username);
    put_legacy_field(&mut payload, 62, 92, password);
    put_legacy_field(&mut payload, 93, 123, "4242");
    put_legacy_field(&mut payload, 140, 170, application);
    put_legacy_field(&mut payload, 171, 201, "203.0.113.10:1433");
    payload[458..462].copy_from_slice(&0x0402_0000_u32.to_be_bytes());
    put_legacy_field(&mut payload, 462, 472, "pymssql");
    put_legacy_field(&mut payload, 480, 510, "us_english");
    put_legacy_field(&mut payload, 525, 555, "iso_1");
    put_legacy_field(&mut payload, 557, 563, "4096");
    payload
}

fn tds50_login(host: &str, username: &str, password: &str, application: &str) -> Vec<u8> {
    let mut payload = legacy_login(host, username, password, application);
    payload.truncate(568);
    payload[458..462].copy_from_slice(&0x0500_0000_u32.to_be_bytes());
    payload[462..472].fill(0);
    put_legacy_field(&mut payload, 462, 472, "ct-lib");
    payload[202] = 0;
    payload[203] = password.len() as u8;
    payload[204..204 + password.len()].copy_from_slice(password.as_bytes());
    payload[457] = (password.len() + 2) as u8;
    payload.push(0xe2);
    payload.extend_from_slice(&18_u16.to_le_bytes());
    payload.extend_from_slice(&[
        1, 7, 7, 97, 65, 207, 255, 255, 230, 2, 7, 0, 0, 2, 0, 0, 0, 0,
    ]);
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
