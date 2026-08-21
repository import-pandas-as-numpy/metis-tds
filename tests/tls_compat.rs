use std::{process::Command, time::Duration};

use metis_tds::{
    Config as ServerConfig,
    config::TlsMode,
    server::Server,
    tds::{
        self,
        packet::{read_message, write_message},
        prelogin::{Encryption, encode_response},
    },
};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use serde_json::Value;
use tiberius::{AuthMethod, Config as ClientConfig, EncryptionLevel};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::test]
async fn tiberius_negotiates_tds_wrapped_tls_and_queries() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("metis_tds=trace,tiberius=trace")
        .with_test_writer()
        .try_init();
    let temp = tempfile::tempdir().unwrap();
    let key_pem = temp.path().join("key.pem");
    let cert_pem = temp.path().join("cert.pem");
    let key_der = temp.path().join("key.der");
    let cert_der = temp.path().join("cert.der");
    let telemetry_path = temp.path().join("events.jsonl");
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        key_pem.to_str().unwrap(),
        "-out",
        cert_pem.to_str().unwrap(),
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=localhost",
    ]);
    openssl(&[
        "x509",
        "-in",
        cert_pem.to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        cert_der.to_str().unwrap(),
    ]);
    openssl(&[
        "pkcs8",
        "-topk8",
        "-inform",
        "PEM",
        "-outform",
        "DER",
        "-in",
        key_pem.to_str().unwrap(),
        "-nocrypt",
        "-out",
        key_der.to_str().unwrap(),
    ]);

    let mut server_config = ServerConfig::default();
    server_config.listener.address = "127.0.0.1:0".into();
    server_config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    server_config.telemetry.stdout = false;
    server_config.tls.mode = TlsMode::Required;
    server_config.tls.certificate_der = Some(cert_der.to_string_lossy().into_owned());
    server_config.tls.private_key_der = Some(key_der.to_string_lossy().into_owned());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(
        Server::new(server_config)
            .await
            .unwrap()
            .serve(listener, false),
    );

    let mut client_config = ClientConfig::new();
    client_config.host("localhost");
    client_config.port(address.port());
    client_config.database("master");
    client_config.authentication(AuthMethod::sql_server("tls-scanner", "decoy-password"));
    client_config.encryption(EncryptionLevel::Required);
    client_config.trust_cert();
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut client = tiberius::Client::connect(client_config, tcp.compat_write())
        .await
        .unwrap();
    let rows = client
        .simple_query("SELECT @@SERVERNAME")
        .await
        .unwrap()
        .into_first_result()
        .await
        .unwrap();
    assert_eq!(rows[0].get::<&str, _>(0), Some("SQL-FIN-01"));

    let mut incomplete_tls = TcpStream::connect(address).await.unwrap();
    write_message(
        &mut incomplete_tls,
        tds::PRELOGIN,
        &encode_response(Encryption::On, ""),
        4096,
    )
    .await
    .unwrap();
    read_message(&mut incomplete_tls, 4096, 65_536)
        .await
        .unwrap();
    drop(incomplete_tls);

    let mut events = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        events = std::fs::read_to_string(&telemetry_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        if events.iter().any(|event| {
            event["event_type"] == "connection_close" && event["protocol_stage"] == "tls_handshake"
        }) {
            break;
        }
    }
    let close = events
        .iter()
        .find(|event| {
            event["event_type"] == "connection_close" && event["protocol_stage"] == "tls_handshake"
        })
        .expect("TLS handshake failure telemetry");
    assert_eq!(close["source_ip"], "127.0.0.1");
    assert_eq!(close["error_kind"], "tls");
    assert_eq!(close["parser_errors"], 0);
    assert!(close["bytes_read"].as_u64().unwrap() > 8);
    assert!(close["bytes_written"].as_u64().unwrap() > 8);
    server_task.abort();
}

fn openssl(arguments: &[&str]) {
    let output = Command::new("openssl").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn tds8_raw_tls_precedes_prelogin_and_login7() {
    let temp = tempfile::tempdir().unwrap();
    let key_pem = temp.path().join("key.pem");
    let cert_pem = temp.path().join("cert.pem");
    let key_der = temp.path().join("key.der");
    let cert_der = temp.path().join("cert.der");
    let telemetry_path = temp.path().join("events.jsonl");
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        key_pem.to_str().unwrap(),
        "-out",
        cert_pem.to_str().unwrap(),
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
    ]);
    openssl(&[
        "x509",
        "-in",
        cert_pem.to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        cert_der.to_str().unwrap(),
    ]);
    openssl(&[
        "pkcs8",
        "-topk8",
        "-inform",
        "PEM",
        "-outform",
        "DER",
        "-in",
        key_pem.to_str().unwrap(),
        "-nocrypt",
        "-out",
        key_der.to_str().unwrap(),
    ]);

    let mut server_config = ServerConfig::default();
    server_config.listener.address = "127.0.0.1:0".into();
    server_config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    server_config.telemetry.stdout = false;
    server_config.tls.mode = TlsMode::Required;
    server_config.tls.certificate_der = Some(cert_der.to_string_lossy().into_owned());
    server_config.tls.private_key_der = Some(key_der.to_string_lossy().into_owned());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(
        Server::new(server_config)
            .await
            .unwrap()
            .serve(listener, false),
    );

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(std::fs::read(&cert_der).unwrap()))
        .unwrap();
    let mut client_config = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"tds/8.0".to_vec()];
    let connector = TlsConnector::from(std::sync::Arc::new(client_config));
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap().to_owned(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"tds/8.0".as_slice()));

    write_message(
        &mut tls,
        tds::PRELOGIN,
        &encode_response(Encryption::Required, "MSSQLSERVER"),
        4096,
    )
    .await
    .unwrap();
    let prelogin_response = read_message(&mut tls, 4096, 65_536).await.unwrap();
    assert_eq!(prelogin_response.packet_type, tds::TABULAR_RESULT);
    let parsed = tds::prelogin::parse(&prelogin_response.payload).unwrap();
    assert_eq!(parsed.encryption, Some(Encryption::Required));

    write_message(
        &mut tls,
        tds::LOGIN7,
        &login7("strict-client", "weak-password", "ODBC 18"),
        4096,
    )
    .await
    .unwrap();
    let login_response = read_message(&mut tls, 4096, 65_536).await.unwrap();
    assert!(login_response.payload.contains(&0xad));

    tokio::time::sleep(Duration::from_millis(50)).await;
    let events: Vec<Value> = std::fs::read_to_string(&telemetry_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert!(events.iter().any(|event| {
        event["event_type"] == "tls_negotiated"
            && event["transport"] == "tds8"
            && event["alpn_protocol"] == "tds/8.0"
    }));
    assert!(
        events
            .iter()
            .any(|event| { event["event_type"] == "prelogin" && event["transport"] == "tds8" })
    );
    assert!(events.iter().any(|event| {
        event["event_type"] == "login_attempt" && event["username"] == "strict-client"
    }));
    server_task.abort();
}

fn login7(username: &str, password: &str, application: &str) -> Vec<u8> {
    let mut packet = vec![0_u8; 94];
    packet[4..8].copy_from_slice(&0x0800_0000_u32.to_le_bytes());
    packet[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    packet[24] = 0xe0;
    packet[25] = 0x03;
    let fields = [
        (36, "STRICTCLIENT", false),
        (40, username, false),
        (44, password, true),
        (48, application, false),
        (52, "SQL-FIN-01", false),
        (60, "ODBC", false),
        (64, "us_english", false),
        (68, "master", false),
    ];
    for (descriptor, value, password_field) in fields {
        let offset = u16::try_from(packet.len()).unwrap();
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if password_field {
            for byte in &mut encoded {
                *byte = byte.rotate_right(4) ^ 0xa5;
            }
        }
        packet[descriptor..descriptor + 2].copy_from_slice(&offset.to_le_bytes());
        packet[descriptor + 2..descriptor + 4]
            .copy_from_slice(&u16::try_from(encoded.len() / 2).unwrap().to_le_bytes());
        packet.extend_from_slice(&encoded);
    }
    let packet_len = u32::try_from(packet.len()).unwrap();
    packet[0..4].copy_from_slice(&packet_len.to_le_bytes());
    packet
}
