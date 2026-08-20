use std::process::Command;

use metis_tds::{Config as ServerConfig, config::TlsMode, server::Server};
use tiberius::{AuthMethod, Config as ClientConfig, EncryptionLevel};
use tokio::net::{TcpListener, TcpStream};
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
    server_config.telemetry.jsonl_path = None;
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
