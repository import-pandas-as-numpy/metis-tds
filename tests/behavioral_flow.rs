use std::time::Duration;

use metis_tds::{Config as ServerConfig, server::Server};
use tiberius::{AuthMethod, Config as ClientConfig, EncryptionLevel};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::test]
async fn attacker_workflow_is_stateful_logged_and_never_executed() {
    let temp = tempfile::tempdir().unwrap();
    let telemetry_path = temp.path().join("events.jsonl");
    let payload_path = temp.path().join("payloads");
    let mut server_config = ServerConfig::default();
    server_config.telemetry.jsonl_path = Some(telemetry_path.to_string_lossy().into_owned());
    server_config.telemetry.stdout = false;
    server_config.payloads.enabled = true;
    server_config.payloads.directory = payload_path.to_string_lossy().into_owned();
    server_config.personality.honey_objects = vec!["dbo.DomainAdminCredentials".into()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(
        Server::new(server_config)
            .await
            .unwrap()
            .serve(listener, false),
    );

    let mut client_config = ClientConfig::new();
    client_config.host(address.ip().to_string());
    client_config.port(address.port());
    client_config.authentication(AuthMethod::sql_server("attacker", "must-not-be-logged"));
    client_config.encryption(EncryptionLevel::NotSupported);
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut client = tiberius::Client::connect(client_config, tcp.compat_write())
        .await
        .unwrap();

    client
        .simple_query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE")
        .await
        .unwrap()
        .into_results()
        .await
        .unwrap();
    let rows = client
        .simple_query("EXEC xp_cmdshell 'whoami'")
        .await
        .unwrap()
        .into_first_result()
        .await
        .unwrap();
    assert_eq!(rows[0].get::<&str, _>(0), Some("nt service\\mssqlserver"));
    client
        .simple_query("CREATE ASSEMBLY Probe FROM 0x4d5a900003000000")
        .await
        .unwrap()
        .into_results()
        .await
        .unwrap();
    client
        .simple_query("SELECT * FROM dbo.DomainAdminCredentials")
        .await
        .unwrap()
        .into_results()
        .await
        .unwrap();
    drop(client);

    let mut second_config = ClientConfig::new();
    second_config.host(address.ip().to_string());
    second_config.port(address.port());
    second_config.authentication(AuthMethod::sql_server("second-session", "different-decoy"));
    second_config.encryption(EncryptionLevel::NotSupported);
    let second_tcp = TcpStream::connect(address).await.unwrap();
    let mut second = tiberius::Client::connect(second_config, second_tcp.compat_write())
        .await
        .unwrap();
    let disabled = second.simple_query("EXEC xp_cmdshell 'whoami'").await;
    assert!(
        disabled.is_err(),
        "xp_cmdshell state leaked between sessions"
    );
    drop(disabled);
    drop(second);

    let mut telemetry = String::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        telemetry = std::fs::read_to_string(&telemetry_path).unwrap_or_default();
        if telemetry.contains("\"event_type\":\"connection_close\"") {
            break;
        }
    }
    assert!(telemetry.contains("\"classification\":\"xp_cmdshell\""));
    assert!(telemetry.contains("EXEC xp_cmdshell 'whoami'"));
    assert!(telemetry.contains("\"event_type\":\"payload_capture\""));
    assert!(telemetry.contains("\"event_type\":\"honey_object_access\""));
    assert!(!telemetry.contains("must-not-be-logged"));
    let payloads: Vec<_> = std::fs::read_dir(payload_path).unwrap().collect();
    assert_eq!(payloads.len(), 1);
    server_task.abort();
}
