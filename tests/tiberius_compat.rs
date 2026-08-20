use metis_tds::{Config as ServerConfig, server::Server};
use tiberius::{AuthMethod, Config as ClientConfig, EncryptionLevel};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::test]
async fn tiberius_logs_in_and_decodes_a_discovery_result() {
    let mut server_config = ServerConfig::default();
    server_config.listener.address = "127.0.0.1:0".into();
    server_config.telemetry.jsonl_path = None;
    server_config.telemetry.stdout = false;
    server_config.payloads.enabled = false;
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
    client_config.database("master");
    client_config.authentication(AuthMethod::sql_server("scanner", "decoy-password"));
    client_config.encryption(EncryptionLevel::NotSupported);
    let tcp = TcpStream::connect(address).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let mut client = tiberius::Client::connect(client_config, tcp.compat_write())
        .await
        .unwrap();
    let rows = client
        .simple_query("SELECT @@VERSION")
        .await
        .unwrap()
        .into_first_result()
        .await
        .unwrap();
    let version: &str = rows[0].get(0).unwrap();
    assert!(version.starts_with("Microsoft SQL Server 2022"));

    let rpc_rows = client
        .query("SELECT @@SERVERNAME", &[])
        .await
        .unwrap()
        .into_first_result()
        .await
        .unwrap();
    assert_eq!(rpc_rows[0].get::<&str, _>(0), Some("SQL-FIN-01"));
    server_task.abort();
}
