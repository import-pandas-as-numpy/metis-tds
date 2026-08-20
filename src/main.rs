use std::{env, process::ExitCode};

use metis_tds::{Config, server::Server};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let result = async {
        let config = parse_config_path()?.map_or_else(|| Ok(Config::default()), Config::load)?;
        Server::new(config).await?.run().await
    }
    .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server terminated");
            ExitCode::FAILURE
        }
    }
}

fn parse_config_path() -> metis_tds::Result<Option<String>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None => Ok(None),
        Some("--config") => {
            let path = args
                .next()
                .ok_or_else(|| metis_tds::Error::Config("--config requires a path".into()))?;
            if args.next().is_some() {
                return Err(metis_tds::Error::Config(
                    "unexpected extra arguments".into(),
                ));
            }
            Ok(Some(path))
        }
        Some("--help" | "-h") => {
            println!("Usage: metis-tds [--config PATH]");
            std::process::exit(0);
        }
        Some(other) => Err(metis_tds::Error::Config(format!(
            "unknown argument {other}"
        ))),
    }
}
