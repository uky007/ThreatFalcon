mod collectors;
mod config;
mod events;
mod output;
mod sensor;

use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    tracing::info!("ThreatFalcon Sensor v{}", env!("CARGO_PKG_VERSION"));

    #[cfg(not(target_os = "windows"))]
    tracing::warn!("ThreatFalcon is designed for Windows — running in development mode");

    let config = config::SensorConfig::load()?;
    let mut sensor = sensor::Sensor::new(config)?;
    sensor.run().await
}
