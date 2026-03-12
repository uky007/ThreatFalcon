mod collectors;
mod config;
mod events;
mod output;
mod sensor;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use config::SensorConfig;

/// ThreatFalcon — lightweight endpoint telemetry sensor for Windows
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to config file (default: threatfalcon.toml in current directory)
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Force output to stdout (overrides config file)
    #[arg(long)]
    stdout: bool,

    /// Override output file path (overrides config file)
    #[arg(long, value_name = "PATH", conflicts_with = "stdout")]
    output: Option<PathBuf>,

    /// Validate config and exit
    #[arg(long)]
    validate_config: bool,

    /// Dump default config as TOML and exit
    #[arg(long)]
    dump_default_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // --dump-default-config: print and exit (no logging needed)
    if cli.dump_default_config {
        let defaults = SensorConfig::default();
        print!("{}", toml::to_string_pretty(&defaults)?);
        return Ok(());
    }

    // --validate-config: load, validate, exit
    if cli.validate_config {
        let config_path = cli.config.as_deref();
        match SensorConfig::load_from(config_path) {
            Ok(_) => {
                eprintln!("Config is valid.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Config validation failed: {e}");
                std::process::exit(1);
            }
        }
    }

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

    let config_path = cli.config.as_deref();
    let mut config = SensorConfig::load_from(config_path)?;

    // CLI overrides for output
    if cli.stdout {
        config.output.sink_type = config::SinkType::Stdout;
    } else if let Some(path) = cli.output {
        config.output.sink_type = config::SinkType::File;
        config.output.path = path;
    }

    let mut sensor = sensor::Sensor::new(config)?;
    sensor.run().await
}
