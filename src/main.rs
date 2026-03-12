mod collectors;
mod config;
mod events;
mod output;
mod sensor;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tokio::sync::watch;
use tracing_subscriber::{fmt, EnvFilter};

use config::SensorConfig;

/// Exit codes for structured process lifecycle management.
/// A future Windows service wrapper can map these to service-specific status.
mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const CONFIG_ERROR: i32 = 1;
    pub const RUNTIME_ERROR: i32 = 2;
}

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
async fn main() {
    let cli = Cli::parse();

    // --dump-default-config: print and exit (no logging needed)
    if cli.dump_default_config {
        let defaults = SensorConfig::default();
        match toml::to_string_pretty(&defaults) {
            Ok(s) => {
                print!("{s}");
                std::process::exit(exit_code::SUCCESS);
            }
            Err(e) => {
                eprintln!("Failed to serialize default config: {e}");
                std::process::exit(exit_code::RUNTIME_ERROR);
            }
        }
    }

    // --validate-config: load, validate, exit
    if cli.validate_config {
        let config_path = cli.config.as_deref();
        match SensorConfig::load_from(config_path) {
            Ok(_) => {
                eprintln!("Config is valid.");
                std::process::exit(exit_code::SUCCESS);
            }
            Err(e) => {
                eprintln!("Config validation failed: {e}");
                std::process::exit(exit_code::CONFIG_ERROR);
            }
        }
    }

    match run_foreground(cli).await {
        Ok(()) => std::process::exit(exit_code::SUCCESS),
        Err(e) => {
            tracing::error!(error = %e, "Sensor exited with error");
            std::process::exit(exit_code::RUNTIME_ERROR);
        }
    }
}

/// Run the sensor as a foreground process with ctrl-c shutdown.
/// Separated from main() so a future Windows service entrypoint can
/// call `Sensor::run()` directly with its own shutdown signal.
async fn run_foreground(cli: Cli) -> Result<()> {
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

    // Shutdown channel — ctrl_c triggers shutdown for foreground mode.
    // A Windows service entrypoint would create its own channel and
    // signal it from the service control handler instead.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    let mut sensor = sensor::Sensor::new(config)?;
    sensor.run(shutdown_rx).await
}
