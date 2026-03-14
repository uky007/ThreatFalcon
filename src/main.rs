mod collectors;
mod config;
mod events;
mod index;
mod investigate;
mod output;
#[allow(dead_code)] // some methods only used by evasion collector on Windows
mod pe;
mod process_cache;
mod sensor;
#[cfg(target_os = "windows")]
mod service;
mod spool;
mod state;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tokio::sync::watch;
use tracing_subscriber::{fmt, EnvFilter};

use config::SensorConfig;

/// Exit codes for structured process lifecycle management.
/// Windows service mode maps these to `ServiceExitCode::Win32`.
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

    /// Run as a Windows service (used by SCM, not for manual invocation)
    #[arg(long, conflicts_with_all = ["stdout", "output"])]
    service: bool,

    /// Install ThreatFalcon as a Windows service and exit
    #[arg(long, conflicts_with_all = ["stdout", "output", "service", "validate_config", "dump_default_config"])]
    install_service: bool,

    /// Uninstall the ThreatFalcon Windows service and exit
    #[arg(long, conflicts_with_all = ["stdout", "output", "service", "validate_config", "dump_default_config", "config"])]
    uninstall_service: bool,

    /// Investigation subcommand (query, explain, bundle)
    #[command(subcommand)]
    command: Option<investigate::Command>,
}

fn main() {
    let cli = Cli::parse();

    // Subcommands (query, explain, bundle) take priority over sensor mode.
    if let Some(command) = cli.command {
        match investigate::run(command) {
            Ok(()) => std::process::exit(exit_code::SUCCESS),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(exit_code::RUNTIME_ERROR);
            }
        }
    }

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

    // --install-service: register with SCM and exit
    if cli.install_service {
        run_install_service(cli.config);
    }

    // --uninstall-service: remove from SCM and exit
    if cli.uninstall_service {
        run_uninstall_service();
    }

    // --service: run as Windows service
    if cli.service {
        run_service_mode(cli.config);
    }

    // Foreground mode — create the async runtime explicitly so that
    // service mode (above) can create its own runtime independently.
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("Failed to create async runtime: {e}");
        std::process::exit(exit_code::RUNTIME_ERROR);
    });

    match rt.block_on(run_foreground(cli)) {
        Ok(()) => std::process::exit(exit_code::SUCCESS),
        Err(e) => {
            tracing::error!(error = %e, "Sensor exited with error");
            std::process::exit(exit_code::RUNTIME_ERROR);
        }
    }
}

/// Dispatch to the Windows service controller. Does not return.
fn run_service_mode(config_path: Option<PathBuf>) -> ! {
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = service::run(config_path) {
            eprintln!("Service error: {e}");
            std::process::exit(exit_code::RUNTIME_ERROR);
        }
        std::process::exit(exit_code::SUCCESS);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = config_path;
        eprintln!("--service is only supported on Windows");
        std::process::exit(exit_code::RUNTIME_ERROR);
    }
}

/// Register ThreatFalcon with the Windows Service Control Manager.
fn run_install_service(config_path: Option<PathBuf>) -> ! {
    #[cfg(target_os = "windows")]
    {
        match service::install(config_path.as_deref()) {
            Ok(()) => {
                eprintln!("Service '{}' installed successfully.", service::SERVICE_NAME);
                if let Some(ref p) = config_path {
                    eprintln!("Config: {}", p.display());
                }
                std::process::exit(exit_code::SUCCESS);
            }
            Err(e) => {
                eprintln!("Failed to install service: {e}");
                std::process::exit(exit_code::RUNTIME_ERROR);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = config_path;
        eprintln!("--install-service is only supported on Windows");
        std::process::exit(exit_code::RUNTIME_ERROR);
    }
}

/// Remove ThreatFalcon from the Windows Service Control Manager.
fn run_uninstall_service() -> ! {
    #[cfg(target_os = "windows")]
    {
        match service::uninstall() {
            Ok(()) => {
                eprintln!("Service '{}' uninstalled successfully.", service::SERVICE_NAME);
                std::process::exit(exit_code::SUCCESS);
            }
            Err(e) => {
                eprintln!("Failed to uninstall service: {e}");
                std::process::exit(exit_code::RUNTIME_ERROR);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("--uninstall-service is only supported on Windows");
        std::process::exit(exit_code::RUNTIME_ERROR);
    }
}

/// Run the sensor as a foreground process with ctrl-c shutdown.
/// Separated from service mode so each entrypoint owns its own runtime
/// and shutdown wiring.
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
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    let mut sensor = sensor::Sensor::new(config)?;
    sensor.run(shutdown_rx).await
}
