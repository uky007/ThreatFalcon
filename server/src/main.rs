use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use threatfalcon_server::app::Server;
use threatfalcon_server::config::{ServerConfig, DEFAULT_CONFIG_PATH};
use threatfalcon_server::{tokens, REVISION, VERSION};

/// ThreatFalcon management server: receives and stores telemetry from
/// ThreatFalcon sensors.
#[derive(Parser)]
#[command(name = "threatfalcon-server", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server
    Serve(ConfigArg),
    /// Validate the config file and exit
    CheckConfig(ConfigArg),
    /// Manage agent tokens
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Args)]
struct ConfigArg {
    /// Config file
    #[arg(
        long,
        short = 'c',
        value_name = "PATH",
        env = "THREATFALCON_SERVER_CONFIG",
        default_value = DEFAULT_CONFIG_PATH
    )]
    config: PathBuf,
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Add an agent and print its new token (shown only once)
    Add {
        /// Agent name: [a-z0-9._-], also used as its storage directory
        name: String,
        #[command(flatten)]
        cfg: ConfigArg,
        /// Print only the token
        #[arg(long)]
        quiet: bool,
    },
    /// Remove an agent (its stored telemetry is kept)
    Remove {
        name: String,
        #[command(flatten)]
        cfg: ConfigArg,
    },
    /// List configured agents
    List {
        #[command(flatten)]
        cfg: ConfigArg,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve(arg) => serve(&arg.config),
        Command::CheckConfig(arg) => check_config(&arg.config),
        Command::Token(cmd) => token(cmd),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn serve(config_path: &Path) -> Result<()> {
    init_logging();
    let config = ServerConfig::load(config_path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start async runtime")?;
    runtime.block_on(async move {
        let server = Server::bind(&config).await?;
        tracing::info!(
            version = VERSION,
            revision = REVISION,
            ingest = %server.ingest_addr()?,
            admin = %server.admin_addr()?,
            data_dir = %config.data_dir.display(),
            agents = config.agents.len(),
            "threatfalcon-server started"
        );
        if config.agents.is_empty() {
            tracing::warn!(
                "no agents configured; add one with `threatfalcon-server token add <name>`"
            );
        }
        if !config.listen.ip().is_loopback() {
            tracing::warn!(
                listen = %config.listen,
                "ingest listener is not on loopback; make sure TLS is terminated in front of it"
            );
        }
        server.run(shutdown_signal()).await?;
        tracing::info!("threatfalcon-server stopped");
        Ok(())
    })
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to install SIGTERM handler; only Ctrl-C will stop the server");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    tracing::info!("shutdown requested; finishing in-flight requests");
}

fn check_config(config_path: &Path) -> Result<()> {
    let config = ServerConfig::load(config_path)?;
    println!("threatfalcon-server {VERSION} (revision {REVISION})");
    println!("config OK: {}", config_path.display());
    println!("  ingest listener: {}", config.listen);
    println!("  admin listener:  {}", config.admin_listen);
    println!("  data directory:  {}", config.data_dir.display());
    println!("  agents:          {}", config.agents.len());
    Ok(())
}

fn token(cmd: TokenCommand) -> Result<()> {
    match cmd {
        TokenCommand::Add { name, cfg, quiet } => {
            let token = tokens::add_agent(&cfg.config, &name)?;
            if quiet {
                println!("{token}");
                return Ok(());
            }
            let url = ServerConfig::load(&cfg.config)
                .ok()
                .and_then(|c| c.public_url)
                .unwrap_or_else(|| "https://<server>/api/v1/events".to_string());
            println!("Added agent \"{name}\" to {}.", cfg.config.display());
            println!();
            println!("Token (shown only once; only its hash is stored on the server):");
            println!();
            println!("  {token}");
            println!();
            println!("Agent configuration (threatfalcon.toml on the endpoint):");
            println!();
            println!("  [output]");
            println!("  type = \"http\"");
            println!("  url = \"{url}\"");
            println!("  bearer_token = \"{token}\"");
            println!("  gzip = true");
            println!("  spool_dir = \"spool\"");
            println!();
            println!("Apply on the server:  sudo systemctl restart threatfalcon-server");
            Ok(())
        }
        TokenCommand::Remove { name, cfg } => {
            tokens::remove_agent(&cfg.config, &name)?;
            println!("Removed agent \"{name}\" from {}.", cfg.config.display());
            println!(
                "Its stored telemetry was kept. Apply:  sudo systemctl restart threatfalcon-server"
            );
            Ok(())
        }
        TokenCommand::List { cfg } => {
            let agents = tokens::list_agents(&cfg.config)?;
            if agents.is_empty() {
                println!("no agents configured");
            }
            for (name, hash_prefix) in agents {
                println!("{name:<32} sha256:{hash_prefix}...");
            }
            Ok(())
        }
    }
}

fn init_logging() {
    use std::io::IsTerminal;
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
}
