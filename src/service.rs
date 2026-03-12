//! Windows service integration.
//!
//! When started with `--service`, the process registers with the Windows
//! Service Control Manager (SCM). SCM stop commands are forwarded to the
//! sensor via a `watch` shutdown channel — the same mechanism used for
//! ctrl-c in foreground mode.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use tracing_subscriber::{fmt, EnvFilter};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::{SensorConfig, SinkType};
use crate::sensor::Sensor;

const SERVICE_NAME: &str = "ThreatFalcon";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Config path passed from main() before the dispatcher takes over.
static CONFIG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Start the Windows service dispatcher. Blocks until the service stops.
pub fn run(config_path: Option<PathBuf>) -> Result<(), windows_service::Error> {
    CONFIG_PATH.set(config_path).ok();
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Tracing may not be initialised yet; best-effort stderr.
        eprintln!("ThreatFalcon service error: {e}");
    }
}

fn run_service() -> Result<()> {
    // Shutdown channel — SCM Stop sends true.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx = Mutex::new(Some(shutdown_tx));

    // Register the service control handler with SCM.
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                if let Ok(mut guard) = shutdown_tx.lock() {
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(true);
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    // Report StartPending while we initialise.
    report_state(&status_handle, ServiceState::StartPending, 0)?;

    // Initialise logging (same style as foreground mode).
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    tracing::info!(
        "ThreatFalcon service v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Load config.
    let config_path = CONFIG_PATH.get().and_then(|p| p.as_deref());
    let config = match SensorConfig::load_from(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to load config");
            let _ = report_state(&status_handle, ServiceState::Stopped, 1);
            return Err(e);
        }
    };

    // Refuse stdout sink in service mode — there is no console.
    if config.output.sink_type == SinkType::Stdout {
        let e = anyhow::anyhow!("stdout sink is not supported in service mode");
        tracing::error!("{e}");
        let _ = report_state(&status_handle, ServiceState::Stopped, 1);
        return Err(e);
    }

    // Create the tokio runtime and run the sensor.
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        let mut sensor = Sensor::new(config)?;

        // Report Running — sensor is about to enter the event loop.
        report_state(&status_handle, ServiceState::Running, 0)
            .map_err(|e| anyhow::anyhow!("failed to report Running: {e}"))?;

        sensor.run(shutdown_rx).await
    });

    // Report Stopped.
    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = report_state(&status_handle, ServiceState::Stopped, exit);

    if let Err(ref e) = result {
        tracing::error!(error = %e, "Sensor exited with error");
    }
    tracing::info!("ThreatFalcon service stopped");

    result
}

fn report_state(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    exit: u32,
) -> Result<(), windows_service::Error> {
    let controls = if state == ServiceState::Running {
        ServiceControlAccept::STOP
    } else {
        ServiceControlAccept::empty()
    };
    handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })
}
