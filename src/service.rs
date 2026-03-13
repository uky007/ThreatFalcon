//! Windows service integration.
//!
//! When started with `--service`, the process registers with the Windows
//! Service Control Manager (SCM). SCM stop commands are forwarded to the
//! sensor via a `watch` shutdown channel — the same mechanism used for
//! ctrl-c in foreground mode.
//!
//! `--install-service` and `--uninstall-service` manage the service
//! registration without requiring manual `sc.exe` invocations.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::watch;
use tracing_subscriber::{fmt, EnvFilter};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::{SensorConfig, SinkType};
use crate::sensor::Sensor;

pub const SERVICE_NAME: &str = "ThreatFalcon";
const SERVICE_DISPLAY_NAME: &str = "ThreatFalcon Sensor";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Exit codes matching the foreground `exit_code` module.
mod svc_exit {
    pub const SUCCESS: u32 = 0;
    pub const CONFIG_ERROR: u32 = 1;
    pub const RUNTIME_ERROR: u32 = 2;
}

/// Config path passed from main() before the dispatcher takes over.
static CONFIG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

// ---- Service install / uninstall -------------------------------------------

/// Register ThreatFalcon as a Windows service.
///
/// The service is configured to start automatically (`AutoStart`) and
/// run as `LocalSystem`. If `config_path` is `Some`, `--config <path>`
/// is appended to the service launch arguments so SCM passes it on
/// every start.
pub fn install(config_path: Option<&std::path::Path>) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| anyhow::anyhow!("failed to open Service Control Manager: {e}"))?;

    let exe_path = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("failed to determine executable path: {e}"))?;

    let mut launch_args = vec![OsString::from("--service")];
    if let Some(path) = config_path {
        launch_args.push(OsString::from("--config"));
        launch_args.push(path.as_os_str().to_os_string());
    }

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: launch_args,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    manager
        .create_service(&service_info, ServiceAccess::QUERY_STATUS)
        .map_err(|e| anyhow::anyhow!("failed to create service: {e}"))?;

    Ok(())
}

/// Remove ThreatFalcon from the Windows service registry.
///
/// If the service is currently running, it is stopped first.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| anyhow::anyhow!("failed to open Service Control Manager: {e}"))?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| anyhow::anyhow!("failed to open service '{}': {e}", SERVICE_NAME))?;

    // Stop the service if it's not already stopped, then poll until Stopped.
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            wait_for_stopped(&service)?;
        }
    }

    service
        .delete()
        .map_err(|e| anyhow::anyhow!("failed to delete service: {e}"))?;

    Ok(())
}

/// Poll SCM until the service reaches `Stopped` state, or timeout after 30 seconds.
fn wait_for_stopped(service: &windows_service::service::Service) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let poll_interval = Duration::from_millis(500);

    loop {
        match service.query_status() {
            Ok(status) if status.current_state == ServiceState::Stopped => return Ok(()),
            Ok(_) if Instant::now() >= deadline => {
                return Err(anyhow::anyhow!(
                    "timed out waiting for service to stop (30s)"
                ));
            }
            Ok(_) => std::thread::sleep(poll_interval),
            Err(e) => {
                return Err(anyhow::anyhow!("failed to query service status: {e}"));
            }
        }
    }
}

// ---- Service runtime -------------------------------------------------------

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

    // Shared status handle so the control handler can report StopPending
    // at the moment SCM sends Stop, before the sensor begins its shutdown.
    let shared_handle: std::sync::Arc<Mutex<Option<service_control_handler::ServiceStatusHandle>>> =
        std::sync::Arc::new(Mutex::new(None));
    let handler_handle = shared_handle.clone();

    // Register the service control handler with SCM.
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                // Report StopPending immediately so SCM sees the transition
                // *before* the sensor starts flushing sinks and writing the
                // final health event.
                if let Ok(guard) = handler_handle.lock() {
                    if let Some(ref h) = *guard {
                        let _ = h.set_service_status(ServiceStatus {
                            service_type: SERVICE_TYPE,
                            current_state: ServiceState::StopPending,
                            controls_accepted: ServiceControlAccept::empty(),
                            exit_code: ServiceExitCode::Win32(svc_exit::SUCCESS),
                            checkpoint: 0,
                            wait_hint: Duration::from_secs(15),
                            process_id: None,
                        });
                    }
                }
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

    // Store the handle so the control handler closure can report StopPending.
    if let Ok(mut guard) = shared_handle.lock() {
        *guard = Some(status_handle.clone());
    }

    // Report StartPending while we initialise.
    report_state(&status_handle, ServiceState::StartPending, svc_exit::SUCCESS)?;

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
            let _ = report_state(
                &status_handle,
                ServiceState::Stopped,
                svc_exit::CONFIG_ERROR,
            );
            return Err(e);
        }
    };

    // Refuse stdout sink in service mode — there is no console.
    if config.output.sink_type == SinkType::Stdout {
        let e = anyhow::anyhow!("stdout sink is not supported in service mode");
        tracing::error!("{e}");
        let _ = report_state(
            &status_handle,
            ServiceState::Stopped,
            svc_exit::CONFIG_ERROR,
        );
        return Err(e);
    }

    // Create the tokio runtime and run the sensor.
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        let mut sensor = Sensor::new(config)?;

        // Report Running — sensor is about to enter the event loop.
        report_state(&status_handle, ServiceState::Running, svc_exit::SUCCESS)
            .map_err(|e| anyhow::anyhow!("failed to report Running: {e}"))?;

        sensor.run(shutdown_rx).await
    });

    // StopPending was already reported by the control handler when SCM sent
    // Stop — the sensor has now finished its shutdown (flush, final health).
    // Report Stopped with the appropriate exit code.
    let exit = match &result {
        Ok(()) => svc_exit::SUCCESS,
        Err(_) => svc_exit::RUNTIME_ERROR,
    };
    let _ = report_state(&status_handle, ServiceState::Stopped, exit);

    if let Err(ref e) = result {
        tracing::error!(error = %e, "Sensor exited with error");
    }
    tracing::info!("ThreatFalcon service stopped (exit code {exit})");

    result
}

fn report_state(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    exit: u32,
) -> Result<(), windows_service::Error> {
    let (controls, wait_hint) = match state {
        ServiceState::Running => (
            ServiceControlAccept::STOP,
            Duration::default(),
        ),
        ServiceState::StartPending => (
            ServiceControlAccept::empty(),
            Duration::from_secs(10),
        ),
        ServiceState::StopPending => (
            ServiceControlAccept::empty(),
            Duration::from_secs(15),
        ),
        _ => (
            ServiceControlAccept::empty(),
            Duration::default(),
        ),
    };
    handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })
}
