// Cerise minimal orderly-shutdown broker.
//
// This is the terminal component-topology broker for Cerise. It runs in-process
// in component_manager as the `builtin_shutdown_shim` runner (see
// src/upstream/fuchsia/src/sys/component_manager/src/builtin/builtin_runner.rs). It
// serves two protocols on its outgoing /svc:
//
//   * fuchsia.hardware.power.statecontrol.Admin — the terminal entry point. Products
//     route it only to a host lifecycle controller which has already quiesced and
//     flushed higher-level state.
//   * fuchsia.system.state.SystemStateTransition — driver_manager's shutdown_manager
//     calls GetTerminationSystemState() during its graceful Stop to learn the target
//     power state before issuing the final platform call.
//
// On a supported Admin request the shim records the termination state and then drives
// component_manager's reverse-dependency-order topology teardown via
// fuchsia.sys2.SystemController.Shutdown(). Because driver_manager `use`s
// SystemStateTransition FROM this shim, the routing graph makes driver_manager a
// dependent of the shim: component_manager stops driver_manager BEFORE the shim, so
// when driver_manager queries GetTerminationSystemState() here the shim is still serving.
//
// This is intentionally minimal versus the upstream shim: no inspect, no syslog, no
// collaborative reboot, no suspend/ActivityGovernor, no config VMO requirement. It
// tolerates a missing config VMO and reports failures rather than acknowledging a
// transition merely because teardown was requested.

use anyhow::{Context, Result};
use fidl::endpoints::ServerEnd;
use fidl_fuchsia_hardware_power_statecontrol::{
    AdminRequest, AdminRequestStream, ShutdownAction,
};
use fidl_fuchsia_io as fio;
use fidl_fuchsia_sys2::SystemControllerMarker;
use fidl_fuchsia_system_state::{
    SystemPowerState, SystemStateTransitionRequest, SystemStateTransitionRequestStream,
};
use fuchsia_component::client::connect_to_protocol_at_dir_root;
use fuchsia_component::directory::AsRefDirectory;
use fuchsia_component::server::ServiceFs;
use futures::prelude::*;
use shutdown_policy::{BeginError, TerminalAction, TerminalTransition};
use std::sync::{Arc, Mutex};

/// Write a marker straight to the kernel debuglog (surfaced on serial) — the same
/// mechanism the Cerise status_console/probes use, with no LogSink dependency.
fn emit(msg: &str) {
    // SAFETY: zx_debug_write takes (ptr,len) of readable bytes; msg is a live &str.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

enum Request {
    Admin(AdminRequestStream),
    SystemStateTransition(SystemStateTransitionRequestStream),
}

pub async fn main(
    svc: impl AsRefDirectory + Clone + 'static,
    directory_request: ServerEnd<fio::DirectoryMarker>,
    _config_vmo: Option<zx::Vmo>,
) -> Result<()> {
    emit("CERISE-SHUTDOWN-SHIM-READY\n");

    // The termination state driver_manager reads at Stop time. A transition is
    // one-shot: accepting a second request could change the terminal action after
    // topology teardown has already begun.
    let transition = Arc::new(Mutex::new(TerminalTransition::default()));

    let mut fs = ServiceFs::new();
    fs.dir("svc")
        .add_fidl_service(Request::Admin)
        .add_fidl_service(Request::SystemStateTransition);
    fs.serve_connection(directory_request)
        .context("shutdown-shim: failed to serve outgoing directory")?;

    fs.for_each_concurrent(None, move |request| {
        let svc = svc.clone();
        let transition = transition.clone();
        async move {
            match request {
                Request::Admin(stream) => handle_admin(stream, svc, transition).await,
                Request::SystemStateTransition(stream) => {
                    handle_system_state_transition(stream, transition).await
                }
            }
        }
    })
    .await;

    Ok(())
}

async fn handle_admin(
    mut stream: AdminRequestStream,
    svc: impl AsRefDirectory,
    transition: Arc<Mutex<TerminalTransition>>,
) {
    while let Ok(Some(request)) = stream.try_next().await {
        match request {
            AdminRequest::Shutdown { options, responder } => {
                let result = match options.action {
                    Some(action) => match terminal_action(action) {
                        Ok(action) => {
                            drive_terminal_transition(&svc, &transition, action).await
                        }
                        Err(status) => Err(status),
                    },
                    None => Err(zx::Status::INVALID_ARGS),
                };
                let _ = responder.send(result.map_err(zx::Status::into_raw));
            }
            AdminRequest::Poweroff { responder } => {
                let result = drive_terminal_transition(
                    &svc,
                    &transition,
                    TerminalAction::Poweroff,
                )
                .await;
                let _ = responder.send(result.map_err(zx::Status::into_raw));
            }
            AdminRequest::PerformReboot { options, responder } => {
                let result =
                    if options.reasons.as_ref().is_some_and(|reasons| !reasons.is_empty()) {
                        drive_terminal_transition(
                            &svc,
                            &transition,
                            TerminalAction::Reboot,
                        )
                        .await
                    } else {
                        Err(zx::Status::INVALID_ARGS)
                    };
                let _ = responder.send(result.map_err(zx::Status::into_raw));
            }
            AdminRequest::RebootToBootloader { responder } => {
                let result = drive_terminal_transition(
                    &svc,
                    &transition,
                    TerminalAction::RebootToBootloader,
                )
                .await;
                let _ = responder.send(result.map_err(zx::Status::into_raw));
            }
            AdminRequest::RebootToRecovery { responder } => {
                let result = drive_terminal_transition(
                    &svc,
                    &transition,
                    TerminalAction::RebootToRecovery,
                )
                .await;
                let _ = responder.send(result.map_err(zx::Status::into_raw));
            }
            AdminRequest::PowerFullyOn { responder } => {
                let _ = responder.send(Err(zx::Status::NOT_SUPPORTED.into_raw()));
            }
            AdminRequest::SuspendToRam { responder } => {
                let _ = responder.send(Err(zx::Status::NOT_SUPPORTED.into_raw()));
            }
            AdminRequest::Mexec { responder, .. } => {
                let _ = responder.send(Err(zx::Status::NOT_SUPPORTED.into_raw()));
            }
        }
    }
}

fn terminal_action(
    action: ShutdownAction,
) -> std::result::Result<TerminalAction, zx::Status> {
    match action {
        ShutdownAction::Poweroff => Ok(TerminalAction::Poweroff),
        ShutdownAction::Reboot => Ok(TerminalAction::Reboot),
        ShutdownAction::RebootToBootloader => Ok(TerminalAction::RebootToBootloader),
        ShutdownAction::RebootToRecovery => Ok(TerminalAction::RebootToRecovery),
        ShutdownAction::__SourceBreaking { .. } => Err(zx::Status::INVALID_ARGS),
    }
}

fn system_power_state(action: TerminalAction) -> SystemPowerState {
    match action {
        TerminalAction::Poweroff => SystemPowerState::Poweroff,
        TerminalAction::Reboot => SystemPowerState::Reboot,
        TerminalAction::RebootToBootloader => SystemPowerState::RebootBootloader,
        TerminalAction::RebootToRecovery => SystemPowerState::RebootRecovery,
    }
}

async fn drive_terminal_transition(
    svc: &impl AsRefDirectory,
    transition: &Arc<Mutex<TerminalTransition>>,
    action: TerminalAction,
) -> std::result::Result<(), zx::Status> {
    let controller =
        connect_to_protocol_at_dir_root::<SystemControllerMarker>(svc).map_err(|e| {
            emit(&format!(
                "CERISE-SHUTDOWN-FAIL: connect fuchsia.sys2.SystemController: {e}\n"
            ));
            zx::Status::INTERNAL
        })?;

    transition
        .lock()
        .unwrap()
        .begin(action)
        .map_err(|BeginError::AlreadyPending| zx::Status::ALREADY_EXISTS)?;
    let power_state = system_power_state(action);
    emit(&format!("CERISE-SHUTDOWN-REQUESTED: {power_state:?}\n"));
    emit("CERISE-SHUTDOWN-TOPOLOGY-BEGIN\n");

    // A successful terminal platform transition removes this process, so this call
    // cannot truthfully return Ok to an in-topology client. Any return means that
    // the machine is still running and must be reported as failure.
    match controller.shutdown().await {
        Ok(()) => {
            emit("CERISE-SHUTDOWN-FAIL: topology shutdown returned while system is running\n");
            Err(zx::Status::INTERNAL)
        }
        Err(e) => {
            emit(&format!(
                "CERISE-SHUTDOWN-FAIL: SystemController.Shutdown: {e}\n"
            ));
            Err(zx::Status::INTERNAL)
        }
    }
}

async fn handle_system_state_transition(
    mut stream: SystemStateTransitionRequestStream,
    transition: Arc<Mutex<TerminalTransition>>,
) {
    while let Ok(Some(request)) = stream.try_next().await {
        match request {
            SystemStateTransitionRequest::GetTerminationSystemState { responder } => {
                let state = transition
                    .lock()
                    .unwrap()
                    .action()
                    .map(system_power_state)
                    .unwrap_or(SystemPowerState::FullyOn);
                let _ = responder.send(state);
            }
            SystemStateTransitionRequest::GetMexecZbis { responder } => {
                let _ = responder.send(Err(zx::Status::NOT_SUPPORTED.into_raw()));
            }
        }
    }
}
