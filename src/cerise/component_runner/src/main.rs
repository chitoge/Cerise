// Component-runner gate: ComponentRunner spawns hello_component as a real process via process_builder.
//
// Architecture (single process, two async tasks on a LocalExecutor):
//   runner task: serves ComponentRunner FIDL; on Start(), spawns hello_component using
//                process_builder with a bootfs-backed fuchsia.ldsvc.Loader service.
//   client task: sends one Start() request, waits for runner-done signal.
//
// ldsvc file VMO source: userboot sends file VMOs via fuchsia.boot.Userboot.PostBootfsFiles
// (PA_USER0) after the dynamic linker finishes loading component_runner.  Files whose bootfs
// VMO pages were decommitted by zx_vmo_transfer_data (ld.so.1, libc.so) are served from this
// VMO cache keyed by bootfs payload offset.  Files whose pages remain intact (libfdio.so) are
// read directly from the bootfs VMO as a fallback.
//
// gate: CERISE-COMPONENT-OK  (printed BY hello_component as a separate process)

use fidl::endpoints::{create_endpoints, create_proxy_and_stream};
use fidl_fuchsia_component_runner::{
    ComponentControllerMarker, ComponentRunnerMarker, ComponentRunnerRequest, ComponentStartInfo,
};
use fidl_fuchsia_data::{Dictionary, DictionaryEntry, DictionaryValue};
use fidl_fuchsia_ldsvc::LoaderRequest;
use fuchsia_async::{LocalExecutor, OnSignals, Task};
use fuchsia_runtime::{HandleInfo, HandleType};
use futures::StreamExt;
use futures::channel::oneshot;
use process_builder::ProcessBuilder;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Arc;
use zx::{MonotonicInstant, ResourceKind, Signals};

extern "C" {
    fn zx_debug_write(buf: *const u8, len: usize) -> i32;
}

fn debug_write(msg: &str) {
    unsafe { zx_debug_write(msg.as_ptr(), msg.len()) };
}

// ZX_RSRC_SYSTEM_VMEX_BASE (zircon/syscalls/resource.h)
const ZX_RSRC_SYSTEM_VMEX_BASE: u64 = 1;

// Bootfs dirent format (zbi-format/internal/bootfs.h)
const ZBI_BOOTFS_MAGIC: u32 = 0xa56d3ff9;

// fuchsia.boot.Userboot.PostBootfsFiles FIDL ordinal (userboot/fidl.h)
const USERBOOT_POST_BOOTFS_FILES_ORDINAL: u64 = 2985117035928536724;

struct BootfsEntry {
    data_off: u64,
    data_len: u64,
}

fn bootfs_find(vmo: &zx::Vmo, path: &str) -> Option<BootfsEntry> {
    let mut header = [0u8; 16];
    vmo.read(&mut header, 0).ok()?;

    let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
    if magic != ZBI_BOOTFS_MAGIC {
        debug_write("[bootfs] bad magic\n");
        return None;
    }
    let dirsize = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;

    let mut dir = vec![0u8; dirsize];
    vmo.read(&mut dir, 16).ok()?;

    let mut offset = 0usize;
    while offset + 12 <= dirsize {
        let name_len = u32::from_le_bytes(dir[offset..offset + 4].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(dir[offset + 4..offset + 8].try_into().unwrap()) as u64;
        let data_off =
            u32::from_le_bytes(dir[offset + 8..offset + 12].try_into().unwrap()) as u64;

        if name_len == 0 {
            break;
        }
        if offset + 12 + name_len > dirsize {
            break;
        }

        // name_len includes the NUL terminator; exclude it for comparison.
        let name_bytes = &dir[offset + 12..offset + 12 + name_len.saturating_sub(1)];
        let name = std::str::from_utf8(name_bytes).unwrap_or("");

        if name == path {
            return Some(BootfsEntry { data_off, data_len });
        }

        let entry_size = (12 + name_len + 3) & !3;
        offset += entry_size;
    }
    None
}

// Read messages from the PA_USER0 (fuchsia.boot.Userboot) channel.
// Loops until it finds PostBootfsFiles (ordinal 2985117035928536724), discarding anything else
// (e.g. PushStashSvc which arrives first).  Returns a map:
//   key:   bootfs payload offset (u32) — the same value as BootfsEntry.data_off
//   value: executable VMO for that file (already replace_as_executable'd by userboot)
//
// Wire format of PostBootfsFiles (hand-encoded by userboot/fidl.h):
//   bytes[ 0..16]: fidl_message_header_t  (txid:u32, flags:[u8;3], magic:u8, ordinal:u64)
//   bytes[16..24]: vector element count (u64)
//   bytes[24..32]: FIDL_ALLOC_PRESENT (0xFFFF…)
//   bytes[32 + i*8 .. 32 + i*8 + 4]: bootfs payload offset for entry i (u32)
//   bytes[32 + i*8 + 4 .. 32 + i*8 + 8]: FIDL_HANDLE_PRESENT placeholder (u32)
//   handles[i]: actual VMO handle (in same order as entries)
fn parse_userboot_files(channel: zx::Channel) -> HashMap<u32, zx::Vmo> {
    loop {
        channel
            .wait_one(Signals::CHANNEL_READABLE, MonotonicInstant::INFINITE)
            .expect("wait for fuchsia.boot.Userboot message");

        let mut msg = zx::MessageBuf::new();
        channel.read(&mut msg).expect("read fuchsia.boot.Userboot message");

        // FIDL ordinal lives at bytes[8..16].
        let ordinal = {
            let b = msg.bytes();
            if b.len() < 16 {
                continue;
            }
            u64::from_le_bytes(b[8..16].try_into().unwrap())
        };

        if ordinal != USERBOOT_POST_BOOTFS_FILES_ORDINAL {
            // Not PostBootfsFiles (e.g. PushStashSvc) — discard and read the next message.
            continue;
        }

        // Parse the vector header.
        let count = {
            let b = msg.bytes();
            if b.len() < 24 {
                debug_write("[runner] PostBootfsFiles: message too short\n");
                return HashMap::new();
            }
            u64::from_le_bytes(b[16..24].try_into().unwrap()) as usize
        };

        if count != msg.n_handles() {
            debug_write(&format!(
                "[runner] PostBootfsFiles: count mismatch: entries={} handles={}\n",
                count,
                msg.n_handles()
            ));
        }

        // Consume the MessageBuf; extract bytes and handles.
        let (bytes_vec, handles) = msg.split();
        let mut map = HashMap::with_capacity(count);

        for (i, nullable) in handles.into_iter().enumerate() {
            let off = 32 + i * 8;
            if off + 4 > bytes_vec.len() {
                break;
            }
            let bootfs_offset = u32::from_le_bytes(bytes_vec[off..off + 4].try_into().unwrap());
            if let Ok(handle) = zx::Handle::try_from(nullable) {
                map.insert(bootfs_offset, zx::Vmo::from(handle));
            }
        }

        debug_write(&format!("[runner] PostBootfsFiles: {} VMOs cached\n", map.len()));
        return map;
    }
}

// Get an executable VMO for `path` inside the bootfs.
//
// Two-level lookup:
//   1. Check the file_vmos cache (offsets from userboot's PostBootfsFiles).
//      Hits: ld.so.1 and other files whose pages were moved out of the bootfs VMO by
//      zx_vmo_transfer_data.  These pages now read as zeros in the bootfs VMO.
//   2. Fall back to reading from the bootfs VMO directly for files that userboot never
//      opened (e.g. lib/libfdio.so) — their pages are still committed.
fn bootfs_get_exec(
    bootfs: &zx::Vmo,
    file_vmos: &HashMap<u32, zx::Vmo>,
    vmex: &zx::Resource,
    path: &str,
) -> Option<zx::Vmo> {
    let entry = bootfs_find(bootfs, path)?;

    // Level 1: check userboot VMO cache (key = bootfs payload offset = entry.data_off).
    if let Some(cached) = file_vmos.get(&(entry.data_off as u32)) {
        debug_write(&format!("[ldsvc] cache hit: {} @ 0x{:x}\n", path, entry.data_off));
        // Duplicate so the cache keeps its handle; caller owns the duplicate.
        return cached.duplicate_handle(zx::Rights::SAME_RIGHTS).ok();
    }

    // Level 2: read bytes from the bootfs VMO (pages still committed for this file).
    debug_write(&format!("[ldsvc] bootfs fallback: {} @ 0x{:x}\n", path, entry.data_off));
    let mut data = vec![0u8; entry.data_len as usize];
    bootfs.read(&mut data, entry.data_off).ok()?;

    // Guard: decommitted pages read as zeros; ELF magic is 0x7f 0x45 0x4c 0x46.
    // If we see zeros here, the file is in the VMO cache but our offset didn't match.
    if data.get(..4) == Some(&[0u8; 4]) {
        debug_write(&format!(
            "[ldsvc] ERROR: {} reads as zeros — offset 0x{:x} not in cache (cache has {} entries)\n",
            path,
            entry.data_off,
            file_vmos.len()
        ));
        return None;
    }

    let vmo = zx::Vmo::create(entry.data_len).ok()?;
    vmo.write(&data, 0).ok()?;
    vmo.replace_as_executable(vmex).ok()
}

// Serve fuchsia.ldsvc.Loader requests, using the two-level VMO lookup above.
async fn serve_ldsvc(
    mut stream: fidl_fuchsia_ldsvc::LoaderRequestStream,
    bootfs: zx::Vmo,
    file_vmos: Arc<HashMap<u32, zx::Vmo>>,
    vmex: zx::Resource,
) {
    while let Some(Ok(req)) = stream.next().await {
        match req {
            LoaderRequest::LoadObject { object_name, responder } => {
                let path = format!("lib/{}", object_name);
                match bootfs_get_exec(&bootfs, &file_vmos, &vmex, &path) {
                    Some(vmo) => {
                        let _ = responder.send(0, Some(vmo));
                    }
                    None => {
                        debug_write(&format!("[ldsvc] NOT_FOUND: {}\n", path));
                        let _ = responder.send(zx::Status::NOT_FOUND.into_raw(), None);
                    }
                }
            }
            LoaderRequest::Config { responder, .. } => {
                let _ = responder.send(0);
            }
            LoaderRequest::Clone { loader, responder } => {
                let bootfs2 = bootfs.duplicate_handle(zx::Rights::SAME_RIGHTS);
                let vmex2 = vmex.duplicate_handle(zx::Rights::SAME_RIGHTS);
                match (bootfs2, vmex2) {
                    (Ok(b), Ok(v)) => {
                        Task::local(serve_ldsvc(
                            loader.into_stream(),
                            b,
                            Arc::clone(&file_vmos),
                            v,
                        ))
                        .detach();
                        let _ = responder.send(0);
                    }
                    _ => {
                        let _ = responder.send(zx::Status::INTERNAL.into_raw());
                    }
                }
            }
            LoaderRequest::Done { .. } => break,
        }
    }
}

async fn spawn_component(
    bootfs: zx::Vmo,
    file_vmos: Arc<HashMap<u32, zx::Vmo>>,
    vdso: zx::Vmo,
    vmex: zx::Resource,
) {
    use fidl_fuchsia_ldsvc::LoaderMarker;

    let exec_vmo = match bootfs_get_exec(&bootfs, &file_vmos, &vmex, "bin/hello_component") {
        Some(v) => v,
        None => {
            debug_write("[runner] ERROR: bin/hello_component not found in bootfs\n");
            return;
        }
    };

    let bootfs_ldsvc = match bootfs.duplicate_handle(zx::Rights::SAME_RIGHTS) {
        Ok(v) => v,
        Err(e) => {
            debug_write(&format!("[runner] ERROR: dup bootfs: {}\n", e));
            return;
        }
    };
    let vmex_ldsvc = match vmex.duplicate_handle(zx::Rights::SAME_RIGHTS) {
        Ok(v) => v,
        Err(e) => {
            debug_write(&format!("[runner] ERROR: dup vmex: {}\n", e));
            return;
        }
    };

    let (ldsvc_client, ldsvc_server) = create_endpoints::<LoaderMarker>();
    Task::local(serve_ldsvc(
        ldsvc_server.into_stream(),
        bootfs_ldsvc,
        Arc::clone(&file_vmos),
        vmex_ldsvc,
    ))
    .detach();

    let job = fuchsia_runtime::job_default();
    let name = CString::new("hello_component").unwrap();
    let mut builder =
        match ProcessBuilder::new(&name, &*job, zx::ProcessOptions::default(), exec_vmo, vdso) {
            Ok(b) => b,
            Err(e) => {
                debug_write(&format!("[runner] ProcessBuilder::new failed: {:?}\n", e));
                return;
            }
        };

    if let Err(e) = builder.set_loader_service(ldsvc_client) {
        debug_write(&format!("[runner] set_loader_service failed: {:?}\n", e));
        return;
    }

    let built = match builder.build().await {
        Ok(b) => b,
        Err(e) => {
            debug_write(&format!("[runner] build failed: {:?}\n", e));
            return;
        }
    };

    let process = match built.start() {
        Ok(p) => p,
        Err(e) => {
            debug_write(&format!("[runner] start failed: {:?}\n", e));
            return;
        }
    };

    debug_write("[runner] hello_component started\n");

    // Wait asynchronously so the ldsvc task keeps serving while the process runs.
    let _ = OnSignals::new(&process, Signals::PROCESS_TERMINATED).await;

    debug_write("[runner] hello_component exited\n");
}

async fn serve_runner(
    mut stream: fidl_fuchsia_component_runner::ComponentRunnerRequestStream,
    done: oneshot::Sender<()>,
    bootfs: zx::Vmo,
    file_vmos: Arc<HashMap<u32, zx::Vmo>>,
    vdso: zx::Vmo,
    vmex: zx::Resource,
) {
    while let Some(Ok(req)) = stream.next().await {
        if let ComponentRunnerRequest::Start { .. } = req {
            debug_write("[runner] ComponentRunner.Start() received\n");
            spawn_component(bootfs, file_vmos, vdso, vmex).await;
            let _ = done.send(());
            return;
        }
    }
}

fn make_start_info() -> ComponentStartInfo {
    ComponentStartInfo {
        resolved_url: Some("cerise://hello_component".to_string()),
        program: Some(Dictionary {
            entries: Some(vec![DictionaryEntry {
                key: "binary".to_string(),
                value: Some(Box::new(DictionaryValue::Str("bin/hello_component".to_string()))),
            }]),
            ..Default::default()
        }),
        ns: Some(vec![]),
        outgoing_dir: None,
        runtime_dir: None,
        numbered_handles: Some(vec![]),
        encoded_config: None,
        break_on_start: None,
        ..Default::default()
    }
}

fn main() {
    // Take startup handles before the executor starts — these are one-shot.
    let bootfs_vmo = zx::Vmo::from(
        fuchsia_runtime::take_startup_handle(HandleInfo::new(HandleType::BootfsVmo, 0))
            .expect("PA_VMO_BOOTFS not available"),
    );
    let vdso_vmo = zx::Vmo::from(
        fuchsia_runtime::take_startup_handle(HandleInfo::new(HandleType::VdsoVmo, 0))
            .expect("PA_VMO_VDSO not available"),
    );
    let sys_resource = zx::Resource::from(
        fuchsia_runtime::take_startup_handle(HandleInfo::new(HandleType::SystemResource, 0))
            .expect("PA_SYSTEM_RESOURCE not available"),
    );
    let vmex = sys_resource
        .create_child(ResourceKind::SYSTEM, None, ZX_RSRC_SYSTEM_VMEX_BASE, 1, b"vmex")
        .expect("create vmex resource");

    // Parse PA_USER0 synchronously before the executor starts: read messages, match by ordinal,
    // extract the PostBootfsFiles VMO cache.  The channel may already have both messages queued
    // (PushStashSvc + PostBootfsFiles) by the time main() runs.
    let file_vmos = Arc::new(
        match fuchsia_runtime::take_startup_handle(HandleInfo::new(HandleType::User0, 0)) {
            Some(h) => {
                debug_write("[runner] got PA_USER0, parsing PostBootfsFiles\n");
                parse_userboot_files(zx::Channel::from(h))
            }
            None => {
                debug_write("[runner] PA_USER0 not available — no VMO cache\n");
                HashMap::new()
            }
        },
    );

    let mut exec = LocalExecutor::default();
    exec.run_singlethreaded(async {
        let (proxy, stream) = create_proxy_and_stream::<ComponentRunnerMarker>();
        let (done_tx, done_rx) = oneshot::channel::<()>();

        Task::local(serve_runner(stream, done_tx, bootfs_vmo, file_vmos, vdso_vmo, vmex))
            .detach();

        let (_ctrl_proxy, ctrl_server) = create_endpoints::<ComponentControllerMarker>();
        proxy.start(make_start_info(), ctrl_server).expect("Start failed");

        let _ = done_rx.await;
    });
}
