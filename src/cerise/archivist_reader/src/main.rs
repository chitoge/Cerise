// Cerise Archivist query proof (logging bring-up).
//
// This component proves the structured-log query round-trip end to end against a
// live Archivist:
//
//   1. It emits a known structured record through fuchsia.logger.LogSink (offered
//      from #archivist in the realm). #[fuchsia::main(logging_tags=[...])] wires
//      the diagnostics_log/log backend to that LogSink, so `info!` produces a real
//      structured record — severity=Info, tag=cerise_archivist_probe, a distinctive
//      message NEEDLE — that Archivist ingests via the capability_requested event
//      the realm routes to it.
//
//   2. It connects to fuchsia.diagnostics.ArchiveAccessor (routed out of
//      Archivist's diagnostics-accessors dictionary into this component's namespace)
//      and, using the vendored diagnostics_reader client, snapshots the log store
//      and searches for that record back — asserting it round-trips with the
//      expected severity AND tag (not just any log line).
//
//   3. Only on a real match does it emit the gate marker CERISE-ARCHIVIST-QUERY-OK
//      via zx_debug_write. A mismatch or exhausted retries emit a distinct FAIL
//      marker instead — the OK marker never fires without a real accessor
//      round-trip that returned our record.
use anyhow::{Context, Error};
use diagnostics_reader::{ArchiveReader, RetryConfig, Severity};
use log::info;

/// Distinctive message we log and then look for in the query result. Deliberately
/// not a "CERISE-*" boot marker so a serial grep can't satisfy the gate — the OK
/// marker is only reachable via a real ArchiveAccessor query that returned it.
const NEEDLE: &str = "cerise-archivist-log-needle-7f3a";
/// The logging tag we assert on the retrieved record.
const TAG: &str = "cerise_archivist_probe";
/// Bound the retry loop so a genuinely broken query fails the boot test rather than
/// hanging until the harness timeout. ~40 attempts * 250ms ≈ 10s of propagation slack.
const MAX_ATTEMPTS: u32 = 40;

/// (posix_probe printf acceptance): the needle the plain-C posix_probe
/// printf()s to its elf_runner-installed fd1 socket, which elf_runner drains into
/// the Archivist-backed LogSink. Finding this record via ArchiveAccessor proves
/// the whole stdio -> real-libfdio.so -> fd1 socket -> LogSink -> Archivist path,
/// and is reported as CERISE-POSIX-PROBE-OK. Independent of the QUERY gate above:
/// its absence emits CERISE-POSIX-PROBE-FAIL, never a QUERY marker.
const POSIX_NEEDLE: &str = "cerise-posix-printf-needle-42a7";
/// The probe's moniker (relative to the diagnostics realm root).
const POSIX_MONIKER: &str = "posix_probe";
/// The posix record can lag the reader's own (the probe is a separate eager
/// child): give it a longer window. 120 * 500ms = 60s.
const POSIX_MAX_ATTEMPTS: u32 = 120;

fn marker(s: &str) {
    // Raw serial write: survives even if the diagnostics pipeline degrades.
    unsafe {
        zx::sys::zx_debug_write(s.as_ptr(), s.len());
    }
}

#[fuchsia::main(logging_tags = ["cerise_archivist_probe"])]
async fn main() -> Result<(), Error> {
    marker("CERISE-ARCHIVIST-READER-START\n");

    // (1) Emit the known structured record through LogSink -> Archivist.
    info!(needle = NEEDLE; "archivist query proof: {NEEDLE}");

    // (2) Query it back through ArchiveAccessor. Default connect is to
    // fuchsia.diagnostics.ArchiveAccessor in our namespace (routed from #archivist).
    // Disable the reader's own "retry until non-empty" so each snapshot returns
    // immediately; we own the retry loop below (we retry until OUR needle appears,
    // not merely until any log shows up).
    let mut reader = ArchiveReader::logs();
    reader.retry(RetryConfig::never());

    for attempt in 0..MAX_ATTEMPTS {
        let logs = reader.snapshot().await.context("ArchiveAccessor snapshot")?;
        for record in &logs {
            let msg = record.msg().unwrap_or("");
            if !msg.contains(NEEDLE) {
                continue;
            }
            // Found our record: assert severity AND tag before declaring success.
            let severity_ok = record.severity() == Severity::Info;
            let tag_ok =
                record.tags().map(|tags| tags.iter().any(|t| t == TAG)).unwrap_or(false);
            if severity_ok && tag_ok {
                marker(&format!(
                    "CERISE-ARCHIVIST-QUERY-FOUND moniker={} severity={:?} tags={:?}\n",
                    record.moniker,
                    record.severity(),
                    record.tags(),
                ));
                // (3) The gate marker: a real ArchiveAccessor round-trip returned
                // the exact record we logged, matching severity and tag.
                marker("CERISE-ARCHIVIST-QUERY-OK\n");
                // (4) Independently look for the posix_probe's printf
                // record before exiting; //validation:posix-probe-boot asserts
                // the marker this emits.
                query_posix_printf_record(&mut reader).await;
                return Ok(());
            }
            marker(&format!(
                "CERISE-ARCHIVIST-QUERY-MISMATCH severity={:?} tags={:?}\n",
                record.severity(),
                record.tags(),
            ));
        }
        fuchsia_async::Timer::new(std::time::Duration::from_millis(250)).await;
        if attempt + 1 == MAX_ATTEMPTS {
            marker("CERISE-ARCHIVIST-QUERY-FAIL needle-not-found\n");
        }
    }
    Err(anyhow::anyhow!("archivist query: needle record never retrieved"))
}

/// poll ArchiveAccessor for the plain-C posix_probe's printf record —
/// the line it wrote to fd1 (the elf_runner stdout socket) through musl stdio and
/// the loaded real libfdio.so. Asserts the message content AND that the record's
/// moniker is the probe's (so a lookalike record from another component cannot
/// satisfy the gate). Emits CERISE-POSIX-PROBE-OK / CERISE-POSIX-PROBE-FAIL;
/// deliberately never touches the CERISE-ARCHIVIST-QUERY-* markers.
async fn query_posix_printf_record(reader: &mut ArchiveReader<diagnostics_reader::Logs>) {
    for _ in 0..POSIX_MAX_ATTEMPTS {
        let Ok(logs) = reader.snapshot().await else {
            marker("CERISE-POSIX-PROBE-FAIL reader-snapshot\n");
            return;
        };
        for record in &logs {
            if !record.msg().unwrap_or("").contains(POSIX_NEEDLE) {
                continue;
            }
            if record.moniker.to_string() != POSIX_MONIKER {
                marker(&format!(
                    "CERISE-POSIX-PROBE-FAIL wrong-moniker={}\n",
                    record.moniker
                ));
                return;
            }
            marker(&format!(
                "CERISE-POSIX-PROBE-QUERY-FOUND moniker={} severity={:?}\n",
                record.moniker,
                record.severity(),
            ));
            marker("CERISE-POSIX-PROBE-OK\n");
            return;
        }
        fuchsia_async::Timer::new(std::time::Duration::from_millis(500)).await;
    }
    marker("CERISE-POSIX-PROBE-FAIL printf-record-not-found\n");
}
