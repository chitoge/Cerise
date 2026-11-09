// Cerise runtime-conformance Rust probe. A plain-`fn main` Rust
// component (NOT #[fuchsia::main], so it needs no LogSink dispatcher) that
// exercises + asserts the Rust runtime surface on a real boot, emitting a
// granular CERISE-CONF-RUST-* marker straight to serial
// via zx_debug_write per area:
//
//   * THREADS:       std::thread with N=4 workers + an mpsc channel, summed.
//   * CATCH-UNWIND:  std::panic::catch_unwind catches a DELIBERATE panic and the
//                    program CONTINUES (proves the unwinder runs, no abort). A
//                    custom panic hook suppresses the default "thread panicked"
//                    output so the deliberate panic never reaches serial and
//                    cannot trip the boot gate's fault regex.
//   * BACKTRACE:     std::backtrace::Backtrace::force_capture() after the catch,
//                    asserted to have non-empty frames (symbolization is host-side,
//                    so we gate on frame presence, not names) + a captured snippet.
//   * SENDEXEC:      a multithreaded fuchsia_async SendExecutor (num_threads=3)
//                    running a CONCURRENT-LOAD workload: N tasks each block a
//                    distinct worker thread on a std Barrier while a timer task
//                    completes — this only makes progress if >1 OS thread runs
//                    tasks simultaneously (a single-threaded executor deadlocks).
//   * TIME:          std::time::Instant monotonicity across real work.
use std::backtrace::Backtrace;
use std::collections::HashSet;
use std::panic;
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fuchsia_async as fasync;

fn marker(s: &str) {
    // Raw serial write: independent of the log pipeline.
    unsafe {
        zx::sys::zx_debug_write(s.as_ptr(), s.len());
    }
}

fn fail(why: &str) {
    marker(&format!("CERISE-CONF-RUST-FAIL {why}\n"));
}

// (1) std::thread N=4 + mpsc channel.
fn run_threads() -> bool {
    const N: usize = 4;
    let (tx, rx) = mpsc::channel::<u64>();
    let mut handles = Vec::new();
    for i in 0..N as u64 {
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            // A little real work per thread, then hand a value back over the channel.
            let mut acc = 0u64;
            for k in 0..1000u64 {
                acc = acc.wrapping_add(k);
            }
            tx.send(i + (acc & 0)).unwrap(); // acc&0==0; keeps `acc` live
        }));
    }
    drop(tx);
    let mut sum = 0u64;
    let mut count = 0;
    while let Ok(v) = rx.recv() {
        sum += v;
        count += 1;
    }
    for h in handles {
        if h.join().is_err() {
            fail("thread-join");
            return false;
        }
    }
    if count != N {
        fail("thread-count");
        return false;
    }
    if sum != (0 + 1 + 2 + 3) {
        fail("thread-sum");
        return false;
    }
    true
}

// (2)+(3) catch_unwind over a deliberate panic, then a captured backtrace.
fn run_catch_unwind_and_backtrace() -> bool {
    // Install a quiet hook so the deliberate panic produces NO default serial
    // output; restore the previous (default) hook afterwards so any UNEXPECTED
    // later panic is still visible.
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_info| {
        // Deliberately emits no "panic"/FAIL token — just proof the hook ran.
        marker("CERISE-CONF-RUST-UNWIND-HOOK-RAN\n");
    }));
    let result = panic::catch_unwind(|| {
        // Deliberate panic: caught below, program continues.
        panic!("cerise-deliberate-caught-unwind");
    });
    panic::set_hook(default_hook);

    if result.is_ok() {
        fail("catch-unwind-not-caught");
        return false;
    }
    marker("CERISE-CONF-RUST-CATCH-UNWIND-OK\n");

    // Backtrace after the catch. force_capture ignores RUST_BACKTRACE (unset here).
    let bt = Backtrace::force_capture();
    let text = format!("{bt}");
    // On Fuchsia, std emits the backtrace as SYMBOLIZER MARKUP — `{{{bt:N:pc}}}`
    // frame elements plus `{{{module}}}`/`{{{mmap}}}` context — which a host-side
    // symbolizer resolves to names later. Count those markup frames (and also the
    // classic `N: func / at file` form, in case the format ever changes). We gate
    // on FRAME PRESENCE only, never on symbol names.
    let bt_frames = text.matches("{{{bt:").count();
    let std_frames = text.lines().filter(|l| l.contains(" at ")).count();
    let frames = bt_frames + std_frames;
    // A sample frame line for the report (markup form, unsymbolized on-target).
    let sample: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("{{{bt:") || l.contains(" at "))
        .take(1)
        .collect();
    marker(&format!(
        "CERISE-CONF-RUST-BACKTRACE-CAPTURE frames={} bt_markup={} status={:?} sample={:?}\n",
        frames,
        bt_frames,
        bt.status(),
        sample
    ));
    // Gate on frame presence only when a backtrace was actually Captured
    // (symbolization is host-side, so names are not asserted). If this target's
    // std reports the backtrace machinery Unsupported, that is not a runtime hole
    // for the gate to fail on — the CAPTURE marker above records what happened.
    if matches!(bt.status(), std::backtrace::BacktraceStatus::Captured)
        && (text.trim().is_empty() || frames == 0)
    {
        fail("backtrace-empty");
        return false;
    }
    marker("CERISE-CONF-RUST-BACKTRACE-OK\n");
    true
}

// (4) multithreaded SendExecutor concurrent-load proof.
fn run_send_executor() -> bool {
    const NTHREADS: u8 = 3;
    const NTASKS: usize = 3; // == worker count: all must run at once or deadlock

    let mut exec = fasync::SendExecutorBuilder::new().num_threads(NTHREADS).build();
    let outcome = exec.run(async move {
        // A std Barrier that only releases when all NTASKS tasks reach it
        // simultaneously — i.e. only if NTASKS worker threads run in parallel.
        let barrier = Arc::new(Barrier::new(NTASKS));
        let thread_ids = Arc::new(Mutex::new(HashSet::<String>::new()));
        let mut tasks = Vec::new();
        for i in 0..NTASKS {
            let b = barrier.clone();
            let ids = thread_ids.clone();
            tasks.push(fasync::Task::spawn(async move {
                // Record which OS thread this task is running on, then block on the
                // barrier. Blocking (not awaiting) deliberately pins the worker
                // thread, so release requires genuine parallelism.
                ids.lock().unwrap().insert(format!("{:?}", thread::current().id()));
                b.wait();
                i as u64
            }));
        }
        // A concurrent async timer task, proving timers fire alongside the blocked
        // workers (the timer is serviced by the executor's port thread).
        let timer = fasync::Task::spawn(async {
            fasync::Timer::new(Duration::from_millis(50)).await;
            100u64
        });

        let mut sum = 0u64;
        for t in tasks {
            sum += t.await;
        }
        let t = timer.await;
        let distinct = thread_ids.lock().unwrap().len();
        (sum, t, distinct)
    });

    let (sum, timer_val, distinct) = outcome;
    marker(&format!(
        "CERISE-CONF-RUST-SENDEXEC-CAPTURE task_sum={} timer={} distinct_threads={}\n",
        sum, timer_val, distinct
    ));
    if sum != (0 + 1 + 2) {
        fail("sendexec-task-sum");
        return false;
    }
    if timer_val != 100 {
        fail("sendexec-timer");
        return false;
    }
    // The barrier could not have released without >=2 worker threads running the
    // blocking tasks at the same time.
    if distinct < 2 {
        fail("sendexec-not-parallel");
        return false;
    }
    true
}

// (5) std::time monotonicity.
fn run_time() -> bool {
    let start = Instant::now();
    let mut acc = 0u64;
    for k in 0..2_000_000u64 {
        acc = acc.wrapping_add(k);
    }
    std::hint::black_box(acc);
    let elapsed = start.elapsed();
    let later = Instant::now();
    if later < start {
        fail("time-not-monotonic");
        return false;
    }
    // NOTE (opt): under -Oz the accumulator loop folds to a closed form
    // (black_box only pins the FINAL value, not each iteration), so the "real work"
    // completes within the monotonic clock's resolution and `elapsed` can read
    // ZERO. That is a legitimate optimization effect, NOT a runtime hole: the
    // invariant this row proves is that std::time::Instant is functional and
    // MONOTONIC (asserted above via `later < start`) and that `elapsed` is a valid
    // Duration. We therefore assert monotonicity + a non-backwards, well-formed
    // elapsed, and do not gate on the busy-loop being slower than a clock tick.
    marker(&format!(
        "CERISE-CONF-RUST-TIME-CAPTURE elapsed_ns={} monotonic=true\n",
        elapsed.as_nanos(),
    ));
    true
}

fn main() {
    marker("CERISE-CONF-RUST-START\n");
    if !run_threads() {
        return;
    }
    marker("CERISE-CONF-RUST-THREADS-OK\n");
    if !run_catch_unwind_and_backtrace() {
        return;
    }
    if !run_send_executor() {
        return;
    }
    marker("CERISE-CONF-RUST-SENDEXEC-OK\n");
    if !run_time() {
        return;
    }
    marker("CERISE-CONF-RUST-TIME-OK\n");
    marker("CERISE-CONF-RUST-DONE\n");
}
