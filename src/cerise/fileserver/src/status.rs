//! The file server's single record of what it decided about storage, plus the
//! `cerise.storage/Status` server that publishes it.
//!
//! ONE WRITER, MANY READERS, ONE TRUTH. The mount path (`fs::mount_with_retry` ->
//! `Mount::mount_once`) is the only thing that writes here, and it writes at the
//! exact points it already logs: as each device is surveyed and dispositioned, and
//! once more when the overall outcome is settled. The FIDL server only reads. That
//! is the whole point of the protocol existing — the alternative, letting the
//! status console probe block devices itself, would produce a second opinion about
//! the disk with no authority behind it and no interlock against the writer.
//!
//! WHY IT IS PUBLISHED BEFORE THE ANSWER IS KNOWN. The block device is published
//! ~180s into boot, and a refusal is decided later still. If the server only
//! appeared once the mount resolved, a console that connected earlier would get a
//! channel-closed error and would have to render that as *something* — most likely
//! as "no disk", which is a lie. So the record starts at `PENDING`, the server is
//! up from the start of `run()`, and the console re-polls. "Not decided yet" is a
//! state the protocol can express, so it never has to be guessed.

use std::sync::{Arc, Mutex};

use fidl_cerise_storage as fstorage;
// `fx_futures`, not `futures`: this binary also links @grpc's futures for
// hyper/tonic, and a FIDL RequestStream only implements the FIDL side's Stream
// trait. See the `aliases` note in BUILD.bazel.
use fx_futures::TryStreamExt;

/// What the file server concluded about one block device it surveyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Surveyed,
    Opened,
    Formatted,
    Refused,
    Problem,
}

impl Disposition {
    fn to_fidl(self) -> fstorage::Disposition {
        match self {
            Disposition::Surveyed => fstorage::Disposition::Surveyed,
            Disposition::Opened => fstorage::Disposition::Opened,
            Disposition::Formatted => fstorage::Disposition::Formatted,
            Disposition::Refused => fstorage::Disposition::Refused,
            Disposition::Problem => fstorage::Disposition::Problem,
        }
    }
}

/// One surveyed device, as the panel will render it.
#[derive(Clone, Debug)]
pub struct Device {
    pub instance: String,
    pub block_size: u64,
    pub block_count: u64,
    pub disposition: Disposition,
    pub reason: String,
}

/// A terminal storage outcome, paired with exactly the data that outcome can carry.
/// See `Sink::settle` for why this is an enum and not (outcome, Option<fs>).
pub enum Settled {
    /// A filesystem is mounted; sizes come live from it.
    Mounted(Arc<dyn Usage>),
    /// A device was surveyed and declined, with the reason.
    Refused(String),
    /// No filesystem, for a reason that is not a refusal.
    Unavailable(String),
}

/// The overall storage outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Mounted,
    Refused,
    Unavailable,
}

impl Outcome {
    fn to_fidl(self) -> fstorage::Outcome {
        match self {
            Outcome::Pending => fstorage::Outcome::Pending,
            Outcome::Mounted => fstorage::Outcome::Mounted,
            Outcome::Refused => fstorage::Outcome::Refused,
            Outcome::Unavailable => fstorage::Outcome::Unavailable,
        }
    }
}

/// Something that can report `(total_bytes, used_bytes)` for a live filesystem.
///
/// The status record holds one of these rather than a captured pair of numbers so
/// the console sees CURRENT usage. A snapshot taken at mount time would be correct
/// for about a second and then quietly wrong for the rest of the boot — and a stale
/// number on a status panel is indistinguishable from a fresh one, which makes it
/// worse than no number at all.
pub trait Usage: Send + Sync {
    fn usage(&self) -> (u64, u64);
}

struct Report {
    outcome: Outcome,
    devices: Vec<Device>,
    reason: String,
    /// `None` means "no filesystem", NEVER a zero pair. A zero here would render as
    /// a real 0-byte filesystem, which is exactly the class of plausible-wrong
    /// number this whole change exists to avoid.
    usage: Option<Arc<dyn Usage>>,
}

impl Default for Report {
    fn default() -> Self {
        Report {
            outcome: Outcome::Pending,
            devices: Vec::new(),
            reason: String::new(),
            usage: None,
        }
    }
}

/// A handle to the shared record. Cheap to clone; every clone names the same record.
#[derive(Clone, Default)]
pub struct Sink(Arc<Mutex<Report>>);

impl Sink {
    pub fn new() -> Self {
        Sink::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Report) -> R) -> R {
        // A poisoned lock would mean a previous writer panicked mid-update. There is
        // nothing useful to do about that here and losing the status server would be
        // strictly worse than reporting a possibly-stale record, so recover.
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Starts a fresh mount attempt. The device list describes the LATEST attempt
    /// only — a device that has gone away must not linger on the panel.
    pub fn begin_attempt(&self) {
        self.with(|r| r.devices.clear());
    }

    /// Records one surveyed device and what was decided about it.
    pub fn observe(&self, device: Device) {
        self.with(|r| {
            // Re-surveying the same instance within an attempt replaces the entry
            // rather than duplicating it.
            if let Some(slot) = r.devices.iter_mut().find(|d| d.instance == device.instance) {
                *slot = device;
            } else {
                r.devices.push(device);
            }
        });
    }

    /// Records a device whose geometry could not even be read. There is no size to
    /// report, so the entry exists only to say the file server looked.
    pub fn observe_problem(&self, instance: &str, reason: String) {
        self.observe(Device {
            instance: instance.to_string(),
            block_size: 0,
            block_count: 0,
            disposition: Disposition::Problem,
            reason,
        });
    }

    /// Marks an already-observed device with its final disposition.
    pub fn set_disposition(&self, instance: &str, disposition: Disposition, reason: &str) {
        self.with(|r| {
            if let Some(d) = r.devices.iter_mut().find(|d| d.instance == instance) {
                d.disposition = disposition;
                if !reason.is_empty() {
                    d.reason = reason.to_string();
                }
            }
        });
    }

    /// Settles the overall outcome.
    ///
    /// Takes a `Settled` rather than an outcome plus an optional filesystem so that
    /// "MOUNTED with nothing behind it" — a report that would put a size on the panel
    /// with no filesystem to have measured it — is not a thing this API can express. The
    /// three variants are exactly the three terminal states, and only one of them
    /// carries usage.
    pub fn settle(&self, settled: Settled) {
        let (outcome, reason, usage) = match settled {
            Settled::Mounted(fs) => (Outcome::Mounted, String::new(), Some(fs)),
            Settled::Refused(why) => (Outcome::Refused, why, None),
            Settled::Unavailable(why) => (Outcome::Unavailable, why, None),
        };
        self.with(|r| {
            r.outcome = outcome;
            r.reason = reason;
            r.usage = usage;
        });
    }

    fn snapshot(&self) -> fstorage::Report {
        // Take a reference to the filesystem under the lock, then RELEASE the lock before
        // asking it anything. `Usage::usage` for a real mount reaches into Fxfs's
        // allocator, which takes locks of its own; calling out to foreign code while
        // holding ours is how lock-order bugs are born, and there is no reason to.
        let fs = self.with(|r| r.usage.clone());
        // Read live, on every request — see the `Usage` trait for why this is not a
        // number captured at mount time.
        let usage = fs.map(|u| u.usage());
        self.with(|r| {
            fstorage::Report {
                outcome: Some(r.outcome.to_fidl()),
                // BOUNDED to what the FIDL declares (vector<Device>:8, string:64 for
                // the instance). Exceeding either is an ENCODE failure, which closes the
                // status channel — so a machine with nine disks, or an unusually long
                // instance id, would take the panel's Storage section down rather than
                // showing eight disks. Clamp here, where the bound is visible next to it.
                devices: Some(
                    r.devices
                        .iter()
                        .take(8)
                        .map(|d| fstorage::Device {
                            instance: Some(truncate(&d.instance, 64)),
                            block_size: Some(d.block_size),
                            block_count: Some(d.block_count),
                            disposition: Some(d.disposition.to_fidl()),
                            reason: Some(truncate(&d.reason, 1024)),
                            ..Default::default()
                        })
                        .collect(),
                ),
                reason: Some(truncate(&r.reason, 2048)),
                // Absent, not zero, when there is no filesystem — see `Report::usage`.
                total_bytes: usage.map(|(t, _)| t),
                used_bytes: usage.map(|(_, u)| u),
                ..Default::default()
            }
        })
    }
}

/// Clamps to the FIDL bound, on a char boundary so the result is still valid UTF-8.
/// The reason strings are assembled from device geometry and a fixed set of English
/// sentences, so this should never bite — but a FIDL encode error here would take
/// down the status channel, and a truncated reason is strictly better than no report.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Serves one `cerise.storage/Status` connection.
pub async fn serve(sink: Sink, mut stream: fstorage::StatusRequestStream) {
    loop {
        let next = match stream.try_next().await {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(e) => {
                log::warn!("storage status channel error: {e:?}");
                return;
            }
        };
        let fstorage::StatusRequest::GetReport { responder } = next;
        if let Err(e) = responder.send(&sink.snapshot()) {
            log::warn!("storage status reply failed: {e:?}");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Usage` whose "used" figure moves, to prove the report reads it live.
    struct Moving(std::sync::atomic::AtomicU64);
    impl Usage for Moving {
        fn usage(&self) -> (u64, u64) {
            (
                100,
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            )
        }
    }

    #[test]
    fn usage_is_absent_until_a_filesystem_is_attached() {
        let sink = Sink::new();
        assert_eq!(sink.snapshot().total_bytes, None);
        assert_eq!(sink.snapshot().outcome, Some(fstorage::Outcome::Pending));
        sink.settle(Settled::Mounted(Arc::new(Moving(
            std::sync::atomic::AtomicU64::new(40),
        ))));
        assert_eq!(sink.snapshot().total_bytes, Some(100));
        assert_eq!(sink.snapshot().used_bytes, Some(40));
    }

    #[test]
    fn usage_is_read_live_not_captured_once() {
        let sink = Sink::new();
        sink.settle(Settled::Mounted(Arc::new(Moving(
            std::sync::atomic::AtomicU64::new(7),
        ))));
        assert_eq!(sink.snapshot().used_bytes, Some(7));
        // A second request must re-read the filesystem, not replay the first answer.
        assert_eq!(sink.snapshot().used_bytes, Some(8));
    }

    #[test]
    fn a_refusal_survives_into_the_report() {
        let sink = Sink::new();
        sink.begin_attempt();
        sink.observe(Device {
            instance: "000".into(),
            block_size: 512,
            block_count: 488_397_168,
            disposition: Disposition::Refused,
            reason: "it carries a valid GPT partition table".into(),
        });
        sink.settle(Settled::Refused("declined".into()));
        let snap = sink.snapshot();
        assert_eq!(snap.outcome, Some(fstorage::Outcome::Refused));
        // No usage was measured, so none is reported.
        assert_eq!(snap.total_bytes, None);
        let devices = snap.devices.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].block_count, Some(488_397_168));
        assert_eq!(devices[0].disposition, Some(fstorage::Disposition::Refused));
    }

    #[test]
    fn a_new_attempt_forgets_devices_that_went_away() {
        let sink = Sink::new();
        sink.begin_attempt();
        sink.observe_problem("000", "survey failed".into());
        assert_eq!(sink.snapshot().devices.unwrap().len(), 1);
        sink.begin_attempt();
        assert_eq!(sink.snapshot().devices.unwrap().len(), 0);
    }

    #[test]
    fn re_surveying_one_instance_does_not_duplicate_it() {
        let sink = Sink::new();
        sink.begin_attempt();
        sink.observe_problem("000", "survey failed".into());
        sink.observe(Device {
            instance: "000".into(),
            block_size: 512,
            block_count: 8,
            disposition: Disposition::Surveyed,
            reason: String::new(),
        });
        let devices = sink.snapshot().devices.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].block_count, Some(8));
    }

    #[test]
    fn the_report_is_clamped_to_the_fidl_bounds() {
        let sink = Sink::new();
        sink.begin_attempt();
        // Nine devices and an over-long instance id would both fail to ENCODE and take
        // the status channel down with them.
        for i in 0..9 {
            sink.observe(Device {
                instance: format!("{}{i}", "a".repeat(80)),
                block_size: 512,
                block_count: 8,
                disposition: Disposition::Surveyed,
                reason: String::new(),
            });
        }
        let devices = sink.snapshot().devices.unwrap();
        assert_eq!(devices.len(), 8, "vector<Device>:8");
        for d in &devices {
            assert!(d.instance.as_ref().unwrap().len() <= 64, "string:64");
        }
    }

    #[test]
    fn truncation_keeps_utf8_valid() {
        // A 4-byte char straddling the bound must not be split mid-sequence.
        let s = format!("{}\u{1F600}", "a".repeat(1022));
        let out = truncate(&s, 1024);
        assert_eq!(out.len(), 1022);
        assert!(out.chars().all(|c| c == 'a'));
    }
}
