//! Storage state for the panel, read from the component that decides it.
//!
//! The console does NOT probe block devices. The file server surveys the disk and
//! either opens an Fxfs container that is its own, formats one it can positively
//! prove is blank, or refuses the device; it publishes that verdict over
//! `cerise.storage/Status` and this module renders what it is told. Two components
//! independently deciding what the disk is would give two notions of truth that can
//! disagree, and the console's copy would be the one with no authority behind it.
//!
//! The capability is OPTIONAL. In the app-tier product the file server is a Lazy,
//! package-resolved child that another component is responsible for binding, so the
//! route is deliberately not offered there — connecting would make the console the
//! thing that activates it. An unroutable optional capability surfaces here as an
//! `Err`, and the panel prints the reason instead of inventing a disk.

use anyhow::{anyhow, Context, Result};
use fidl_cerise_storage as fstorage;
use fuchsia_component::client::connect_to_protocol;

use crate::metrics::human_bytes;

/// One surveyed device, as the panel renders it.
///
/// The file server's aggregated-service instance id is deliberately NOT carried here.
/// It is 32 hex digits assigned per boot, is not stable across boots, means nothing to
/// someone reading a screen, and is long enough to push the size and disposition — the
/// parts that matter — off the edge. It is in the file server's own log for anyone
/// correlating; the panel numbers the devices instead.
pub struct Device {
    /// `None` when the device's geometry could not be read at all.
    pub size_bytes: Option<u64>,
    pub disposition: &'static str,
    pub reason: String,
}

impl Device {
    pub fn size_text(&self) -> String {
        match self.size_bytes {
            Some(b) => human_bytes(b),
            None => "unknown".to_string(),
        }
    }
}

/// The file server's storage verdict.
pub struct Report {
    pub state: &'static str,
    /// True when the state is one the operator should look at.
    pub alarming: bool,
    pub devices: Vec<Device>,
    pub reason: String,
    /// Filesystem size and usage. `Some` only when something is really mounted.
    pub usage: Option<(u64, u64)>,
}

impl Report {
    /// Used as a percentage of the filesystem, when there is a filesystem.
    pub fn used_pct(&self) -> Option<u32> {
        let (total, used) = self.usage?;
        if total == 0 {
            return None;
        }
        Some(((used as u128 * 100) / total as u128) as u32)
    }
}

fn disposition_text(d: fstorage::Disposition) -> &'static str {
    match d {
        fstorage::Disposition::Surveyed => "surveyed",
        fstorage::Disposition::Opened => "OPENED",
        fstorage::Disposition::Formatted => "FORMATTED",
        fstorage::Disposition::Refused => "REFUSED",
        fstorage::Disposition::Problem => "PROBLEM",
        _ => "unknown",
    }
}

pub struct Storage {
    proxy: fstorage::StatusProxy,
}

impl Storage {
    pub fn connect() -> Result<Storage> {
        let proxy =
            connect_to_protocol::<fstorage::StatusMarker>().context("connect cerise.storage.Status")?;
        Ok(Storage { proxy })
    }

    pub async fn report(&self) -> Result<Report> {
        let r = self.proxy.get_report().await.context("cerise.storage.Status/GetReport")?;
        let outcome = r.outcome.ok_or_else(|| anyhow!("file server reported no outcome"))?;
        let (state, alarming) = match outcome {
            fstorage::Outcome::Pending => ("waiting for a disk", false),
            fstorage::Outcome::Mounted => ("MOUNTED", false),
            fstorage::Outcome::Refused => ("REFUSED", true),
            fstorage::Outcome::Unavailable => ("UNAVAILABLE", true),
            _ => ("unknown", true),
        };
        let devices = r
            .devices
            .unwrap_or_default()
            .into_iter()
            .map(|d| {
                // Size is present only if BOTH geometry fields are, and neither is zero:
                // a device that reported no block size has no size, and rendering that as
                // "0 B" would read as a real, empty disk.
                let size_bytes = match (d.block_size, d.block_count) {
                    (Some(bs), Some(bc)) if bs != 0 && bc != 0 => bs.checked_mul(bc),
                    _ => None,
                };
                Device {
                    size_bytes,
                    disposition: d.disposition.map(disposition_text).unwrap_or("unknown"),
                    reason: d.reason.unwrap_or_default(),
                }
            })
            .collect();
        // Usage is reported only when BOTH halves are present. Half a measurement is
        // not a measurement.
        let usage = match (r.total_bytes, r.used_bytes) {
            (Some(t), Some(u)) => Some((t, u)),
            _ => None,
        };
        Ok(Report { state, alarming, devices, reason: r.reason.unwrap_or_default(), usage })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_with(usage: Option<(u64, u64)>) -> Report {
        Report {
            state: "MOUNTED",
            alarming: false,
            devices: Vec::new(),
            reason: String::new(),
            usage,
        }
    }

    #[test]
    fn no_usage_means_no_percentage() {
        assert_eq!(report_with(None).used_pct(), None);
        // A zero-byte filesystem cannot yield a meaningful percentage either.
        assert_eq!(report_with(Some((0, 0))).used_pct(), None);
    }

    #[test]
    fn used_percentage_is_of_the_filesystem() {
        assert_eq!(report_with(Some((256, 64))).used_pct(), Some(25));
    }

    #[test]
    fn a_device_with_no_geometry_has_no_size() {
        let d = Device {
            size_bytes: None,
            disposition: "PROBLEM",
            reason: String::new(),
        };
        // "unknown", never "0 B" — a zero would read as a real, empty disk.
        assert_eq!(d.size_text(), "unknown");
    }
}
