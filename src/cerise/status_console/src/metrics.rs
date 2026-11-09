//! Memory and CPU sampling for the status panel, via `fuchsia.kernel.Stats`.
//!
//! WHY `fuchsia.kernel.Stats` AND NOT A RESOURCE HANDLE. The two topics the panel
//! needs — `ZX_INFO_KMEM_STATS` and `ZX_INFO_CPU_STATS` — are gated in the kernel on
//! one specific resource: SYSTEM kind at `ZX_RSRC_SYSTEM_INFO_BASE`
//! (zircon/kernel/lib/syscalls/object_info.cc). Userspace can reach that two ways:
//! `fuchsia.kernel.InfoResource`, which hands over the resource HANDLE, or
//! `fuchsia.kernel.Stats`, where component_manager keeps the handle and vends only
//! the decoded numbers. This console takes the second. A handle would let it make
//! every other INFO-gated query too, forever, for the sake of two read-only numbers;
//! the protocol's own FIDL documentation says as much ("Instead of vending out that
//! capability, programs that just want stats should use this service instead").
//!
//! EVERY VALUE HERE IS EITHER REAL OR ABSENT. There is no default, no zero-fill and
//! no last-known-good: if the protocol is not routed, or a call fails, the sample is
//! an `Err` carrying the reason and the panel renders that reason. A status panel
//! showing a plausible wrong number is worse than one that says "unavailable", so
//! the types make the wrong thing impossible rather than merely discouraged.

// The FIDL client half is Fuchsia-only; the arithmetic below is not, and is compiled
// and unit-tested on the HOST by //src/cerise/status_console:metrics_math_test. Same
// split, and the same reason, as the file server's claim.rs: a delta-over-time
// calculation is exactly the kind of thing that should be provable without a boot.
#[cfg(target_os = "fuchsia")]
use anyhow::Context;
use anyhow::{anyhow, Result};
#[cfg(target_os = "fuchsia")]
use fidl_fuchsia_kernel as fkernel;
#[cfg(target_os = "fuchsia")]
use fuchsia_component::client::connect_to_protocol;

/// A memory sample, exactly as the kernel reported it. Bytes.
#[derive(Clone, Copy, Debug)]
pub struct Memory {
    pub total: u64,
    pub free: u64,
    /// The optional breakdown. `None` is "the kernel did not report this", and the panel
    /// draws "-" for it. NOT `0`: these are tables with optional fields, and a zero here
    /// would render as a real measurement of nothing, which is the one thing this panel
    /// must never do.
    pub wired: Option<u64>,
    pub vmo: Option<u64>,
    pub heap_total: Option<u64>,
}

impl Memory {
    /// Everything the kernel is not currently counting as free. Derived, not read:
    /// the kernel reports total and free, and "used" is the difference, so it cannot
    /// disagree with them.
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }

    /// Used as a percentage of total, or `None` when total is zero (which would mean
    /// the kernel told us something impossible — better to show nothing).
    pub fn used_pct(&self) -> Option<u32> {
        if self.total == 0 {
            return None;
        }
        Some(((self.used() as u128 * 100) / self.total as u128) as u32)
    }
}

/// One CPU's cumulative idle time, in nanoseconds since boot.
#[derive(Clone, Debug)]
pub struct CpuSample {
    /// Kernel-reported number of CPUs on the machine, which may exceed
    /// `idle_ns.len()` if the syscall declined to report some of them.
    pub num_cpus: u64,
    pub idle_ns: Vec<i64>,
    /// Monotonic time this sample was taken, nanoseconds.
    pub at_ns: i64,
}

/// Per-core utilisation, derived from two samples.
#[derive(Clone, Debug)]
pub struct CpuUsage {
    pub num_cpus: u64,
    /// One entry per reported core, 0..=100.
    pub per_core_pct: Vec<u32>,
    /// How much idle time advanced across the whole interval, summed over cores.
    /// Zero is IMPOSSIBLE on a live machine with an idle core and is therefore the
    /// signal that a sample is not real; it is reported so callers can refuse it.
    pub idle_delta_ns: i64,
    /// Wall interval between the two samples, nanoseconds.
    pub interval_ns: i64,
}

impl CpuUsage {
    /// Mean utilisation across the reported cores.
    pub fn mean_pct(&self) -> u32 {
        if self.per_core_pct.is_empty() {
            return 0;
        }
        let sum: u64 = self.per_core_pct.iter().map(|p| *p as u64).sum();
        (sum / self.per_core_pct.len() as u64) as u32
    }
}

/// Utilisation between two samples. `None` if the samples are not comparable
/// (different core counts, no time elapsed, or time running backwards) — a
/// utilisation computed from an interval of zero is a divide-by-zero dressed up as
/// a number, and the panel is better off saying it is still measuring.
pub fn utilisation(prev: &CpuSample, now: &CpuSample) -> Option<CpuUsage> {
    let interval_ns = now.at_ns.checked_sub(prev.at_ns)?;
    if interval_ns <= 0 || prev.idle_ns.len() != now.idle_ns.len() || now.idle_ns.is_empty() {
        return None;
    }
    let mut per_core_pct = Vec::with_capacity(now.idle_ns.len());
    let mut idle_delta_ns: i64 = 0;
    for (p, n) in prev.idle_ns.iter().zip(now.idle_ns.iter()) {
        // A core that went offline and back can report idle time going backwards;
        // clamp rather than produce a >100% or negative utilisation.
        let d = n.saturating_sub(*p).clamp(0, interval_ns);
        idle_delta_ns = idle_delta_ns.saturating_add(d);
        let idle_pct = (d as i128 * 100 / interval_ns as i128) as u32;
        per_core_pct.push(100u32.saturating_sub(idle_pct));
    }
    Some(CpuUsage { num_cpus: now.num_cpus, per_core_pct, idle_delta_ns, interval_ns })
}

/// A live connection to the kernel stats provider.
#[cfg(target_os = "fuchsia")]
///
/// Held open across samples rather than reconnected each time: the panel samples on
/// a timer, and a fresh `connect_to_protocol` per tick would turn an unrouted
/// capability into a per-tick namespace lookup for no benefit.
pub struct Stats {
    proxy: fkernel::StatsProxy,
}

#[cfg(target_os = "fuchsia")]
impl Stats {
    /// Connects to `fuchsia.kernel.Stats`. Fails — loudly and with the reason — if
    /// the capability is not routed to this component.
    pub fn connect() -> Result<Stats> {
        let proxy = connect_to_protocol::<fkernel::StatsMarker>()
            .context("connect fuchsia.kernel.Stats")?;
        Ok(Stats { proxy })
    }

    pub async fn memory(&self) -> Result<Memory> {
        let s = self
            .proxy
            .get_memory_stats()
            .await
            .context("fuchsia.kernel.Stats/GetMemoryStats")?;
        // `total_bytes` is the one field with no sensible substitute: without it
        // there is no denominator and every derived figure would be meaningless.
        // An absent field is an error, never a zero.
        let total = s
            .total_bytes
            .ok_or_else(|| anyhow!("kernel reported no total_bytes"))?;
        Ok(Memory {
            total,
            free: s.free_bytes.ok_or_else(|| anyhow!("kernel reported no free_bytes"))?,
            wired: s.wired_bytes,
            vmo: s.vmo_bytes,
            heap_total: s.total_heap_bytes,
        })
    }

    pub async fn cpu(&self) -> Result<CpuSample> {
        let s = self.proxy.get_cpu_stats().await.context("fuchsia.kernel.Stats/GetCpuStats")?;
        let per = s
            .per_cpu_stats
            .ok_or_else(|| anyhow!("kernel reported no per_cpu_stats"))?;
        if per.is_empty() {
            return Err(anyhow!("kernel reported zero CPUs"));
        }
        let idle_ns = per
            .iter()
            .map(|c| c.idle_time.ok_or_else(|| anyhow!("a CPU reported no idle_time")))
            .collect::<Result<Vec<i64>>>()?;
        Ok(CpuSample {
            num_cpus: s.actual_num_cpus,
            idle_ns,
            at_ns: fuchsia_async::MonotonicInstant::now().into_nanos(),
        })
    }
}

/// Formats a byte count as whole MiB. Whole numbers on purpose: the panel is read at
/// arm's length over a KVM link, and a fractional megabyte is noise at that distance.
pub fn mib(bytes: u64) -> u64 {
    bytes / (1 << 20)
}

/// Renders an optional byte count as whole MiB, or "-" when the kernel did not report it.
pub fn mib_opt(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => format!("{} MiB", mib(b)),
        None => "-".to_string(),
    }
}

/// Formats a byte count with a unit chosen so the number stays short. Used for disk
/// sizes, which span megabytes to terabytes.
pub fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;
    let (div, unit) = match bytes {
        b if b >= TIB => (TIB, "TiB"),
        b if b >= GIB => (GIB, "GiB"),
        b if b >= MIB => (MIB, "MiB"),
        b if b >= KIB => (KIB, "KiB"),
        _ => return format!("{bytes} B"),
    };
    // One decimal place, computed in integers to avoid pulling in float formatting
    // for something this small.
    let whole = bytes / div;
    let tenths = (bytes % div) * 10 / div;
    format!("{whole}.{tenths} {unit}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(at_ns: i64, idle: &[i64]) -> CpuSample {
        CpuSample { num_cpus: idle.len() as u64, idle_ns: idle.to_vec(), at_ns }
    }

    #[test]
    fn a_fully_idle_core_reads_zero_percent() {
        let u = utilisation(&sample(0, &[0]), &sample(1_000_000_000, &[1_000_000_000])).unwrap();
        assert_eq!(u.per_core_pct, vec![0]);
        assert_eq!(u.idle_delta_ns, 1_000_000_000);
    }

    #[test]
    fn a_fully_busy_core_reads_one_hundred_percent() {
        let u = utilisation(&sample(0, &[500]), &sample(1_000_000_000, &[500])).unwrap();
        assert_eq!(u.per_core_pct, vec![100]);
        // No idle time advanced at all — the caller can tell this apart from a
        // sample that never happened, because that returns None instead.
        assert_eq!(u.idle_delta_ns, 0);
    }

    #[test]
    fn a_half_idle_core_reads_fifty_percent() {
        let u = utilisation(&sample(0, &[0]), &sample(1_000_000_000, &[500_000_000])).unwrap();
        assert_eq!(u.per_core_pct, vec![50]);
    }

    #[test]
    fn no_elapsed_time_is_not_a_utilisation() {
        assert!(utilisation(&sample(5, &[0]), &sample(5, &[0])).is_none());
        // Time running backwards is likewise refused rather than clamped to
        // something that would render as a real measurement.
        assert!(utilisation(&sample(9, &[0]), &sample(5, &[0])).is_none());
    }

    #[test]
    fn a_changed_core_count_is_not_comparable() {
        assert!(utilisation(&sample(0, &[0]), &sample(1_000, &[0, 0])).is_none());
    }

    #[test]
    fn idle_time_running_backwards_is_clamped_not_negative() {
        let u = utilisation(&sample(0, &[900]), &sample(1_000_000_000, &[100])).unwrap();
        assert_eq!(u.per_core_pct, vec![100]);
    }

    #[test]
    fn idle_advancing_faster_than_wall_time_cannot_exceed_the_scale() {
        // A core reporting more idle nanoseconds than elapsed would otherwise
        // produce a negative utilisation via the subtraction.
        let u = utilisation(&sample(0, &[0]), &sample(1_000, &[10_000])).unwrap();
        assert_eq!(u.per_core_pct, vec![0]);
    }

    #[test]
    fn mean_is_over_the_reported_cores() {
        let u = utilisation(
            &sample(0, &[0, 0]),
            &sample(1_000_000_000, &[1_000_000_000, 0]),
        )
        .unwrap();
        assert_eq!(u.per_core_pct, vec![0, 100]);
        assert_eq!(u.mean_pct(), 50);
    }

    #[test]
    fn used_is_total_minus_free_and_never_underflows() {
        let m = Memory { total: 100, free: 140, wired: None, vmo: None, heap_total: None };
        assert_eq!(m.used(), 0);
        let m = Memory { free: 25, ..m };
        assert_eq!(m.used(), 75);
        assert_eq!(m.used_pct(), Some(75));
    }

    #[test]
    fn a_zero_total_yields_no_percentage_rather_than_a_wrong_one() {
        let m = Memory { total: 0, free: 0, wired: None, vmo: None, heap_total: None };
        assert_eq!(m.used_pct(), None);
    }

    #[test]
    fn human_bytes_picks_a_short_unit() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(256 * (1 << 20)), "256.0 MiB");
        // A 250 GB SATA SSD as found on the cf-sz5 board: 488397168 x 512B.
        assert_eq!(human_bytes(488_397_168 * 512), "232.8 GiB");
    }

    #[test]
    fn an_unreported_breakdown_field_renders_as_a_dash_not_a_zero() {
        assert_eq!(mib_opt(None), "-");
        assert_eq!(mib_opt(Some(0)), "0 MiB");
        assert_eq!(mib_opt(Some(3 << 20)), "3 MiB");
    }

    #[test]
    fn mib_truncates_rather_than_rounds_up() {
        assert_eq!(mib(0), 0);
        assert_eq!(mib((1 << 20) - 1), 0);
        assert_eq!(mib(3 << 20), 3);
    }
}
