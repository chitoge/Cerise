//! RAII ownership for an interface installed during service network bootstrap.
//!
//! Netstack keeps an installed device, its address, and an optional route only
//! while their corresponding client endpoints remain open.  A service retains
//! the returned [`NetworkBootstrap`] for exactly the time it needs that network
//! configuration; dropping it deliberately tears the configuration down.

#![forbid(unsafe_code)]

/// Policy that is independent of Fuchsia FIDL types.
///
/// The target adapter consumes this together with its Fuchsia configuration. Keeping
/// retry and reuse decisions here lets those decisions be tested on the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapPolicy {
    /// Number of complete bootstrap attempts. Zero is normalized to one attempt.
    pub discovery_attempts: u32,
    /// Delay between unsuccessful complete bootstrap attempts.
    pub retry_delay_seconds: u32,
    /// Whether an existing non-loopback IPv4 interface is reused.
    pub reuse_existing_ipv4: bool,
}

impl BootstrapPolicy {
    pub const fn once() -> Self {
        Self {
            discovery_attempts: 1,
            retry_delay_seconds: 0,
            reuse_existing_ipv4: false,
        }
    }

    pub const fn attempts(self) -> u32 {
        if self.discovery_attempts == 0 {
            1
        } else {
            self.discovery_attempts
        }
    }

    pub const fn retries_after(self, failed_attempt: u32) -> bool {
        failed_attempt + 1 < self.attempts()
    }
}

/// Owns the endpoints that keep a configured interface live.
///
/// `C`, `D`, and `A` are respectively the interface control, device control,
/// and address-state endpoints. `R` is an optional route-set endpoint.  The
/// generic form makes the ownership rule usable with FIDL proxies on target
/// and with drop-observable stand-ins in host tests.
#[must_use = "retain the bootstrap object for as long as the interface is needed"]
pub struct NetworkBootstrap<C, D, A, R = ()> {
    _control: C,
    _device_control: D,
    _address_state_provider: A,
    _default_route: Option<R>,
}

impl<C, D, A> NetworkBootstrap<C, D, A> {
    /// Retains an interface and address without an explicitly owned route.
    pub fn new(control: C, device_control: D, address_state_provider: A) -> Self {
        Self {
            _control: control,
            _device_control: device_control,
            _address_state_provider: address_state_provider,
            _default_route: None,
        }
    }
}

impl<C, D, A, R> NetworkBootstrap<C, D, A, R> {
    /// Retains an interface, address, and an optional default-route endpoint.
    pub fn with_optional_default_route(
        control: C,
        device_control: D,
        address_state_provider: A,
        default_route: Option<R>,
    ) -> Self {
        Self {
            _control: control,
            _device_control: device_control,
            _address_state_provider: address_state_provider,
            _default_route: default_route,
        }
    }

    /// Whether this bootstrap instance owns an explicitly installed route.
    pub fn retains_default_route(&self) -> bool {
        self._default_route.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::{BootstrapPolicy, NetworkBootstrap};
    use std::cell::Cell;
    use std::rc::Rc;

    struct DropCounter(Rc<Cell<u8>>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    fn counter(counter: &Rc<Cell<u8>>) -> DropCounter {
        DropCounter(counter.clone())
    }

    #[test]
    fn dropping_bootstrap_releases_all_interface_owners() {
        let drops = Rc::new(Cell::new(0));
        let bootstrap = NetworkBootstrap::new(counter(&drops), counter(&drops), counter(&drops));
        assert!(!bootstrap.retains_default_route());
        assert_eq!(drops.get(), 0);
        drop(bootstrap);
        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn optional_route_has_the_same_raii_lifetime() {
        let drops = Rc::new(Cell::new(0));
        let bootstrap = NetworkBootstrap::with_optional_default_route(
            counter(&drops),
            counter(&drops),
            counter(&drops),
            Some(counter(&drops)),
        );
        assert!(bootstrap.retains_default_route());
        drop(bootstrap);
        assert_eq!(drops.get(), 4);
    }

    #[test]
    fn policy_normalizes_zero_attempts_and_preserves_retry_envelope() {
        let policy = BootstrapPolicy {
            discovery_attempts: 0,
            retry_delay_seconds: 3,
            reuse_existing_ipv4: true,
        };
        assert_eq!(policy.attempts(), 1);
        assert!(!policy.retries_after(0));
        let retrying = BootstrapPolicy {
            discovery_attempts: 60,
            ..policy
        };
        assert!(retrying.retries_after(58));
        assert!(!retrying.retries_after(59));
        assert!(retrying.reuse_existing_ipv4);
    }

    #[test]
    fn policy_retries_each_failed_full_bootstrap_before_the_last_attempt() {
        let policy = BootstrapPolicy {
            discovery_attempts: 3,
            retry_delay_seconds: 5,
            reuse_existing_ipv4: false,
        };
        assert_eq!(policy.attempts(), 3);
        assert!(policy.retries_after(0));
        assert!(policy.retries_after(1));
        assert!(!policy.retries_after(2));
    }
}
