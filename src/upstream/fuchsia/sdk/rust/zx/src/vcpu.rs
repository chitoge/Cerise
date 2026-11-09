// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{Guest, NullableHandle, Packet, Status, ok, sys};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Vcpu(NullableHandle);
impl_handle_based!(Vcpu);

impl Vcpu {
    /// Create a VCPU, for use with `guest` that begins execution at `entry`.
    pub fn create(guest: &Guest, entry: usize) -> Result<Vcpu, Status> {
        Self::create_with_options(guest, 0, entry)
    }

    /// Create a VCPU with `options`, for use with `guest` that begins execution
    /// at `entry`.
    pub fn create_with_options(
        guest: &Guest,
        options: u32,
        entry: usize,
    ) -> Result<Vcpu, Status> {
        unsafe {
            let mut vcpu_handle = 0;
            ok(sys::zx_vcpu_create(
                guest.raw_handle(),
                options,
                entry,
                &mut vcpu_handle,
            ))?;
            Ok(Self::from(NullableHandle::from_raw(vcpu_handle)))
        }
    }

    /// Enter a VCPU, causing it to resume execution.
    pub fn enter(&self) -> Result<Packet, Status> {
        let mut packet = Default::default();
        ok(unsafe { sys::zx_vcpu_enter(self.raw_handle(), &mut packet) })?;
        Ok(Packet(packet))
    }

    /// Kick a VCPU, causing it to stop execution.
    pub fn kick(&self) -> Result<(), Status> {
        ok(unsafe { sys::zx_vcpu_kick(self.raw_handle()) })
    }

    /// Raise an interrupt on a VCPU.
    pub fn interrupt(&self, vector: u32) -> Result<(), Status> {
        ok(unsafe { sys::zx_vcpu_interrupt(self.raw_handle(), vector) })
    }

    /// Read the state of a VCPU.
    pub fn read_state(&self) -> Result<sys::zx_vcpu_state_t, Status> {
        let mut state = sys::zx_vcpu_state_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Write the state of a VCPU.
    pub fn write_state(&self, state: &sys::zx_vcpu_state_t) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read the VCPU's complete architectural state (`ZX_VCPU_STATE_FULL`)
    /// into `buf`.
    ///
    /// The blob is self-describing — a `[magic|version|payload_size]` header
    /// followed by the state bytes — so a buffer that is too short is refused
    /// with `Status::BUFFER_TOO_SMALL` rather than truncated. Callers should
    /// size `buf` generously; the kernel's requirement may grow.
    pub fn read_state_full(&self, buf: &mut [u8]) -> Result<(), Status> {
        // SAFETY: the kernel writes at most buf.len() bytes into buf.
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_FULL,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        ok(status)
    }

    /// Write a complete architectural state blob previously produced by
    /// [`Vcpu::read_state_full`] back to the VCPU.
    ///
    /// A blob whose header does not describe state this kernel understands is
    /// refused, so a mismatched producer cannot corrupt a VCPU.
    pub fn write_state_full(&self, buf: &[u8]) -> Result<(), Status> {
        // SAFETY: the kernel reads at most buf.len() bytes from buf.
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_FULL,
                buf.as_ptr(),
                buf.len(),
            )
        };
        ok(status)
    }

    /// Read the VCPU's asynchronous kernel state (`ZX_VCPU_STATE_ASYNC`).
    ///
    /// This captures the local-APIC timer, pending-interrupt set, and
    /// paravirtual-clock mapping. The VCPU must be cooperatively stopped on its
    /// owning thread. The blob is versioned and self-describing.
    pub fn read_state_async(&self, buf: &mut [u8]) -> Result<(), Status> {
        // SAFETY: the kernel writes at most buf.len() bytes into buf.
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_ASYNC,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        ok(status)
    }

    /// Restore a blob produced by [`Vcpu::read_state_async`].
    ///
    /// Restore this after `ZX_VCPU_STATE_FULL` and before the next VCPU entry.
    pub fn write_state_async(&self, buf: &[u8]) -> Result<(), Status> {
        // SAFETY: the kernel reads at most buf.len() bytes from buf.
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_ASYNC,
                buf.as_ptr(),
                buf.len(),
            )
        };
        ok(status)
    }

    /// Read the VCPU's host-assisted debug capabilities and active controls
    /// (`ZX_VCPU_STATE_DEBUG`).
    ///
    /// Capabilities are reported by the active hypervisor rather than inferred
    /// from the CPU model. `ZX_VCPU_DEBUG_SINGLE_STEP` is one-shot and is no
    /// longer active after its guest-exception exit has been returned.
    pub fn read_debug_state(&self) -> Result<sys::zx_vcpu_debug_state_t, Status> {
        let mut state = sys::zx_vcpu_debug_state_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_DEBUG,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Atomically replace the VCPU's active host-assisted debug controls.
    ///
    /// `supported_flags` and `reserved` must be zero on write. Requesting a
    /// known control unavailable on this host returns `Status::NOT_SUPPORTED`
    /// without changing any active control.
    pub fn write_debug_state(
        &self,
        state: &sys::zx_vcpu_debug_state_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_DEBUG,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read the VCPU's host-assisted bounded-run capabilities and active
    /// controls (`ZX_VCPU_STATE_RUN_CONTROL`).
    pub fn read_run_control(&self) -> Result<sys::zx_vcpu_run_control_t, Status> {
        let mut state = sys::zx_vcpu_run_control_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_RUN_CONTROL,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Atomically replace the VCPU's host-assisted bounded-run controls.
    pub fn write_run_control(
        &self,
        state: &sys::zx_vcpu_run_control_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_RUN_CONTROL,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read exact runtime support, active controls, and any pending one-shot
    /// post-handler VM-exit result (`ZX_VCPU_STATE_EXIT_CONTROL`).
    pub fn read_exit_control(&self) -> Result<sys::zx_vcpu_exit_control_t, Status> {
        let mut state = sys::zx_vcpu_exit_control_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_EXIT_CONTROL,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Acknowledge and/or atomically arm a one-shot post-handler VM-exit
    /// observation or completed-exit budget.
    pub fn write_exit_control(
        &self,
        state: &sys::zx_vcpu_exit_control_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_EXIT_CONTROL,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read runtime PMU/resource availability, active state, and any pending
    /// guest-only retired-instruction budget result.
    pub fn read_instruction_control(
        &self,
    ) -> Result<sys::zx_vcpu_instruction_control_t, Status> {
        let mut state = sys::zx_vcpu_instruction_control_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_INSTRUCTION_CONTROL,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Acknowledge and/or atomically arm a one-shot guest-only
    /// retired-instruction budget.
    pub fn write_instruction_control(
        &self,
        state: &sys::zx_vcpu_instruction_control_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_INSTRUCTION_CONTROL,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read guest-global EPT-backed guest-physical access controls and any
    /// pending pre-access result.
    pub fn read_memory_access_control(
        &self,
    ) -> Result<sys::zx_vcpu_memory_access_control_t, Status> {
        let mut state = sys::zx_vcpu_memory_access_control_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Acknowledge and/or atomically replace guest-global guest-physical
    /// access stops.
    pub fn write_memory_access_control(
        &self,
        state: &sys::zx_vcpu_memory_access_control_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read Intel PT capability/status and the currently selected bounded
    /// immutable cursor chunk.
    pub fn read_intel_pt_control(
        &self,
    ) -> Result<sys::zx_vcpu_intel_pt_control_t, Status> {
        let mut state = sys::zx_vcpu_intel_pt_control_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_INTEL_PT_CONTROL,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Configure, select a read, acknowledge, stop, or release a typed Intel
    /// PT session.
    pub fn write_intel_pt_control(
        &self,
        state: &sys::zx_vcpu_intel_pt_control_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_INTEL_PT_CONTROL,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read transparent hardware-breakpoint capability, active requests, and
    /// any pending exact stop.
    pub fn read_hardware_breakpoint_control(
        &self,
    ) -> Result<sys::zx_vcpu_hardware_breakpoint_control_t, Status> {
        let mut state = sys::zx_vcpu_hardware_breakpoint_control_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Acknowledge and/or atomically replace transparent hardware
    /// instruction/data breakpoints.
    pub fn write_hardware_breakpoint_control(
        &self,
        state: &sys::zx_vcpu_hardware_breakpoint_control_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read the VCPU's paravirtual ("enlightenment") surface configuration
    /// (`ZX_VCPU_STATE_ENLIGHTENMENT`).
    ///
    /// Must be called on the thread that created the VCPU.
    pub fn read_enlightenment(&self) -> Result<sys::zx_vcpu_enlightenment_t, Status> {
        let mut state = sys::zx_vcpu_enlightenment_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_ENLIGHTENMENT,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Write the VCPU's paravirtual ("enlightenment") surface configuration.
    ///
    /// A write replaces the configuration in full, and is validated in full
    /// before any of it is applied, so a rejected write leaves the VCPU
    /// unchanged. Must be called on the thread that created the VCPU, and — for
    /// the delegated-exit flags to affect the guest from its first instruction —
    /// before the first [`Vcpu::enter`].
    pub fn write_enlightenment(
        &self,
        state: &sys::zx_vcpu_enlightenment_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_ENLIGHTENMENT,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read the event currently queued for delivery on this VCPU's next entry
    /// (`ZX_VCPU_STATE_PENDING_EVENT`).
    ///
    /// Must be called on the thread that created the VCPU.
    pub fn read_pending_event(&self) -> Result<sys::zx_vcpu_pending_event_t, Status> {
        let mut state = sys::zx_vcpu_pending_event_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_PENDING_EVENT,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Queue an event for delivery on this VCPU's next entry
    /// (`ZX_VCPU_STATE_PENDING_EVENT`), replacing whatever was queued before.
    ///
    /// Writing a `zx_vcpu_pending_event_t` with `type: ZX_VCPU_EVENT_NONE`
    /// cancels a queued event. Nothing is applied unless the whole structure
    /// validates, so a rejected write (`Status::INVALID_ARGS` for a malformed
    /// payload, `Status::BAD_STATE` for an error code claimed while the VCPU
    /// is in real mode) leaves the VCPU exactly as it was.
    ///
    /// Must be called on the thread that created the VCPU: the event is
    /// queued as part of finishing an exit, in order with the register writes
    /// that accompany it. Unlike `Vcpu::interrupt()` and `Vcpu::kick()`, this
    /// cannot be used to poke a running VCPU from another thread.
    pub fn write_pending_event(
        &self,
        state: &sys::zx_vcpu_pending_event_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_PENDING_EVENT,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Read the result of the most recently submitted software xAPIC access
    /// (`ZX_VCPU_STATE_XAPIC_ACCESS`).
    ///
    /// Must be called on the thread that created the VCPU, after
    /// [`Vcpu::write_xapic_access`] and before the next [`Vcpu::enter`].
    pub fn read_xapic_access(&self) -> Result<sys::zx_vcpu_xapic_access_t, Status> {
        let mut state = sys::zx_vcpu_xapic_access_t::default();
        let status = unsafe {
            sys::zx_vcpu_read_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_XAPIC_ACCESS,
                std::ptr::from_mut(&mut state).cast::<u8>(),
                std::mem::size_of_val(&state),
            )
        };
        ok(status).map(|_| state)
    }

    /// Submit one software access to the VCPU's xAPIC MMIO register page
    /// (`ZX_VCPU_STATE_XAPIC_ACCESS`).
    ///
    /// The kernel validates the complete request before accessing the APIC.
    /// Must be called on the thread that created the VCPU, between the MMIO
    /// exit and the next [`Vcpu::enter`].
    pub fn write_xapic_access(
        &self,
        state: &sys::zx_vcpu_xapic_access_t,
    ) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_STATE_XAPIC_ACCESS,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }

    /// Write the result of an IO trap to a VCPU.
    pub fn write_io(&self, state: &sys::zx_vcpu_io_t) -> Result<(), Status> {
        let status = unsafe {
            sys::zx_vcpu_write_state(
                self.raw_handle(),
                sys::ZX_VCPU_IO,
                std::ptr::from_ref(state).cast::<u8>(),
                std::mem::size_of_val(state),
            )
        };
        ok(status)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VcpuContents {
    Interrupt { mask: u64, vector: u8 },
    Startup { id: u64, entry: sys::zx_gpaddr_t },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Resource;
    use fidl_fuchsia_kernel as fkernel;
    use fuchsia_component::client::connect_to_protocol;

    async fn get_hypervisor() -> Resource {
        let resource = connect_to_protocol::<fkernel::HypervisorResourceMarker>()
            .unwrap()
            .get()
            .await
            .unwrap();
        unsafe { Resource::from(NullableHandle::from_raw(resource.into_raw())) }
    }

    #[fuchsia::test]
    async fn vcpu_create() {
        let hypervisor = get_hypervisor().await;
        let (guest, _vmar) = match Guest::create(&hypervisor) {
            Err(Status::NOT_SUPPORTED) => {
                println!("Hypervisor not supported");
                return;
            }
            result => result.unwrap(),
        };
        let _vcpu = Vcpu::create(&guest, 0).unwrap();
    }

    #[fuchsia::test]
    async fn vcpu_interrupt() {
        let hypervisor = get_hypervisor().await;
        let (guest, _vmar) = match Guest::create(&hypervisor) {
            Err(Status::NOT_SUPPORTED) => {
                println!("Hypervisor not supported");
                return;
            }
            result => result.unwrap(),
        };
        let vcpu = Vcpu::create(&guest, 0).unwrap();

        vcpu.interrupt(0).unwrap();
    }

    #[fuchsia::test]
    async fn vcpu_read_write_state() {
        let hypervisor = get_hypervisor().await;
        let (guest, _vmar) = match Guest::create(&hypervisor) {
            Err(Status::NOT_SUPPORTED) => {
                println!("Hypervisor not supported");
                return;
            }
            result => result.unwrap(),
        };
        let vcpu = Vcpu::create(&guest, 0).unwrap();

        let state = vcpu.read_state().unwrap();
        vcpu.write_state(&state).unwrap();
    }
}
