// Copyright 2024 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_camel_case_types)]
#![no_std]

use core::fmt::{self, Debug};
use core::hash::{Hash, Hasher};
use core::sync::atomic::AtomicI32;
#[cfg(feature = "zerocopy")]
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

pub type zx_addr_t = usize;
pub type zx_stream_seek_origin_t = u32;
pub type zx_clock_t = u32;
pub type zx_duration_t = i64;
pub type zx_duration_mono_t = i64;
pub type zx_duration_mono_ticks_t = i64;
pub type zx_duration_boot_t = i64;
pub type zx_duration_boot_ticks_t = i64;
pub type zx_futex_t = AtomicI32;
pub type zx_gpaddr_t = usize;
pub type zx_vcpu_option_t = u32;
pub type zx_guest_trap_t = u32;
pub type zx_handle_t = u32;
pub type zx_handle_op_t = u32;
pub type zx_koid_t = u64;
pub type zx_obj_type_t = u32;
pub type zx_object_info_topic_t = u32;
pub type zx_info_maps_type_t = u32;
pub type zx_instant_boot_t = i64;
pub type zx_instant_boot_ticks_t = i64;
pub type zx_instant_mono_t = i64;
pub type zx_instant_mono_ticks_t = i64;
pub type zx_iob_access_t = u32;
pub type zx_iob_allocate_id_options_t = u32;
pub type zx_iob_discipline_type_t = u64;
pub type zx_iob_region_type_t = u32;
pub type zx_iob_write_options_t = u64;
pub type zx_off_t = u64;
pub type zx_paddr_t = usize;
pub type zx_rights_t = u32;
pub type zx_rsrc_flags_t = u32;
pub type zx_rsrc_kind_t = u32;
pub type zx_signals_t = u32;
pub type zx_ssize_t = isize;
pub type zx_status_t = i32;
pub type zx_rsrc_system_base_t = u64;
pub type zx_ticks_t = i64;
pub type zx_time_t = i64;
pub type zx_txid_t = u32;
pub type zx_vaddr_t = usize;
pub type zx_vm_option_t = u32;
pub type zx_thread_state_topic_t = u32;
pub type zx_vcpu_state_topic_t = u32;
pub type zx_restricted_reason_t = u64;
pub type zx_processor_power_level_options_t = u64;
pub type zx_processor_power_control_t = u64;
pub type zx_system_memory_stall_type_t = u32;
pub type zx_system_suspend_option_t = u64;
pub type zx_system_wake_report_entry_flag_t = u32;

macro_rules! const_assert {
    ($e:expr $(,)?) => {
        const _: [(); 1 - { const ASSERT: bool = $e; ASSERT as usize }] = [];
    };
}
macro_rules! const_assert_eq {
    ($lhs:expr, $rhs:expr $(,)?) => {
        const_assert!($lhs == $rhs);
    };
}

// TODO: magically coerce this to &`static str somehow?
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_string_view_t {
    pub c_str: *const u8, // Guaranteed NUL-terminated valid UTF-8.
    pub length: usize,
}

pub const ZX_MAX_NAME_LEN: usize = 32;

// TODO: combine these macros with the bitflags and assoc consts macros below
// so that we only have to do one macro invocation.
// The result would look something like:
// multiconst!(bitflags, zx_rights_t, Rights, [RIGHT_NONE => ZX_RIGHT_NONE = 0; ...]);
// multiconst!(assoc_consts, zx_status_t, Status, [OK => ZX_OK = 0; ...]);
// Note that the actual name of the inner macro (e.g. `bitflags`) can't be a variable.
// It'll just have to be matched on manually
macro_rules! multiconst {
    ($typename:ident, [$($(#[$attr:meta])* $rawname:ident = $value:expr;)*]) => {
        $(
            $(#[$attr])*
            pub const $rawname: $typename = $value;
        )*
    }
}

multiconst!(zx_handle_t, [
    ZX_HANDLE_INVALID = 0;
    ZX_HANDLE_FIXED_BITS_MASK = 0x3;
]);

multiconst!(zx_handle_op_t, [
    ZX_HANDLE_OP_MOVE = 0;
    ZX_HANDLE_OP_DUPLICATE = 1;
]);

multiconst!(zx_koid_t, [
    ZX_KOID_INVALID = 0;
    ZX_KOID_KERNEL = 1;
    ZX_KOID_FIRST = 1024;
]);

multiconst!(zx_time_t, [
    ZX_TIME_INFINITE = i64::MAX;
    ZX_TIME_INFINITE_PAST = ::core::i64::MIN;
]);

multiconst!(zx_rights_t, [
    ZX_RIGHT_NONE           = 0;
    ZX_RIGHT_DUPLICATE      = 1 << 0;
    ZX_RIGHT_TRANSFER       = 1 << 1;
    ZX_RIGHT_READ           = 1 << 2;
    ZX_RIGHT_WRITE          = 1 << 3;
    ZX_RIGHT_EXECUTE        = 1 << 4;
    ZX_RIGHT_MAP            = 1 << 5;
    ZX_RIGHT_GET_PROPERTY   = 1 << 6;
    ZX_RIGHT_SET_PROPERTY   = 1 << 7;
    ZX_RIGHT_ENUMERATE      = 1 << 8;
    ZX_RIGHT_DESTROY        = 1 << 9;
    ZX_RIGHT_SET_POLICY     = 1 << 10;
    ZX_RIGHT_GET_POLICY     = 1 << 11;
    ZX_RIGHT_SIGNAL         = 1 << 12;
    ZX_RIGHT_SIGNAL_PEER    = 1 << 13;
    ZX_RIGHT_WAIT           = 1 << 14;
    ZX_RIGHT_INSPECT        = 1 << 15;
    ZX_RIGHT_MANAGE_JOB     = 1 << 16;
    ZX_RIGHT_MANAGE_PROCESS = 1 << 17;
    ZX_RIGHT_MANAGE_THREAD  = 1 << 18;
    ZX_RIGHT_APPLY_PROFILE  = 1 << 19;
    ZX_RIGHT_MANAGE_SOCKET  = 1 << 20;
    ZX_RIGHT_OP_CHILDREN    = 1 << 21;
    ZX_RIGHT_RESIZE         = 1 << 22;
    ZX_RIGHT_ATTACH_VMO     = 1 << 23;
    ZX_RIGHT_MANAGE_VMO     = 1 << 24;
    ZX_RIGHT_SAME_RIGHTS    = 1 << 31;
]);

multiconst!(u32, [
    ZX_VMO_RESIZABLE = 1 << 1;
    ZX_VMO_DISCARDABLE = 1 << 2;
    ZX_VMO_TRAP_DIRTY = 1 << 3;
    ZX_VMO_UNBOUNDED = 1 << 4;
]);

multiconst!(u64, [
    ZX_VMO_DIRTY_RANGE_IS_ZERO = 1;
]);

multiconst!(u32, [
    ZX_INFO_VMO_TYPE_PAGED = 1 << 0;
    ZX_INFO_VMO_RESIZABLE = 1 << 1;
    ZX_INFO_VMO_IS_COW_CLONE = 1 << 2;
    ZX_INFO_VMO_VIA_HANDLE = 1 << 3;
    ZX_INFO_VMO_VIA_MAPPING = 1 << 4;
    ZX_INFO_VMO_PAGER_BACKED = 1 << 5;
    ZX_INFO_VMO_CONTIGUOUS = 1 << 6;
    ZX_INFO_VMO_DISCARDABLE = 1 << 7;
    ZX_INFO_VMO_IMMUTABLE = 1 << 8;
    ZX_INFO_VMO_VIA_IOB_HANDLE = 1 << 9;
]);

multiconst!(u32, [
    ZX_VMO_OP_COMMIT = 1;
    ZX_VMO_OP_DECOMMIT = 2;
    ZX_VMO_OP_LOCK = 3;
    ZX_VMO_OP_UNLOCK = 4;
    ZX_VMO_OP_CACHE_SYNC = 6;
    ZX_VMO_OP_CACHE_INVALIDATE = 7;
    ZX_VMO_OP_CACHE_CLEAN = 8;
    ZX_VMO_OP_CACHE_CLEAN_INVALIDATE = 9;
    ZX_VMO_OP_ZERO = 10;
    ZX_VMO_OP_TRY_LOCK = 11;
    ZX_VMO_OP_DONT_NEED = 12;
    ZX_VMO_OP_ALWAYS_NEED = 13;
    ZX_VMO_OP_PREFETCH = 14;
    // Cerise: revert a copy-on-write child to its parent's baseline content.
    ZX_VMO_OP_REVERT_TO_SNAPSHOT = 15;
    // Cerise: query the pages a copy-on-write child has forked (1 bit/page).
    ZX_VMO_OP_QUERY_DIRTY = 16;
]);

multiconst!(u32, [
    ZX_VMAR_OP_COMMIT = 1;
    ZX_VMAR_OP_DECOMMIT = 2;
    ZX_VMAR_OP_MAP_RANGE = 3;
    ZX_VMAR_OP_ZERO = 10;
    ZX_VMAR_OP_DONT_NEED = 12;
    ZX_VMAR_OP_ALWAYS_NEED = 13;
    ZX_VMAR_OP_PREFETCH = 14;
]);

multiconst!(zx_vm_option_t, [
    ZX_VM_PERM_READ                    = 1 << 0;
    ZX_VM_PERM_WRITE                   = 1 << 1;
    ZX_VM_PERM_EXECUTE                 = 1 << 2;
    ZX_VM_COMPACT                      = 1 << 3;
    ZX_VM_SPECIFIC                     = 1 << 4;
    ZX_VM_SPECIFIC_OVERWRITE           = 1 << 5;
    ZX_VM_CAN_MAP_SPECIFIC             = 1 << 6;
    ZX_VM_CAN_MAP_READ                 = 1 << 7;
    ZX_VM_CAN_MAP_WRITE                = 1 << 8;
    ZX_VM_CAN_MAP_EXECUTE              = 1 << 9;
    ZX_VM_MAP_RANGE                    = 1 << 10;
    ZX_VM_REQUIRE_NON_RESIZABLE        = 1 << 11;
    ZX_VM_ALLOW_FAULTS                 = 1 << 12;
    ZX_VM_OFFSET_IS_UPPER_LIMIT        = 1 << 13;
    ZX_VM_PERM_READ_IF_XOM_UNSUPPORTED = 1 << 14;
    ZX_VM_FAULT_BEYOND_STREAM_SIZE     = 1 << 15;

    // VM alignment options
    ZX_VM_ALIGN_BASE                   = 24;
    ZX_VM_ALIGN_1KB                    = 10 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_2KB                    = 11 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_4KB                    = 12 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_8KB                    = 13 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_16KB                   = 14 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_32KB                   = 15 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_64KB                   = 16 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_128KB                  = 17 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_256KB                  = 18 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_512KB                  = 19 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_1MB                    = 20 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_2MB                    = 21 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_4MB                    = 22 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_8MB                    = 23 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_16MB                   = 24 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_32MB                   = 25 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_64MB                   = 26 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_128MB                  = 27 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_256MB                  = 28 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_512MB                  = 29 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_1GB                    = 30 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_2GB                    = 31 << ZX_VM_ALIGN_BASE;
    ZX_VM_ALIGN_4GB                    = 32 << ZX_VM_ALIGN_BASE;
]);

multiconst!(u32, [
    ZX_PROCESS_SHARED = 1 << 0;
]);

multiconst!(u32, [
    ZX_SYSTEM_BARRIER_DATA_MEMORY = 0;
]);

// LINT.IfChange(zx_status_t)
// matches ///zircon/system/public/zircon/errors.h
multiconst!(zx_status_t, [
    /// Indicates an operation was successful.
    ZX_OK                         = 0;
    /// The system encountered an otherwise unspecified error while performing the
    /// operation.
    ZX_ERR_INTERNAL               = -1;
    /// The operation is not implemented, supported, or enabled.
    ZX_ERR_NOT_SUPPORTED          = -2;
    /// The system was not able to allocate some resource needed for the operation.
    ZX_ERR_NO_RESOURCES           = -3;
    /// The system was not able to allocate memory needed for the operation.
    ZX_ERR_NO_MEMORY              = -4;
    /// The system call was interrupted, but should be retried. This should not be
    /// seen outside of the VDSO.
    ZX_ERR_INTERRUPTED_RETRY      = -6;
    /// An argument is invalid. For example, a null pointer when a null pointer is
    /// not permitted.
    ZX_ERR_INVALID_ARGS           = -10;
    /// A specified handle value does not refer to a handle.
    ZX_ERR_BAD_HANDLE             = -11;
    /// The subject of the operation is the wrong type to perform the operation.
    ///
    /// For example: Attempting a message_read on a thread handle.
    ZX_ERR_WRONG_TYPE             = -12;
    /// The specified syscall number is invalid.
    ZX_ERR_BAD_SYSCALL            = -13;
    /// An argument is outside the valid range for this operation.
    ZX_ERR_OUT_OF_RANGE           = -14;
    /// The caller-provided buffer is too small for this operation.
    ZX_ERR_BUFFER_TOO_SMALL       = -15;
    /// The operation failed because the current state of the object does not allow
    /// it, or a precondition of the operation is not satisfied.
    ZX_ERR_BAD_STATE              = -20;
    /// The time limit for the operation elapsed before the operation completed.
    ZX_ERR_TIMED_OUT              = -21;
    /// The operation cannot be performed currently but potentially could succeed if
    /// the caller waits for a prerequisite to be satisfied, like waiting for a
    /// handle to be readable or writable.
    ///
    /// Example: Attempting to read from a channel that has no messages waiting but
    /// has an open remote will return `ZX_ERR_SHOULD_WAIT`. In contrast, attempting
    /// to read from a channel that has no messages waiting and has a closed remote
    /// end will return `ZX_ERR_PEER_CLOSED`.
    ZX_ERR_SHOULD_WAIT            = -22;
    /// The in-progress operation, for example, a wait, has been canceled.
    ZX_ERR_CANCELED               = -23;
    /// The operation failed because the remote end of the subject of the operation
    /// was closed.
    ZX_ERR_PEER_CLOSED            = -24;
    /// The requested entity is not found.
    ZX_ERR_NOT_FOUND              = -25;
    /// An object with the specified identifier already exists.
    ///
    /// Example: Attempting to create a file when a file already exists with that
    /// name.
    ZX_ERR_ALREADY_EXISTS         = -26;
    /// The operation failed because the named entity is already owned or controlled
    /// by another entity. The operation could succeed later if the current owner
    /// releases the entity.
    ZX_ERR_ALREADY_BOUND          = -27;
    /// The subject of the operation is currently unable to perform the operation.
    ///
    /// This is used when there's no direct way for the caller to observe when the
    /// subject will be able to perform the operation and should thus retry.
    ZX_ERR_UNAVAILABLE            = -28;
    /// The caller did not have permission to perform the specified operation.
    ZX_ERR_ACCESS_DENIED          = -30;
    /// Otherwise-unspecified error occurred during I/O.
    ZX_ERR_IO                     = -40;
    /// The entity the I/O operation is being performed on rejected the operation.
    ///
    /// Example: an I2C device NAK'ing a transaction or a disk controller rejecting
    /// an invalid command, or a stalled USB endpoint.
    ZX_ERR_IO_REFUSED             = -41;
    /// The data in the operation failed an integrity check and is possibly
    /// corrupted.
    ///
    /// Example: CRC or Parity error.
    ZX_ERR_IO_DATA_INTEGRITY      = -42;
    /// The data in the operation is currently unavailable and may be permanently
    /// lost.
    ///
    /// Example: A disk block is irrecoverably damaged.
    ZX_ERR_IO_DATA_LOSS           = -43;
    /// The device is no longer available (has been unplugged from the system,
    /// powered down, or the driver has been unloaded).
    ZX_ERR_IO_NOT_PRESENT         = -44;
    /// More data was received from the device than expected.
    ///
    /// Example: a USB "babble" error due to a device sending more data than the
    /// host queued to receive.
    ZX_ERR_IO_OVERRUN             = -45;
    /// An operation did not complete within the required timeframe.
    ///
    /// Example: A USB isochronous transfer that failed to complete due to an
    /// overrun or underrun.
    ZX_ERR_IO_MISSED_DEADLINE     = -46;
    /// The data in the operation is invalid parameter or is out of range.
    ///
    /// Example: A USB transfer that failed to complete with TRB Error
    ZX_ERR_IO_INVALID             = -47;
    /// Path name is too long.
    ZX_ERR_BAD_PATH               = -50;
    /// The object is not a directory or does not support directory operations.
    ///
    /// Example: Attempted to open a file as a directory or attempted to do
    /// directory operations on a file.
    ZX_ERR_NOT_DIR                = -51;
    /// Object is not a regular file.
    ZX_ERR_NOT_FILE               = -52;
    /// This operation would cause a file to exceed a filesystem-specific size
    /// limit.
    ZX_ERR_FILE_BIG               = -53;
    /// The filesystem or device space is exhausted.
    ZX_ERR_NO_SPACE               = -54;
    /// The directory is not empty for an operation that requires it to be empty.
    ///
    /// For example, non-recursively deleting a directory with files still in it.
    ZX_ERR_NOT_EMPTY              = -55;
    /// An indicate to not call again.
    ///
    /// The flow control values `ZX_ERR_STOP`, `ZX_ERR_NEXT`, and `ZX_ERR_ASYNC` are
    /// not errors and will never be returned by a system call or public API. They
    /// allow callbacks to request their caller perform some other operation.
    ///
    /// For example, a callback might be called on every event until it returns
    /// something other than `ZX_OK`. This status allows differentiation between
    /// "stop due to an error" and "stop because work is done."
    ZX_ERR_STOP                   = -60;
    /// Advance to the next item.
    ///
    /// The flow control values `ZX_ERR_STOP`, `ZX_ERR_NEXT`, and `ZX_ERR_ASYNC` are
    /// not errors and will never be returned by a system call or public API. They
    /// allow callbacks to request their caller perform some other operation.
    ///
    /// For example, a callback could use this value to indicate it did not consume
    /// an item passed to it, but by choice, not due to an error condition.
    ZX_ERR_NEXT                   = -61;
    /// Ownership of the item has moved to an asynchronous worker.
    ///
    /// The flow control values `ZX_ERR_STOP`, `ZX_ERR_NEXT`, and `ZX_ERR_ASYNC` are
    /// not errors and will never be returned by a system call or public API. They
    /// allow callbacks to request their caller perform some other operation.
    ///
    /// Unlike `ZX_ERR_STOP`, which implies that iteration on an object
    /// should stop, and `ZX_ERR_NEXT`, which implies that iteration
    /// should continue to the next item, `ZX_ERR_ASYNC` implies
    /// that an asynchronous worker is responsible for continuing iteration.
    ///
    /// For example, a callback will be called on every event, but one event needs
    /// to handle some work asynchronously before it can continue. `ZX_ERR_ASYNC`
    /// implies the worker is responsible for resuming iteration once its work has
    /// completed.
    ZX_ERR_ASYNC                  = -62;
    /// The specified protocol is not supported.
    ZX_ERR_PROTOCOL_NOT_SUPPORTED = -70;
    /// The host is unreachable.
    ZX_ERR_ADDRESS_UNREACHABLE    = -71;
    /// Address is being used by someone else.
    ZX_ERR_ADDRESS_IN_USE         = -72;
    /// The socket is not connected.
    ZX_ERR_NOT_CONNECTED          = -73;
    /// The remote peer rejected the connection.
    ZX_ERR_CONNECTION_REFUSED     = -74;
    /// The connection was reset.
    ZX_ERR_CONNECTION_RESET       = -75;
    /// The connection was aborted.
    ZX_ERR_CONNECTION_ABORTED     = -76;
]);
// LINT.ThenChange(//zircon/vdso/errors.fidl)

multiconst!(zx_signals_t, [
    ZX_SIGNAL_NONE              = 0;
    ZX_OBJECT_SIGNAL_ALL        = 0x00ffffff;
    ZX_USER_SIGNAL_ALL          = 0xff000000;
    ZX_OBJECT_SIGNAL_0          = 1 << 0;
    ZX_OBJECT_SIGNAL_1          = 1 << 1;
    ZX_OBJECT_SIGNAL_2          = 1 << 2;
    ZX_OBJECT_SIGNAL_3          = 1 << 3;
    ZX_OBJECT_SIGNAL_4          = 1 << 4;
    ZX_OBJECT_SIGNAL_5          = 1 << 5;
    ZX_OBJECT_SIGNAL_6          = 1 << 6;
    ZX_OBJECT_SIGNAL_7          = 1 << 7;
    ZX_OBJECT_SIGNAL_8          = 1 << 8;
    ZX_OBJECT_SIGNAL_9          = 1 << 9;
    ZX_OBJECT_SIGNAL_10         = 1 << 10;
    ZX_OBJECT_SIGNAL_11         = 1 << 11;
    ZX_OBJECT_SIGNAL_12         = 1 << 12;
    ZX_OBJECT_SIGNAL_13         = 1 << 13;
    ZX_OBJECT_SIGNAL_14         = 1 << 14;
    ZX_OBJECT_SIGNAL_15         = 1 << 15;
    ZX_OBJECT_SIGNAL_16         = 1 << 16;
    ZX_OBJECT_SIGNAL_17         = 1 << 17;
    ZX_OBJECT_SIGNAL_18         = 1 << 18;
    ZX_OBJECT_SIGNAL_19         = 1 << 19;
    ZX_OBJECT_SIGNAL_20         = 1 << 20;
    ZX_OBJECT_SIGNAL_21         = 1 << 21;
    ZX_OBJECT_SIGNAL_22         = 1 << 22;
    ZX_OBJECT_HANDLE_CLOSED     = 1 << 23;
    ZX_USER_SIGNAL_0            = 1 << 24;
    ZX_USER_SIGNAL_1            = 1 << 25;
    ZX_USER_SIGNAL_2            = 1 << 26;
    ZX_USER_SIGNAL_3            = 1 << 27;
    ZX_USER_SIGNAL_4            = 1 << 28;
    ZX_USER_SIGNAL_5            = 1 << 29;
    ZX_USER_SIGNAL_6            = 1 << 30;
    ZX_USER_SIGNAL_7            = 1 << 31;

    ZX_OBJECT_READABLE          = ZX_OBJECT_SIGNAL_0;
    ZX_OBJECT_WRITABLE          = ZX_OBJECT_SIGNAL_1;
    ZX_OBJECT_PEER_CLOSED       = ZX_OBJECT_SIGNAL_2;

    // Cancelation (handle was closed while waiting with it)
    ZX_SIGNAL_HANDLE_CLOSED     = ZX_OBJECT_HANDLE_CLOSED;

    // Event
    ZX_EVENT_SIGNALED           = ZX_OBJECT_SIGNAL_3;

    // EventPair
    ZX_EVENTPAIR_SIGNALED       = ZX_OBJECT_SIGNAL_3;
    ZX_EVENTPAIR_PEER_CLOSED    = ZX_OBJECT_SIGNAL_2;

    // Task signals (process, thread, job)
    ZX_TASK_TERMINATED          = ZX_OBJECT_SIGNAL_3;

    // Channel
    ZX_CHANNEL_READABLE         = ZX_OBJECT_SIGNAL_0;
    ZX_CHANNEL_WRITABLE         = ZX_OBJECT_SIGNAL_1;
    ZX_CHANNEL_PEER_CLOSED      = ZX_OBJECT_SIGNAL_2;

    // Clock
    ZX_CLOCK_STARTED            = ZX_OBJECT_SIGNAL_4;
    ZX_CLOCK_UPDATED            = ZX_OBJECT_SIGNAL_5;

    // Socket
    ZX_SOCKET_READABLE            = ZX_OBJECT_READABLE;
    ZX_SOCKET_WRITABLE            = ZX_OBJECT_WRITABLE;
    ZX_SOCKET_PEER_CLOSED         = ZX_OBJECT_PEER_CLOSED;
    ZX_SOCKET_PEER_WRITE_DISABLED = ZX_OBJECT_SIGNAL_4;
    ZX_SOCKET_WRITE_DISABLED      = ZX_OBJECT_SIGNAL_5;
    ZX_SOCKET_READ_THRESHOLD      = ZX_OBJECT_SIGNAL_10;
    ZX_SOCKET_WRITE_THRESHOLD     = ZX_OBJECT_SIGNAL_11;

    // Resource
    ZX_RESOURCE_DESTROYED       = ZX_OBJECT_SIGNAL_3;
    ZX_RESOURCE_READABLE        = ZX_OBJECT_READABLE;
    ZX_RESOURCE_WRITABLE        = ZX_OBJECT_WRITABLE;
    ZX_RESOURCE_CHILD_ADDED     = ZX_OBJECT_SIGNAL_4;

    // Fifo
    ZX_FIFO_READABLE            = ZX_OBJECT_READABLE;
    ZX_FIFO_WRITABLE            = ZX_OBJECT_WRITABLE;
    ZX_FIFO_PEER_CLOSED         = ZX_OBJECT_PEER_CLOSED;

    // Iob
    ZX_IOB_PEER_CLOSED           = ZX_OBJECT_PEER_CLOSED;
    ZX_IOB_SHARED_REGION_UPDATED = ZX_OBJECT_SIGNAL_3;

    // Job
    ZX_JOB_TERMINATED           = ZX_OBJECT_SIGNAL_3;
    ZX_JOB_NO_JOBS              = ZX_OBJECT_SIGNAL_4;
    ZX_JOB_NO_PROCESSES         = ZX_OBJECT_SIGNAL_5;

    // Process
    ZX_PROCESS_TERMINATED       = ZX_OBJECT_SIGNAL_3;

    // Thread
    ZX_THREAD_TERMINATED        = ZX_OBJECT_SIGNAL_3;
    ZX_THREAD_RUNNING           = ZX_OBJECT_SIGNAL_4;
    ZX_THREAD_SUSPENDED         = ZX_OBJECT_SIGNAL_5;

    // Log
    ZX_LOG_READABLE             = ZX_OBJECT_READABLE;
    ZX_LOG_WRITABLE             = ZX_OBJECT_WRITABLE;

    // Timer
    ZX_TIMER_SIGNALED           = ZX_OBJECT_SIGNAL_3;

    // Vmo
    ZX_VMO_ZERO_CHILDREN        = ZX_OBJECT_SIGNAL_3;

    // Virtual Interrupt
    ZX_VIRTUAL_INTERRUPT_UNTRIGGERED = ZX_OBJECT_SIGNAL_4;

    // Counter
    ZX_COUNTER_SIGNALED          = ZX_OBJECT_SIGNAL_3;
    ZX_COUNTER_POSITIVE          = ZX_OBJECT_SIGNAL_4;
    ZX_COUNTER_NON_POSITIVE      = ZX_OBJECT_SIGNAL_5;
]);

multiconst!(zx_obj_type_t, [
    ZX_OBJ_TYPE_NONE                = 0;
    ZX_OBJ_TYPE_PROCESS             = 1;
    ZX_OBJ_TYPE_THREAD              = 2;
    ZX_OBJ_TYPE_VMO                 = 3;
    ZX_OBJ_TYPE_CHANNEL             = 4;
    ZX_OBJ_TYPE_EVENT               = 5;
    ZX_OBJ_TYPE_PORT                = 6;
    ZX_OBJ_TYPE_INTERRUPT           = 9;
    ZX_OBJ_TYPE_PCI_DEVICE          = 11;
    ZX_OBJ_TYPE_DEBUGLOG            = 12;
    ZX_OBJ_TYPE_SOCKET              = 14;
    ZX_OBJ_TYPE_RESOURCE            = 15;
    ZX_OBJ_TYPE_EVENTPAIR           = 16;
    ZX_OBJ_TYPE_JOB                 = 17;
    ZX_OBJ_TYPE_VMAR                = 18;
    ZX_OBJ_TYPE_FIFO                = 19;
    ZX_OBJ_TYPE_GUEST               = 20;
    ZX_OBJ_TYPE_VCPU                = 21;
    ZX_OBJ_TYPE_TIMER               = 22;
    ZX_OBJ_TYPE_IOMMU               = 23;
    ZX_OBJ_TYPE_BTI                 = 24;
    ZX_OBJ_TYPE_PROFILE             = 25;
    ZX_OBJ_TYPE_PMT                 = 26;
    ZX_OBJ_TYPE_SUSPEND_TOKEN       = 27;
    ZX_OBJ_TYPE_PAGER               = 28;
    ZX_OBJ_TYPE_EXCEPTION           = 29;
    ZX_OBJ_TYPE_CLOCK               = 30;
    ZX_OBJ_TYPE_STREAM              = 31;
    ZX_OBJ_TYPE_MSI                 = 32;
    ZX_OBJ_TYPE_IOB                 = 33;
    ZX_OBJ_TYPE_COUNTER             = 34;
]);

// System ABI commits to having no more than 64 object types.
//
// See zx_info_process_handle_stats_t for an example of a binary interface that
// depends on having an upper bound for the number of object types.
pub const ZX_OBJ_TYPE_UPPER_BOUND: usize = 64;

// TODO: add an alias for this type in the C headers.
multiconst!(u32, [
    // Argument is a char[ZX_MAX_NAME_LEN].
    ZX_PROP_NAME                      = 3;

    // Argument is a uintptr_t.
    #[cfg(target_arch = "x86_64")]
    ZX_PROP_REGISTER_GS               = 2;
    #[cfg(target_arch = "x86_64")]
    ZX_PROP_REGISTER_FS               = 4;

    // Argument is the value of ld.so's _dl_debug_addr, a uintptr_t.
    ZX_PROP_PROCESS_DEBUG_ADDR        = 5;

    // Argument is the base address of the vDSO mapping (or zero), a uintptr_t.
    ZX_PROP_PROCESS_VDSO_BASE_ADDRESS = 6;

    // Whether the dynamic loader should issue a debug trap when loading a shared
    // library, either initially or when running (e.g. dlopen).
    ZX_PROP_PROCESS_BREAK_ON_LOAD = 7;

    // Argument is a size_t.
    ZX_PROP_SOCKET_RX_THRESHOLD       = 12;
    ZX_PROP_SOCKET_TX_THRESHOLD       = 13;

    // Argument is a size_t, describing the number of packets a channel
    // endpoint can have pending in its tx direction.
    ZX_PROP_CHANNEL_TX_MSG_MAX        = 14;

    // Terminate this job if the system is low on memory.
    ZX_PROP_JOB_KILL_ON_OOM           = 15;

    // Exception close behavior.
    ZX_PROP_EXCEPTION_STATE           = 16;

    // The size of the content in a VMO, in bytes.
    ZX_PROP_VMO_CONTENT_SIZE          = 17;

    // How an exception should be handled.
    ZX_PROP_EXCEPTION_STRATEGY        = 18;

    // Whether the stream is in append mode or not.
    ZX_PROP_STREAM_MODE_APPEND        = 19;
]);

// Value for ZX_THREAD_STATE_SINGLE_STEP. The value can be 0 (not single-stepping), or 1
// (single-stepping). Other values will give ZX_ERR_INVALID_ARGS.
pub type zx_thread_state_single_step_t = u32;

// Possible values for "kind" in zx_thread_read_state and zx_thread_write_state.
multiconst!(zx_thread_state_topic_t, [
    ZX_THREAD_STATE_GENERAL_REGS       = 0;
    ZX_THREAD_STATE_FP_REGS            = 1;
    ZX_THREAD_STATE_VECTOR_REGS        = 2;
    // No 3 at the moment.
    ZX_THREAD_STATE_DEBUG_REGS         = 4;
    ZX_THREAD_STATE_SINGLE_STEP        = 5;
]);

// Possible values for "kind" in zx_vcpu_read_state and zx_vcpu_write_state.
multiconst!(zx_vcpu_state_topic_t, [
    ZX_VCPU_STATE   = 0;
    ZX_VCPU_IO      = 1;
    // The VCPU's complete architectural state, as a self-describing
    // [magic|version|payload_size]-headered byte buffer. See
    // //zircon/system/public/zircon/syscalls/hypervisor.h.
    ZX_VCPU_STATE_FULL = 2;
    // The VCPU's paravirtual ("enlightenment") surface: the Hyper-V identity,
    // the synthetic CPUID leaves the VMM supplies, and whether synthetic MSRs
    // and hypercalls are delivered to the VMM instead of handled in-kernel.
    // Payload is `zx_vcpu_enlightenment_t`.
    ZX_VCPU_STATE_ENLIGHTENMENT = 3;
    // The event queued for delivery into the guest on the VCPU's next entry:
    // which of the VMX interruption types it is, its vector, whether an error
    // code is present and its value, the instruction length a software
    // exception resumes past, and CR2 for #PF. Payload is
    // `zx_vcpu_pending_event_t`. A state topic (not a second action syscall
    // like `zx_vcpu_interrupt`) because a queued event IS durable VCPU state
    // until entry consumes it: reading it reports what is queued, writing it
    // replaces the queue wholesale, and `ZX_VCPU_EVENT_NONE` clears it. Must
    // be used on the thread the VCPU was created on. See
    // //zircon/system/public/zircon/syscalls/hypervisor.h.
    ZX_VCPU_STATE_PENDING_EVENT = 4;
    // A software access to the VCPU's xAPIC MMIO register page. Write submits
    // one `zx_vcpu_xapic_access_t`; read retrieves its value and side effect.
    ZX_VCPU_STATE_XAPIC_ACCESS = 5;
    // Versioned byte stream containing the local-APIC timer, pending
    // interrupts, and paravirtual-clock mapping.
    ZX_VCPU_STATE_ASYNC = 6;
    // Versioned host-assisted debug controls. Payload is
    // `zx_vcpu_debug_state_t`; reads report host-derived support and current
    // state, while writes atomically replace the active controls.
    ZX_VCPU_STATE_DEBUG = 7;
    // Versioned host-assisted bounded-run controls. Payload is
    // `zx_vcpu_run_control_t`; timer expiry is one-shot and makes VCPU entry
    // return `ZX_ERR_TIMED_OUT`.
    ZX_VCPU_STATE_RUN_CONTROL = 8;
    // Versioned one-shot post-handler VM-exit observation and completed-exit
    // budget. Payload is `zx_vcpu_exit_control_t`.
    ZX_VCPU_STATE_EXIT_CONTROL = 9;
    // Versioned one-shot guest-only retired-instruction budget. Payload is
    // `zx_vcpu_instruction_control_t`.
    ZX_VCPU_STATE_INSTRUCTION_CONTROL = 10;
    // Versioned guest-global, EPT-backed guest-physical access stops. Payload
    // is `zx_vcpu_memory_access_control_t`.
    ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL = 11;
    // Versioned typed Intel PT configuration and bounded cursor reads. Payload
    // is `zx_vcpu_intel_pt_control_t`.
    ZX_VCPU_STATE_INTEL_PT_CONTROL = 12;
    // Versioned transparent hardware instruction/data breakpoints. Payload is
    // `zx_vcpu_hardware_breakpoint_control_t`.
    ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL = 13;
]);

/// Identity and version of `zx_vcpu_debug_state_t`.
pub const ZX_VCPU_DEBUG_STATE_MAGIC: u32 = 0x5644_4247; // 'VDBG'
pub const ZX_VCPU_DEBUG_STATE_VERSION: u32 = 1;

multiconst!(u64, [
    /// Intercept guest `#BP` / `INT3` as a guest-exception exit.
    ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT = 1 << 0;
    /// Exit after the next guest instruction. The kernel disarms this
    /// one-shot control before returning the exit to userspace.
    ZX_VCPU_DEBUG_SINGLE_STEP = 1 << 1;
]);

pub const ZX_VCPU_DEBUG_ALL_FLAGS: u64 =
    ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT | ZX_VCPU_DEBUG_SINGLE_STEP;

/// Host-assisted debug configuration (topic `ZX_VCPU_STATE_DEBUG`).
///
/// A read reports controls supported by the active host and controls currently
/// armed. On write, `supported_flags` and `reserved` must be zero and
/// `active_flags` replaces the configuration atomically.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_debug_state_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub supported_flags: u64,
    pub active_flags: u64,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_debug_state_t>() == 32);

/// Identity and version of `zx_vcpu_run_control_t`.
pub const ZX_VCPU_RUN_CONTROL_MAGIC: u32 = 0x5652_554e; // 'VRUN'
pub const ZX_VCPU_RUN_CONTROL_VERSION: u32 = 1;

multiconst!(u64, [
    /// Exit after `preemption_timer_ticks` host-reported VMX timer ticks.
    ZX_VCPU_RUN_PREEMPTION_TIMER = 1 << 0;
]);

pub const ZX_VCPU_RUN_ALL_FLAGS: u64 = ZX_VCPU_RUN_PREEMPTION_TIMER;

/// Host-assisted bounded-run configuration
/// (`ZX_VCPU_STATE_RUN_CONTROL`).
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_run_control_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub supported_flags: u64,
    pub active_flags: u64,
    pub preemption_timer_ticks: u32,
    pub preemption_timer_rate_shift: u8,
    pub reserved2: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_run_control_t>() == 40);

pub const ZX_VCPU_EXIT_CONTROL_MAGIC: u32 = 0x5645_5843; // 'VEXC'
pub const ZX_VCPU_EXIT_CONTROL_VERSION: u32 = 1;

multiconst!(u64, [
    /// Stop after normal handling of a selected VM-exit reason.
    ZX_VCPU_EXIT_CONTROL_OBSERVE = 1 << 0;
    /// Stop after normal handling of a bounded number of VM exits.
    ZX_VCPU_EXIT_CONTROL_BUDGET = 1 << 1;
]);

pub const ZX_VCPU_EXIT_CONTROL_ALL_FLAGS: u64 =
    ZX_VCPU_EXIT_CONTROL_OBSERVE | ZX_VCPU_EXIT_CONTROL_BUDGET;

/// One-shot post-handler VM-exit controls
/// (`ZX_VCPU_STATE_EXIT_CONTROL`).
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_exit_control_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub supported_flags: u64,
    pub active_flags: u64,
    pub supported_reasons: [u64; 2],
    pub selected_reasons: [u64; 2],
    pub exit_budget: u64,
    pub ack_sequence: u64,
    pub pending_sequence: u64,
    pub exits_seen: u64,
    pub pending_exit_reason: u32,
    pub pending_flags: u32,
    pub pending_exit_rip: u64,
    pub pending_resume_rip: u64,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_exit_control_t>() == 120);

pub const ZX_VCPU_INSTRUCTION_CONTROL_MAGIC: u32 = 0x5649_4e53; // 'VINS'
pub const ZX_VCPU_INSTRUCTION_CONTROL_VERSION: u32 = 1;

multiconst!(u64, [
    ZX_VCPU_INSTRUCTION_RETIRED_BUDGET = 1 << 0;
]);

pub const ZX_VCPU_INSTRUCTION_ALL_FLAGS: u64 = ZX_VCPU_INSTRUCTION_RETIRED_BUDGET;

pub type zx_vcpu_instruction_availability_t = u32;
multiconst!(zx_vcpu_instruction_availability_t, [
    ZX_VCPU_INSTRUCTION_UNSUPPORTED = 0;
    ZX_VCPU_INSTRUCTION_AVAILABLE = 1;
    ZX_VCPU_INSTRUCTION_BUSY = 2;
]);

pub type zx_vcpu_instruction_precision_t = u32;
multiconst!(zx_vcpu_instruction_precision_t, [
    ZX_VCPU_INSTRUCTION_PRECISION_OVERFLOW_INTERRUPT = 1;
]);

/// Guest-only retired-instruction control
/// (`ZX_VCPU_STATE_INSTRUCTION_CONTROL`).
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_instruction_control_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub availability: zx_vcpu_instruction_availability_t,
    pub counter_width: u32,
    pub precision: zx_vcpu_instruction_precision_t,
    pub reserved2: u32,
    pub supported_flags: u64,
    pub active_flags: u64,
    pub max_budget: u64,
    pub budget: u64,
    pub ack_sequence: u64,
    pub pending_sequence: u64,
    pub retired_instructions: u64,
    pub pending_rip: u64,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_instruction_control_t>() == 96);

pub const ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC: u32 = 0x564d_4143; // 'VMAC'
pub const ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION: u32 = 1;
pub const ZX_VCPU_MEMORY_ACCESS_MAX_RANGES: usize = 16;
pub const ZX_VCPU_MEMORY_ACCESS_MAX_PAGES: u32 = 64;

pub type zx_vcpu_memory_access_availability_t = u32;
multiconst!(zx_vcpu_memory_access_availability_t, [
    ZX_VCPU_MEMORY_ACCESS_UNSUPPORTED = 0;
    ZX_VCPU_MEMORY_ACCESS_AVAILABLE = 1;
]);

multiconst!(u64, [
    ZX_VCPU_MEMORY_ACCESS_ARM = 1 << 0;
]);
pub const ZX_VCPU_MEMORY_ACCESS_ALL_FLAGS: u64 = ZX_VCPU_MEMORY_ACCESS_ARM;

pub type zx_vcpu_memory_access_mask_t = u32;
multiconst!(zx_vcpu_memory_access_mask_t, [
    ZX_VCPU_MEMORY_ACCESS_READ = 1 << 0;
    ZX_VCPU_MEMORY_ACCESS_WRITE = 1 << 1;
    ZX_VCPU_MEMORY_ACCESS_EXECUTE = 1 << 2;
]);
pub const ZX_VCPU_MEMORY_ACCESS_ALL: u32 =
    ZX_VCPU_MEMORY_ACCESS_READ | ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE;
pub const ZX_VCPU_MEMORY_ACCESS_RESULT_GVA_VALID: u32 = 1 << 0;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_memory_access_range_t {
    pub guest_paddr: zx_gpaddr_t,
    pub length: u64,
    pub access: zx_vcpu_memory_access_mask_t,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_memory_access_range_t>() == 24);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_memory_access_control_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub availability: zx_vcpu_memory_access_availability_t,
    pub max_ranges: u16,
    pub max_pages: u16,
    pub supported_flags: u64,
    pub active_flags: u64,
    pub range_count: u32,
    pub reserved2: u32,
    pub ranges: [zx_vcpu_memory_access_range_t; ZX_VCPU_MEMORY_ACCESS_MAX_RANGES],
    pub ack_sequence: u64,
    pub pending_sequence: u64,
    pub pending_guest_paddr: zx_gpaddr_t,
    pub pending_guest_vaddr: zx_vaddr_t,
    pub pending_rip: zx_vaddr_t,
    pub pending_qualification: u64,
    pub pending_range_mask: u64,
    pub pending_access: zx_vcpu_memory_access_mask_t,
    pub pending_flags: u32,
    pub pending_vpid: u32,
    pub supported_access: zx_vcpu_memory_access_mask_t,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_memory_access_control_t>() == 504);

pub const ZX_VCPU_INTEL_PT_CONTROL_MAGIC: u32 = 0x5650_5443; // 'VPTC'
pub const ZX_VCPU_INTEL_PT_CONTROL_VERSION: u32 = 1;
pub const ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES: usize = 4;
pub const ZX_VCPU_INTEL_PT_MAX_CPUID_LEAVES: usize = 2;
pub const ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES: usize = 4096;
pub const ZX_VCPU_INTEL_PT_MAX_BUFFER_BYTES: u64 = 4 * 1024 * 1024;

pub type zx_vcpu_intel_pt_availability_t = u32;
multiconst!(zx_vcpu_intel_pt_availability_t, [
    ZX_VCPU_INTEL_PT_UNSUPPORTED = 0;
    ZX_VCPU_INTEL_PT_AVAILABLE = 1;
    ZX_VCPU_INTEL_PT_BUSY = 2;
]);

pub type zx_vcpu_intel_pt_unavailable_reason_t = u32;
multiconst!(zx_vcpu_intel_pt_unavailable_reason_t, [
    ZX_VCPU_INTEL_PT_REASON_NONE = 0;
    ZX_VCPU_INTEL_PT_REASON_NESTED_HOST = 1;
    ZX_VCPU_INTEL_PT_REASON_ABSENT = 2;
    ZX_VCPU_INTEL_PT_REASON_CPUID_MALFORMED = 3;
    ZX_VCPU_INTEL_PT_REASON_TOPA_UNAVAILABLE = 4;
    ZX_VCPU_INTEL_PT_REASON_MULTI_ENTRY_TOPA_UNAVAILABLE = 5;
    ZX_VCPU_INTEL_PT_REASON_RTIT_MSR_UNAVAILABLE = 6;
    ZX_VCPU_INTEL_PT_REASON_PMI_CONFLICT = 7;
    ZX_VCPU_INTEL_PT_REASON_VMX_CONTROL_UNAVAILABLE = 8;
    ZX_VCPU_INTEL_PT_REASON_BUFFER_ALLOCATION = 9;
]);

pub type zx_vcpu_intel_pt_action_t = u32;
multiconst!(zx_vcpu_intel_pt_action_t, [
    ZX_VCPU_INTEL_PT_ACTION_NONE = 0;
    ZX_VCPU_INTEL_PT_ACTION_CONFIGURE = 1;
    ZX_VCPU_INTEL_PT_ACTION_SELECT_READ = 2;
    ZX_VCPU_INTEL_PT_ACTION_ACK = 3;
    ZX_VCPU_INTEL_PT_ACTION_STOP = 4;
    ZX_VCPU_INTEL_PT_ACTION_RELEASE = 5;
]);

pub type zx_vcpu_intel_pt_delivery_t = u32;
multiconst!(zx_vcpu_intel_pt_delivery_t, [
    ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL = 1;
]);

multiconst!(u64, [
    ZX_VCPU_INTEL_PT_TRACE_USER = 1 << 0;
    ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR = 1 << 1;
    ZX_VCPU_INTEL_PT_BRANCH_TRACE = 1 << 2;
    ZX_VCPU_INTEL_PT_CR3_FILTER = 1 << 3;
    ZX_VCPU_INTEL_PT_MTC_PACKETS = 1 << 4;
    ZX_VCPU_INTEL_PT_CYCLE_PACKETS = 1 << 5;
]);
pub const ZX_VCPU_INTEL_PT_ALL_FLAGS: u64 = ZX_VCPU_INTEL_PT_TRACE_USER
    | ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR
    | ZX_VCPU_INTEL_PT_BRANCH_TRACE
    | ZX_VCPU_INTEL_PT_CR3_FILTER
    | ZX_VCPU_INTEL_PT_MTC_PACKETS
    | ZX_VCPU_INTEL_PT_CYCLE_PACKETS;

pub type zx_vcpu_intel_pt_terminal_t = u32;
multiconst!(zx_vcpu_intel_pt_terminal_t, [
    ZX_VCPU_INTEL_PT_TERMINAL_INACTIVE = 0;
    ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE = 1;
    ZX_VCPU_INTEL_PT_TERMINAL_COMPLETE = 2;
    ZX_VCPU_INTEL_PT_TERMINAL_INCOMPLETE = 3;
]);

multiconst!(u32, [
    ZX_VCPU_INTEL_PT_STATUS_BACKPRESSURE = 1 << 0;
    ZX_VCPU_INTEL_PT_STATUS_SEGMENT_COMPLETE = 1 << 1;
    ZX_VCPU_INTEL_PT_STATUS_HARDWARE_STOPPED = 1 << 2;
    ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR = 1 << 3;
    ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE = 1 << 4;
]);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_intel_pt_cpuid_leaf_t {
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_intel_pt_cpuid_leaf_t>() == 24);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_intel_pt_address_range_t {
    pub start: zx_vaddr_t,
    pub length: u64,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_intel_pt_address_range_t>() == 16);

/// Typed Intel PT configuration, status, and a bounded immutable cursor read.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_intel_pt_control_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub action: zx_vcpu_intel_pt_action_t,
    pub availability: zx_vcpu_intel_pt_availability_t,
    pub unavailable_reason: zx_vcpu_intel_pt_unavailable_reason_t,
    pub cpu_family: u32,
    pub cpu_model: u32,
    pub cpu_stepping: u32,
    pub max_address_ranges: u32,
    pub supported_psb_frequencies: u32,
    pub supported_mtc_frequencies: u32,
    pub supported_cycle_thresholds: u32,
    pub reserved0: u32,
    pub supported_flags: u64,
    pub cpuid_14: [zx_vcpu_intel_pt_cpuid_leaf_t; ZX_VCPU_INTEL_PT_MAX_CPUID_LEAVES],
    pub delivery: zx_vcpu_intel_pt_delivery_t,
    pub address_range_count: u32,
    pub config_flags: u64,
    pub buffer_bytes: u64,
    pub address_ranges:
        [zx_vcpu_intel_pt_address_range_t; ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES],
    pub cr3_match: u64,
    pub psb_frequency: u32,
    pub mtc_frequency: u32,
    pub cycle_threshold: u32,
    pub reserved1: u32,
    pub trace_generation: u64,
    pub acknowledged_cursor: u64,
    pub read_cursor: u64,
    pub read_max_bytes: u32,
    pub data_size: u32,
    pub next_cursor: u64,
    pub producer_cursor: u64,
    pub segment_sequence: u64,
    pub segment_offset: u64,
    pub hardware_status: u64,
    pub lost_bytes: u64,
    pub watermark_count: u64,
    pub terminal: zx_vcpu_intel_pt_terminal_t,
    pub status_flags: u32,
    pub data: [u8; ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES],
}

impl Default for zx_vcpu_intel_pt_control_t {
    fn default() -> Self {
        // This C ABI structure contains no invalid bit pattern.
        unsafe { core::mem::zeroed() }
    }
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_intel_pt_control_t>() == 4416);

pub const ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_MAGIC: u32 = 0x5648_4243; // 'VHBC'
pub const ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_VERSION: u32 = 1;
pub const ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS: usize = 4;

pub type zx_vcpu_hardware_breakpoint_availability_t = u32;
multiconst!(zx_vcpu_hardware_breakpoint_availability_t, [
    ZX_VCPU_HARDWARE_BREAKPOINT_UNSUPPORTED = 0;
    ZX_VCPU_HARDWARE_BREAKPOINT_AVAILABLE = 1;
]);

multiconst!(u64, [
    ZX_VCPU_HARDWARE_BREAKPOINT_ARM = 1 << 0;
]);
pub const ZX_VCPU_HARDWARE_BREAKPOINT_ALL_FLAGS: u64 =
    ZX_VCPU_HARDWARE_BREAKPOINT_ARM;

pub type zx_vcpu_hardware_breakpoint_access_t = u32;
multiconst!(zx_vcpu_hardware_breakpoint_access_t, [
    ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE = 0;
    ZX_VCPU_HARDWARE_BREAKPOINT_WRITE = 1;
    ZX_VCPU_HARDWARE_BREAKPOINT_READ_WRITE = 3;
]);

pub type zx_vcpu_hardware_breakpoint_length_t = u32;
multiconst!(zx_vcpu_hardware_breakpoint_length_t, [
    ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1 = 1;
    ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_2 = 2;
    ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_4 = 4;
    ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_8 = 8;
]);

pub type zx_vcpu_hardware_breakpoint_boundary_t = u32;
multiconst!(zx_vcpu_hardware_breakpoint_boundary_t, [
    ZX_VCPU_HARDWARE_BREAKPOINT_PRE_INSTRUCTION = 1;
    ZX_VCPU_HARDWARE_BREAKPOINT_POST_ACCESS = 2;
    ZX_VCPU_HARDWARE_BREAKPOINT_MIXED_BOUNDARY = 3;
]);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_hardware_breakpoint_request_t {
    pub address: zx_vaddr_t,
    pub access: zx_vcpu_hardware_breakpoint_access_t,
    pub length: zx_vcpu_hardware_breakpoint_length_t,
    pub condition_index: u32,
    pub reserved: u32,
}

const _: () =
    assert!(core::mem::size_of::<zx_vcpu_hardware_breakpoint_request_t>() == 24);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_hardware_breakpoint_control_t {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub availability: zx_vcpu_hardware_breakpoint_availability_t,
    pub max_slots: u16,
    pub max_requests: u16,
    pub supported_flags: u64,
    pub active_flags: u64,
    pub request_count: u32,
    pub reserved2: u32,
    pub requests:
        [zx_vcpu_hardware_breakpoint_request_t; ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS],
    pub ack_sequence: u64,
    pub pending_sequence: u64,
    pub pending_condition_mask: u64,
    pub pending_rip: zx_vaddr_t,
    pub pending_raw_dr6: u64,
    pub pending_guest_dr6: u64,
    pub pending_vpid: u16,
    pub pending_slot_mask: u8,
    pub pending_boundary: u8,
    pub reserved3: u32,
}

const _: () =
    assert!(core::mem::size_of::<zx_vcpu_hardware_breakpoint_control_t>() == 200);

/// Create an x86 VCPU with its local APIC enabled in xAPIC mode. Without this
/// option, the VCPU retains the legacy x2APIC-at-reset behavior. CPUID is
/// configured separately and must agree with the selected initial mode.
pub const ZX_VCPU_CREATE_XAPIC: u32 = 1 << 0;

/// Identity and version of `zx_vcpu_xapic_access_t`.
pub const ZX_VCPU_XAPIC_ACCESS_MAGIC: u32 = 0x5658_4150; // 'VXAP'
pub const ZX_VCPU_XAPIC_ACCESS_VERSION: u32 = 1;

pub type zx_vcpu_xapic_action_t = u32;

multiconst!(zx_vcpu_xapic_action_t, [
    /// Read one 32-bit xAPIC register.
    ZX_VCPU_XAPIC_ACTION_READ = 1;
    /// Write one 32-bit xAPIC register.
    ZX_VCPU_XAPIC_ACTION_WRITE = 2;
]);

/// `zx_vcpu_xapic_access_t::value` contains the READ result.
pub const ZX_VCPU_XAPIC_RESULT_VALUE_VALID: u32 = 1 << 0;

pub type zx_vcpu_xapic_result_kind_t = u32;

multiconst!(zx_vcpu_xapic_result_kind_t, [
    /// No device-facing side effect.
    ZX_VCPU_XAPIC_RESULT_NONE = 0;
    /// `vector` names the interrupt whose EOI completed.
    ZX_VCPU_XAPIC_RESULT_EOI = 1;
    /// `target` is a VCPU mask and `vector` is the interrupt to deliver.
    ZX_VCPU_XAPIC_RESULT_INTERRUPT = 2;
    /// `target` is an APIC ID and `entry` is the STARTUP entry address.
    ZX_VCPU_XAPIC_RESULT_STARTUP = 3;
]);

/// One software access to the xAPIC MMIO register page (topic
/// `ZX_VCPU_STATE_XAPIC_ACCESS`).
///
/// On write, all result fields and `reserved` must be zero. On read, `action`
/// and `offset` identify the completed request, `value` contains a READ result
/// when `ZX_VCPU_XAPIC_RESULT_VALUE_VALID` is set, and `result_kind` selects
/// the valid device-facing payload.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_xapic_access_t {
    /// `ZX_VCPU_XAPIC_ACCESS_MAGIC`.
    pub magic: u32,
    /// `ZX_VCPU_XAPIC_ACCESS_VERSION`.
    pub version: u32,
    /// `size_of::<zx_vcpu_xapic_access_t>()`.
    pub size: u32,
    /// One of `ZX_VCPU_XAPIC_ACTION_*`.
    pub action: zx_vcpu_xapic_action_t,
    /// A 16-byte-aligned register offset in `[0, 0xff0]`.
    pub offset: u32,
    /// WRITE request value or READ result.
    pub value: u32,
    /// `ZX_VCPU_XAPIC_RESULT_*` flags.
    pub result_flags: u32,
    /// One of `ZX_VCPU_XAPIC_RESULT_{NONE,EOI,INTERRUPT,STARTUP}`.
    pub result_kind: zx_vcpu_xapic_result_kind_t,
    /// EOI or interrupt vector, according to `result_kind`.
    pub vector: u32,
    /// Must be zero.
    pub reserved: u32,
    /// Interrupt VCPU mask or STARTUP APIC ID.
    pub target: u64,
    /// STARTUP guest entry address; zero otherwise.
    pub entry: u64,
}

const _: () = assert!(core::mem::size_of::<zx_vcpu_xapic_access_t>() == 56);

// Identity and version of `zx_vcpu_enlightenment_t`, both checked by the kernel
// on write so a userspace built against a different layout is refused rather
// than misread.
pub const ZX_VCPU_ENLIGHTENMENT_MAGIC: u32 = 0x564e_4c54; // 'VNLT'
pub const ZX_VCPU_ENLIGHTENMENT_VERSION: u32 = 1;

multiconst!(u32, [
    /// Present the hypervisor to the guest as Hyper-V ("Microsoft Hv") through
    /// the 0x4000_0000 CPUID leaves, instead of the default KVM identity.
    ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY = 1 << 0;
    /// Deliver guest accesses to the synthetic MSR block
    /// (0x4000_0000-0x4000_ffff) as `ZX_PKT_TYPE_GUEST_MSR` packets.
    ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS = 1 << 1;
    /// Deliver guest hypercalls as `ZX_PKT_TYPE_GUEST_HYPERCALL` packets.
    ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS = 1 << 2;
]);

// Identity and version of `zx_vcpu_pending_event_t`, both checked by the
// kernel on write so a userspace built against a different layout is refused
// rather than misread.
pub const ZX_VCPU_PENDING_EVENT_MAGIC: u32 = 0x5650_454e; // 'VPEN'
pub const ZX_VCPU_PENDING_EVENT_VERSION: u32 = 1;

/// The kind of event to deliver (`zx_vcpu_pending_event_t::type`). These name
/// the distinction VMX draws in the VM-entry interruption-information field
/// (SDM Vol. 3, 24.8.3): the hardware vectors an external interrupt, an NMI
/// and an exception differently, and a software exception resumes at the
/// instruction *after* the one that raised it.
pub type zx_vcpu_event_type_t = u32;

multiconst!(zx_vcpu_event_type_t, [
    /// No event queued. Writing this clears whatever was queued before.
    ZX_VCPU_EVENT_NONE = 0;
    /// A maskable external interrupt. Vector must be in `[0x20, 0xff]`.
    /// Delivery waits for the guest to become interruptible, exactly as
    /// `zx_vcpu_interrupt()` does.
    ZX_VCPU_EVENT_EXTERNAL_INTERRUPT = 1;
    /// A non-maskable interrupt. Vector must be 2.
    ZX_VCPU_EVENT_NMI = 2;
    /// A hardware exception (a fault or trap raised by execution): vector in
    /// `[0, 0x1f]`. This is what an instruction emulator injects. Not
    /// maskable, so delivered on the next entry regardless of RFLAGS.IF.
    ZX_VCPU_EVENT_HARDWARE_EXCEPTION = 3;
    /// A software exception: #BP (3) or #OF (4) only, as raised by
    /// INT3 / INTO. `instruction_length` must be set.
    ZX_VCPU_EVENT_SOFTWARE_EXCEPTION = 4;
]);

multiconst!(u32, [
    /// `error_code` holds the error code to deliver. Required for, and
    /// permitted only for, a hardware exception whose vector architecturally
    /// has one: #DF (8), #TS (10), #NP (11), #SS (12), #GP (13), #PF (14) and
    /// #AC (17).
    ZX_VCPU_EVENT_ERROR_CODE_VALID = 1 << 0;
    /// `cr2` holds the faulting linear address to place in CR2 before
    /// delivery. Required for, and permitted only for, #PF (14).
    ZX_VCPU_EVENT_CR2_VALID = 1 << 1;
]);

/// The event queued for delivery on a VCPU's next entry (topic
/// `ZX_VCPU_STATE_PENDING_EVENT`).
///
/// Nothing is applied unless the entire structure validates, so a rejected
/// write leaves the VCPU exactly as it was. Every field not used by the
/// chosen `type` must be zero.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_pending_event_t {
    /// `ZX_VCPU_PENDING_EVENT_MAGIC`.
    pub magic: u32,
    /// `ZX_VCPU_PENDING_EVENT_VERSION`.
    pub version: u32,
    /// `size_of::<zx_vcpu_pending_event_t>()`.
    pub size: u32,
    /// One of `ZX_VCPU_EVENT_*`.
    pub type_: zx_vcpu_event_type_t,
    /// The interrupt or exception vector, within the range its `type` allows.
    pub vector: u32,
    /// `ZX_VCPU_EVENT_*` payload-presence flags.
    pub flags: u32,
    /// The architectural error code, if `ZX_VCPU_EVENT_ERROR_CODE_VALID`;
    /// else zero.
    pub error_code: u32,
    /// Length in bytes of the instruction that raised a software exception,
    /// in `[1, 15]`; zero for every other type.
    pub instruction_length: u32,
    /// The faulting linear address to load into CR2, if
    /// `ZX_VCPU_EVENT_CR2_VALID` (i.e. for #PF); else zero.
    pub cr2: u64,
}

/// Identity and version of `zx_vcpu_vectoring_event_t`, checked by the kernel on
/// write so a userspace built against a different layout is refused.
pub const ZX_VCPU_VECTORING_EVENT_MAGIC: u32 = 0x5645_434e; // 'VECN'
pub const ZX_VCPU_VECTORING_EVENT_VERSION: u32 = 1;

/// An event interrupted mid-delivery through the guest IDT, recovered from the
/// VMCS IDT-vectoring-information field (topic `ZX_VCPU_STATE_VECTORING_EVENT`).
///
/// Distinct from `zx_vcpu_pending_event_t` — both can be outstanding at once.
/// Unlike the pending event's abstract `ZX_VCPU_EVENT_*` vocabulary, `type_`
/// carries the RAW VMX interruption type already shifted into bits 10:8, since
/// the abstract enum cannot name a software interrupt or privileged software
/// exception and re-injection must reproduce the exact hardware type. Only the
/// reinjectable subfields are carried; a write validates the whole structure
/// before applying any of it and `valid == 0` clears it.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_vectoring_event_t {
    /// `ZX_VCPU_VECTORING_EVENT_MAGIC`.
    pub magic: u32,
    /// `ZX_VCPU_VECTORING_EVENT_VERSION`.
    pub version: u32,
    /// `size_of::<zx_vcpu_vectoring_event_t>()`.
    pub size: u32,
    /// Nonzero if an interrupted delivery is owed; zero means nothing queued
    /// and every other field must be zero.
    pub valid: u32,
    /// Raw VMX interruption type, already shifted into bits 10:8.
    pub type_: u32,
    /// The interrupt or exception vector (bits 7:0).
    pub vector: u32,
    /// Nonzero if `error_code` carries a delivered error code.
    pub has_error_code: u32,
    /// The architectural error code, if `has_error_code`; else zero.
    pub error_code: u32,
    /// Length of the originating instruction for the software forms that resume
    /// past it; zero for every other type.
    pub instruction_length: u32,
}

pub const ZX_VCPU_TSC_STATE_MAGIC: u32 = 0x4143_5354; // 'TSCA'
pub const ZX_VCPU_TSC_STATE_VERSION: u32 = 2;

/// `flags`: the topic carries a captured TSC state (a live read always sets it).
/// Clear means a legacy artifact predating this topic; a write is a no-op.
pub const ZX_VCPU_TSC_STATE_PRESENT: u32 = 1 << 0;
/// `flags`: TSC offsetting is available (read) / the supplied `tsc_offset` must
/// be installed (write).
pub const ZX_VCPU_TSC_STATE_OFFSETTING: u32 = 1 << 1;

/// Guest TSC anchor and armed IA32_TSC_DEADLINE (topic `ZX_VCPU_STATE_TSC`).
/// A write installs the supplied signed `tsc_offset` verbatim (a pre-computed
/// single-partition offset) and re-derives the armed deadline through it.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_tsc_state_t {
    /// `ZX_VCPU_TSC_STATE_MAGIC`.
    pub magic: u32,
    /// `ZX_VCPU_TSC_STATE_VERSION`.
    pub version: u32,
    /// `size_of::<zx_vcpu_tsc_state_t>()`.
    pub size: u32,
    /// `ZX_VCPU_TSC_STATE_PRESENT | ZX_VCPU_TSC_STATE_OFFSETTING`.
    pub flags: u32,
    /// Read: the guest's TSC now. Write: informational -- the anchor recorded at
    /// capture; the kernel installs `tsc_offset`, not this.
    pub guest_tsc: u64,
    /// The signed VMCS TSC_OFFSET. Read: the offset in force. Write (with
    /// PRESENT+OFFSETTING): installed verbatim.
    pub tsc_offset: i64,
    /// The armed IA32_TSC_DEADLINE in the guest's own TSC, or zero if unarmed.
    pub tsc_deadline: u64,
}

/// The first synthetic CPUID leaf a VMM may supply. Leaves below this are the
/// fixed identity leaves, which the kernel answers itself.
pub const ZX_VCPU_HYPERV_CPUID_LEAF_FIRST: u32 = 0x4000_0002;
/// The last synthetic CPUID leaf a VMM may supply.
pub const ZX_VCPU_HYPERV_CPUID_LEAF_LAST: u32 = 0x4000_0005;
/// The number of leaves in `zx_vcpu_enlightenment_t::cpuid`.
pub const ZX_VCPU_HYPERV_CPUID_MAX: usize = 4;

/// One synthetic CPUID leaf and the four registers it reports.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_hyperv_cpuid_t {
    pub leaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// The paravirtual surface configuration of a VCPU (topic
/// `ZX_VCPU_STATE_ENLIGHTENMENT`).
///
/// A write replaces the whole configuration: `flags` names every capability
/// that is on afterwards, and any leaf not listed in `cpuid[..cpuid_count]`
/// reads back as zero. Nothing is applied unless the entire structure
/// validates, so a rejected write leaves the VCPU exactly as it was.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_enlightenment_t {
    /// `ZX_VCPU_ENLIGHTENMENT_MAGIC`.
    pub magic: u32,
    /// `ZX_VCPU_ENLIGHTENMENT_VERSION`.
    pub version: u32,
    /// `size_of::<zx_vcpu_enlightenment_t>()`.
    pub size: u32,
    /// `ZX_VCPU_ENLIGHTENMENT_*` flags.
    pub flags: u32,
    /// Number of valid entries in `cpuid`; at most `ZX_VCPU_HYPERV_CPUID_MAX`.
    pub cpuid_count: u32,
    /// Must be zero.
    pub reserved: u32,
    pub cpuid: [zx_vcpu_hyperv_cpuid_t; ZX_VCPU_HYPERV_CPUID_MAX],
}

// From //zircon/system/public/zircon/features.h
multiconst!(u32, [
    ZX_FEATURE_KIND_CPU                        = 0;
    ZX_FEATURE_KIND_HW_BREAKPOINT_COUNT        = 1;
    ZX_FEATURE_KIND_HW_WATCHPOINT_COUNT        = 2;
    ZX_FEATURE_KIND_ADDRESS_TAGGING            = 3;
    ZX_FEATURE_KIND_VM                         = 4;
]);

// From //zircon/system/public/zircon/features.h
multiconst!(u32, [
    ZX_HAS_CPU_FEATURES                   = 1 << 0;

    ZX_VM_FEATURE_CAN_MAP_XOM             = 1 << 0;

    ZX_ARM64_FEATURE_ISA_FP               = 1 << 1;
    ZX_ARM64_FEATURE_ISA_ASIMD            = 1 << 2;
    ZX_ARM64_FEATURE_ISA_AES              = 1 << 3;
    ZX_ARM64_FEATURE_ISA_PMULL            = 1 << 4;
    ZX_ARM64_FEATURE_ISA_SHA1             = 1 << 5;
    ZX_ARM64_FEATURE_ISA_SHA256           = 1 << 6;
    ZX_ARM64_FEATURE_ISA_CRC32            = 1 << 7;
    ZX_ARM64_FEATURE_ISA_ATOMICS          = 1 << 8;
    ZX_ARM64_FEATURE_ISA_RDM              = 1 << 9;
    ZX_ARM64_FEATURE_ISA_SHA3             = 1 << 10;
    ZX_ARM64_FEATURE_ISA_SM3              = 1 << 11;
    ZX_ARM64_FEATURE_ISA_SM4              = 1 << 12;
    ZX_ARM64_FEATURE_ISA_DP               = 1 << 13;
    ZX_ARM64_FEATURE_ISA_DPB              = 1 << 14;
    ZX_ARM64_FEATURE_ISA_FHM              = 1 << 15;
    ZX_ARM64_FEATURE_ISA_TS               = 1 << 16;
    ZX_ARM64_FEATURE_ISA_RNDR             = 1 << 17;
    ZX_ARM64_FEATURE_ISA_SHA512           = 1 << 18;
    ZX_ARM64_FEATURE_ISA_I8MM             = 1 << 19;
    ZX_ARM64_FEATURE_ISA_SVE              = 1 << 20;
    ZX_ARM64_FEATURE_ISA_ARM32            = 1 << 21;
    ZX_ARM64_FEATURE_ISA_SHA2             = 1 << 6;
    ZX_ARM64_FEATURE_ADDRESS_TAGGING_TBI  = 1 << 0;
]);

// From //zircon/system/public/zircon/syscalls/resource.h
multiconst!(zx_rsrc_kind_t, [
    ZX_RSRC_KIND_MMIO       = 0;
    ZX_RSRC_KIND_IRQ        = 1;
    ZX_RSRC_KIND_IOPORT     = 2;
    ZX_RSRC_KIND_ROOT       = 3;
    ZX_RSRC_KIND_SMC        = 4;
    ZX_RSRC_KIND_SYSTEM     = 5;
]);

// From //zircon/system/public/zircon/syscalls/resource.h
multiconst!(zx_rsrc_system_base_t, [
    ZX_RSRC_SYSTEM_HYPERVISOR_BASE  = 0;
    ZX_RSRC_SYSTEM_VMEX_BASE        = 1;
    ZX_RSRC_SYSTEM_DEBUG_BASE       = 2;
    ZX_RSRC_SYSTEM_INFO_BASE        = 3;
    ZX_RSRC_SYSTEM_CPU_BASE         = 4;
    ZX_RSRC_SYSTEM_POWER_BASE       = 5;
    ZX_RSRC_SYSTEM_MEXEC_BASE       = 6;
    ZX_RSRC_SYSTEM_ENERGY_INFO_BASE = 7;
    ZX_RSRC_SYSTEM_IOMMU_BASE       = 8;
    ZX_RSRC_SYSTEM_FRAMEBUFFER_BASE = 9;
    ZX_RSRC_SYSTEM_PROFILE_BASE     = 10;
    ZX_RSRC_SYSTEM_MSI_BASE         = 11;
    ZX_RSRC_SYSTEM_DEBUGLOG_BASE    = 12;
    ZX_RSRC_SYSTEM_STALL_BASE       = 13;
    ZX_RSRC_SYSTEM_TRACING_BASE     = 14;
    // A resource representing the ability to sample callstack information about other processes.
    ZX_RSRC_SYSTEM_SAMPLING_BASE    = 15;
]);

// clock ids
multiconst!(zx_clock_t, [
    ZX_CLOCK_MONOTONIC = 0;
    ZX_CLOCK_BOOT      = 1;
]);

// from //zircon/system/public/zircon/syscalls/clock.h
multiconst!(u64, [
    ZX_CLOCK_OPT_MONOTONIC = 1 << 0;
    ZX_CLOCK_OPT_CONTINUOUS = 1 << 1;
    ZX_CLOCK_OPT_AUTO_START = 1 << 2;
    ZX_CLOCK_OPT_BOOT = 1 << 3;
    ZX_CLOCK_OPT_MAPPABLE = 1 << 4;

    // v1 clock update flags
    ZX_CLOCK_UPDATE_OPTION_VALUE_VALID = 1 << 0;
    ZX_CLOCK_UPDATE_OPTION_RATE_ADJUST_VALID = 1 << 1;
    ZX_CLOCK_UPDATE_OPTION_ERROR_BOUND_VALID = 1 << 2;

    // Additional v2 clock update flags
    ZX_CLOCK_UPDATE_OPTION_REFERENCE_VALUE_VALID = 1 << 3;
    ZX_CLOCK_UPDATE_OPTION_SYNTHETIC_VALUE_VALID = ZX_CLOCK_UPDATE_OPTION_VALUE_VALID;

    ZX_CLOCK_ARGS_VERSION_1 = 1 << 58;
    ZX_CLOCK_ARGS_VERSION_2 = 2 << 58;
]);

// from //zircon/system/public/zircon/syscalls/exception.h
multiconst!(u32, [
    ZX_EXCEPTION_CHANNEL_DEBUGGER = 1 << 0;
    ZX_EXCEPTION_TARGET_JOB_DEBUGGER = 1 << 0;

    // Returned when probing a thread for its blocked state.
    ZX_EXCEPTION_CHANNEL_TYPE_NONE = 0;
    ZX_EXCEPTION_CHANNEL_TYPE_DEBUGGER = 1;
    ZX_EXCEPTION_CHANNEL_TYPE_THREAD = 2;
    ZX_EXCEPTION_CHANNEL_TYPE_PROCESS = 3;
    ZX_EXCEPTION_CHANNEL_TYPE_JOB = 4;
    ZX_EXCEPTION_CHANNEL_TYPE_JOB_DEBUGGER = 5;
]);

/// A byte used only to control memory alignment. All padding bytes are considered equal
/// regardless of their content.
///
/// Note that the kernel C/C++ struct definitions use explicit padding fields to ensure no implicit
/// padding is added. This is important for security since implicit padding bytes are not always
/// safely initialized. These explicit padding fields are mirrored in the Rust struct definitions
/// to minimize the opportunities for mistakes and inconsistencies.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, Default)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable, IntoBytes))]
pub struct PadByte(u8);

impl PartialEq for PadByte {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Hash for PadByte {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u8(0);
    }
}

impl Debug for PadByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("-")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct zx_clock_create_args_v1_t {
    pub backstop_time: zx_time_t,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct zx_clock_rate_t {
    pub synthetic_ticks: u32,
    pub reference_ticks: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct zx_clock_transformation_t {
    pub reference_offset: i64,
    pub synthetic_offset: i64,
    pub rate: zx_clock_rate_t,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct zx_clock_details_v1_t {
    pub options: u64,
    pub backstop_time: zx_time_t,
    pub reference_ticks_to_synthetic: zx_clock_transformation_t,
    pub reference_to_synthetic: zx_clock_transformation_t,
    pub error_bound: u64,
    pub query_ticks: zx_ticks_t,
    pub last_value_update_ticks: zx_ticks_t,
    pub last_rate_adjust_update_ticks: zx_ticks_t,
    pub last_error_bounds_update_ticks: zx_ticks_t,
    pub generation_counter: u32,
    padding1: [PadByte; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct zx_clock_update_args_v1_t {
    pub rate_adjust: i32,
    padding1: [PadByte; 4],
    pub value: i64,
    pub error_bound: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct zx_clock_update_args_v2_t {
    pub rate_adjust: i32,
    padding1: [PadByte; 4],
    pub synthetic_value: i64,
    pub reference_value: i64,
    pub error_bound: u64,
}

multiconst!(zx_stream_seek_origin_t, [
    ZX_STREAM_SEEK_ORIGIN_START        = 0;
    ZX_STREAM_SEEK_ORIGIN_CURRENT      = 1;
    ZX_STREAM_SEEK_ORIGIN_END          = 2;
]);

// Stream constants
pub const ZX_STREAM_MODE_READ: u32 = 1 << 0;
pub const ZX_STREAM_MODE_WRITE: u32 = 1 << 1;
pub const ZX_STREAM_MODE_APPEND: u32 = 1 << 2;

pub const ZX_STREAM_APPEND: u32 = 1 << 0;

pub const ZX_CPRNG_ADD_ENTROPY_MAX_LEN: usize = 256;

// Socket flags and limits.
pub const ZX_SOCKET_STREAM: u32 = 0;
pub const ZX_SOCKET_DATAGRAM: u32 = 1 << 0;
pub const ZX_SOCKET_DISPOSITION_WRITE_DISABLED: u32 = 1 << 0;
pub const ZX_SOCKET_DISPOSITION_WRITE_ENABLED: u32 = 1 << 1;

// VM Object clone flags
pub const ZX_VMO_CHILD_SNAPSHOT: u32 = 1 << 0;
pub const ZX_VMO_CHILD_SNAPSHOT_AT_LEAST_ON_WRITE: u32 = 1 << 4;
pub const ZX_VMO_CHILD_RESIZABLE: u32 = 1 << 2;
pub const ZX_VMO_CHILD_SLICE: u32 = 1 << 3;
pub const ZX_VMO_CHILD_NO_WRITE: u32 = 1 << 5;
pub const ZX_VMO_CHILD_REFERENCE: u32 = 1 << 6;
pub const ZX_VMO_CHILD_SNAPSHOT_MODIFIED: u32 = 1 << 7;

// channel write size constants
pub const ZX_CHANNEL_MAX_MSG_HANDLES: u32 = 64;
pub const ZX_CHANNEL_MAX_MSG_BYTES: u32 = 65536;
pub const ZX_CHANNEL_MAX_MSG_IOVEC: u32 = 8192;

// fifo write size constants
pub const ZX_FIFO_MAX_SIZE_BYTES: u32 = 4096;

// Min/max page size constants
#[cfg(target_arch = "x86_64")]
pub const ZX_MIN_PAGE_SHIFT: u32 = 12;
#[cfg(target_arch = "x86_64")]
pub const ZX_MAX_PAGE_SHIFT: u32 = 21;

#[cfg(target_arch = "aarch64")]
pub const ZX_MIN_PAGE_SHIFT: u32 = 12;
#[cfg(target_arch = "aarch64")]
pub const ZX_MAX_PAGE_SHIFT: u32 = 16;

#[cfg(target_arch = "riscv64")]
pub const ZX_MIN_PAGE_SHIFT: u32 = 12;
#[cfg(target_arch = "riscv64")]
pub const ZX_MAX_PAGE_SHIFT: u32 = 21;

// Task response codes if a process is externally killed
pub const ZX_TASK_RETCODE_SYSCALL_KILL: i64 = -1024;
pub const ZX_TASK_RETCODE_OOM_KILL: i64 = -1025;
pub const ZX_TASK_RETCODE_POLICY_KILL: i64 = -1026;
pub const ZX_TASK_RETCODE_VDSO_KILL: i64 = -1027;
pub const ZX_TASK_RETCODE_EXCEPTION_KILL: i64 = -1028;

// Resource flags.
pub const ZX_RSRC_FLAG_EXCLUSIVE: zx_rsrc_flags_t = 0x00010000;

// Topics for CPU performance info syscalls
pub const ZX_CPU_PERF_SCALE: u32 = 1;
pub const ZX_CPU_DEFAULT_PERF_SCALE: u32 = 2;
pub const ZX_CPU_PERF_LIMIT: u32 = 3;

// Perf limit types.
pub const ZX_CPU_PERF_LIMIT_TYPE_RATE: u32 = 0;
pub const ZX_CPU_PERF_LIMIT_TYPE_POWER: u32 = 1;

// Cache policy flags.
pub const ZX_CACHE_POLICY_CACHED: u32 = 0;
pub const ZX_CACHE_POLICY_UNCACHED: u32 = 1;
pub const ZX_CACHE_POLICY_UNCACHED_DEVICE: u32 = 2;
pub const ZX_CACHE_POLICY_WRITE_COMBINING: u32 = 3;

// Flag bits for zx_cache_flush.
multiconst!(u32, [
    ZX_CACHE_FLUSH_INSN         = 1 << 0;
    ZX_CACHE_FLUSH_DATA         = 1 << 1;
    ZX_CACHE_FLUSH_INVALIDATE   = 1 << 2;
]);

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_wait_item_t {
    pub handle: zx_handle_t,
    pub waitfor: zx_signals_t,
    pub pending: zx_signals_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_waitset_result_t {
    pub cookie: u64,
    pub status: zx_status_t,
    pub observed: zx_signals_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_handle_info_t {
    pub handle: zx_handle_t,
    pub ty: zx_obj_type_t,
    pub rights: zx_rights_t,
    pub unused: u32,
}

pub const ZX_CHANNEL_READ_MAY_DISCARD: u32 = 1;
pub const ZX_CHANNEL_WRITE_USE_IOVEC: u32 = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_channel_call_args_t {
    pub wr_bytes: *const u8,
    pub wr_handles: *const zx_handle_t,
    pub rd_bytes: *mut u8,
    pub rd_handles: *mut zx_handle_t,
    pub wr_num_bytes: u32,
    pub wr_num_handles: u32,
    pub rd_num_bytes: u32,
    pub rd_num_handles: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_channel_call_etc_args_t {
    pub wr_bytes: *const u8,
    pub wr_handles: *mut zx_handle_disposition_t,
    pub rd_bytes: *mut u8,
    pub rd_handles: *mut zx_handle_info_t,
    pub wr_num_bytes: u32,
    pub wr_num_handles: u32,
    pub rd_num_bytes: u32,
    pub rd_num_handles: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_channel_iovec_t {
    pub buffer: *const u8,
    pub capacity: u32,
    padding1: [PadByte; 4],
}

impl Default for zx_channel_iovec_t {
    fn default() -> Self {
        Self {
            buffer: core::ptr::null(),
            capacity: Default::default(),
            padding1: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_handle_disposition_t {
    pub operation: zx_handle_op_t,
    pub handle: zx_handle_t,
    pub type_: zx_obj_type_t,
    pub rights: zx_rights_t,
    pub result: zx_status_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct zx_iovec_t {
    pub buffer: *const u8,
    pub capacity: usize,
}

pub type zx_pci_irq_swizzle_lut_t = [[[u32; 4]; 8]; 32];

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_pci_init_arg_t {
    pub dev_pin_to_global_irq: zx_pci_irq_swizzle_lut_t,
    pub num_irqs: u32,
    pub irqs: [zx_irq_t; 32],
    pub ecam_window_count: u32,
    // Note: the ecam_windows field is actually a variable size array.
    // We use a fixed size array to match the C repr.
    pub ecam_windows: [zx_ecam_window_t; 1],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_irq_t {
    pub global_irq: u32,
    pub level_triggered: bool,
    pub active_high: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_ecam_window_t {
    pub base: u64,
    pub size: usize,
    pub bus_start: u8,
    pub bus_end: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_pcie_device_info_t {
    pub vendor_id: u16,
    pub device_id: u16,
    pub base_class: u8,
    pub sub_class: u8,
    pub program_interface: u8,
    pub revision_id: u8,
    pub bus_id: u8,
    pub dev_id: u8,
    pub func_id: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_pci_resource_t {
    pub type_: u32,
    pub size: usize,
    // TODO: Actually a union
    pub pio_addr: usize,
}

// TODO: Actually a union
pub type zx_rrec_t = [u8; 64];

// Ports V2
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum zx_packet_type_t {
    ZX_PKT_TYPE_USER = 0,
    ZX_PKT_TYPE_SIGNAL_ONE = 1,
    ZX_PKT_TYPE_GUEST_BELL = 3,
    ZX_PKT_TYPE_GUEST_MEM = 4,
    ZX_PKT_TYPE_GUEST_IO = 5,
    ZX_PKT_TYPE_GUEST_VCPU = 6,
    ZX_PKT_TYPE_INTERRUPT = 7,
    ZX_PKT_TYPE_GUEST_EXCEPTION = 8,
    ZX_PKT_TYPE_PAGE_REQUEST = 9,
    ZX_PKT_TYPE_PROCESSOR_POWER_LEVEL_TRANSITION_REQUEST = 10,
    ZX_PKT_TYPE_GUEST_MSR = 0x0B,
    ZX_PKT_TYPE_GUEST_HYPERCALL = 0x0C,
    ZX_PKT_TYPE_GUEST_HALT = 0x0D,
    ZX_PKT_TYPE_GUEST_EOI = 0x0E,
    ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION = 0x0F,
    ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET = 0x10,
    ZX_PKT_TYPE_GUEST_MEMORY_ACCESS = 0x11,
    ZX_PKT_TYPE_GUEST_INTEL_PT = 0x12,
    ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT = 0x13,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Default for zx_packet_type_t {
    fn default() -> Self {
        zx_packet_type_t::ZX_PKT_TYPE_USER
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub enum zx_packet_guest_vcpu_type_t {
    #[default]
    ZX_PKT_GUEST_VCPU_INTERRUPT = 0,
    ZX_PKT_GUEST_VCPU_STARTUP = 1,
    #[doc(hidden)]
    __Nonexhaustive,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_signal_t {
    pub trigger: zx_signals_t,
    pub observed: zx_signals_t,
    pub count: u64,
    pub timestamp: zx_time_t,
}

pub const ZX_WAIT_ASYNC_TIMESTAMP: u32 = 1;
pub const ZX_WAIT_ASYNC_EDGE: u32 = 2;
pub const ZX_WAIT_ASYNC_BOOT_TIMESTAMP: u32 = 4;

// Actually a union of different integer types, but this should be good enough.
pub type zx_packet_user_t = [u8; 32];

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_port_packet_t {
    pub key: u64,
    pub packet_type: zx_packet_type_t,
    pub status: i32,
    pub union: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_bell_t {
    pub addr: zx_gpaddr_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_io_t {
    pub port: u16,
    pub access_size: u8,
    pub input: bool,
    pub data: [u8; 4],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable))]
pub struct zx_packet_guest_vcpu_interrupt_t {
    pub mask: u64,
    pub vector: u8,
    padding1: [PadByte; 7],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable))]
pub struct zx_packet_guest_vcpu_startup_t {
    pub id: u64,
    pub entry: zx_gpaddr_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable))]
pub union zx_packet_guest_vcpu_union_t {
    pub interrupt: zx_packet_guest_vcpu_interrupt_t,
    pub startup: zx_packet_guest_vcpu_startup_t,
}

#[cfg(feature = "zerocopy")]
impl Default for zx_packet_guest_vcpu_union_t {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct zx_packet_guest_vcpu_t {
    pub r#type: zx_packet_guest_vcpu_type_t,
    padding1: [PadByte; 4],
    pub union: zx_packet_guest_vcpu_union_t,
    padding2: [PadByte; 8],
}

impl PartialEq for zx_packet_guest_vcpu_t {
    fn eq(&self, other: &Self) -> bool {
        if self.r#type != other.r#type {
            return false;
        }
        match self.r#type {
            zx_packet_guest_vcpu_type_t::ZX_PKT_GUEST_VCPU_INTERRUPT => unsafe {
                self.union.interrupt == other.union.interrupt
            },
            zx_packet_guest_vcpu_type_t::ZX_PKT_GUEST_VCPU_STARTUP => unsafe {
                self.union.startup == other.union.startup
            },
            // No equality relationship is defined for invalid types.
            _ => false,
        }
    }
}

impl Eq for zx_packet_guest_vcpu_t {}

impl Debug for zx_packet_guest_vcpu_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.r#type {
            zx_packet_guest_vcpu_type_t::ZX_PKT_GUEST_VCPU_INTERRUPT => {
                write!(f, "type: {:?} union: {:?}", self.r#type, unsafe { self.union.interrupt })
            }
            zx_packet_guest_vcpu_type_t::ZX_PKT_GUEST_VCPU_STARTUP => {
                write!(f, "type: {:?} union: {:?}", self.r#type, unsafe { self.union.startup })
            }
            _ => panic!("unexpected VCPU packet type"),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct zx_packet_page_request_t {
    pub command: zx_page_request_command_t,
    pub flags: u16,
    padding1: [PadByte; 4],
    pub offset: u64,
    pub length: u64,
    padding2: [PadByte; 8],
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub enum zx_page_request_command_t {
    #[default]
    ZX_PAGER_VMO_READ = 0x0000,
    ZX_PAGER_VMO_COMPLETE = 0x0001,
    ZX_PAGER_VMO_DIRTY = 0x0002,
    #[doc(hidden)]
    __Nonexhaustive,
}

multiconst!(u32, [
    ZX_PAGER_OP_FAIL = 1;
    ZX_PAGER_OP_DIRTY = 2;
    ZX_PAGER_OP_WRITEBACK_BEGIN = 3;
    ZX_PAGER_OP_WRITEBACK_END = 4;
]);

pub type zx_excp_type_t = u32;

multiconst!(zx_excp_type_t, [
    ZX_EXCP_GENERAL               = 0x008;
    ZX_EXCP_FATAL_PAGE_FAULT      = 0x108;
    ZX_EXCP_UNDEFINED_INSTRUCTION = 0x208;
    ZX_EXCP_SW_BREAKPOINT         = 0x308;
    ZX_EXCP_HW_BREAKPOINT         = 0x408;
    ZX_EXCP_UNALIGNED_ACCESS      = 0x508;

    ZX_EXCP_SYNTH                 = 0x8000;

    ZX_EXCP_THREAD_STARTING       = 0x008 | ZX_EXCP_SYNTH;
    ZX_EXCP_THREAD_EXITING        = 0x108 | ZX_EXCP_SYNTH;
    ZX_EXCP_POLICY_ERROR          = 0x208 | ZX_EXCP_SYNTH;
    ZX_EXCP_PROCESS_STARTING      = 0x308 | ZX_EXCP_SYNTH;
    ZX_EXCP_USER                  = 0x309 | ZX_EXCP_SYNTH;
]);

multiconst!(u32, [
    ZX_EXCP_USER_CODE_PROCESS_NAME_CHANGED = 0x0001;

    ZX_EXCP_USER_CODE_USER0                = 0xF000;
    ZX_EXCP_USER_CODE_USER1                = 0xF001;
    ZX_EXCP_USER_CODE_USER2                = 0xF002;
]);

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable, IntoBytes))]
pub struct zx_exception_info_t {
    pub pid: zx_koid_t,
    pub tid: zx_koid_t,
    pub type_: zx_excp_type_t,
    padding1: [PadByte; 4],
}

#[repr(C)]
#[derive(Default, Copy, Clone, Eq, PartialEq, KnownLayout, FromBytes, Immutable)]
pub struct zx_x86_64_exc_data_t {
    pub vector: u64,
    pub err_code: u64,
    pub cr2: u64,
}

impl Debug for zx_x86_64_exc_data_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vector 0x{:x} err_code {} cr2 0x{:x}", self.vector, self.err_code, self.cr2)
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone, Eq, PartialEq, FromBytes, Immutable)]
pub struct zx_arm64_exc_data_t {
    pub esr: u32,
    padding1: [PadByte; 4],
    pub far: u64,
    padding2: [PadByte; 8],
}

impl Debug for zx_arm64_exc_data_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "esr 0x{:x} far 0x{:x}", self.esr, self.far)
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone, Eq, PartialEq, FromBytes, Immutable)]
pub struct zx_riscv64_exc_data_t {
    pub cause: u64,
    pub tval: u64,
    padding1: [PadByte; 8],
}

impl Debug for zx_riscv64_exc_data_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cause {} tval {}", self.cause, self.tval)
    }
}

#[repr(C)]
#[derive(Copy, Clone, KnownLayout, FromBytes, Immutable)]
pub union zx_exception_header_arch_t {
    pub x86_64: zx_x86_64_exc_data_t,
    pub arm_64: zx_arm64_exc_data_t,
    pub riscv_64: zx_riscv64_exc_data_t,
}

impl Debug for zx_exception_header_arch_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zx_exception_header_arch_t ")?;
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Exception reports are presumed to be from the target architecture.
            // Even if it was not, it's sound to treat the union as another variant as
            // the size and alignment are the same, there is no internal padding, and
            // the variants have no validity invariants.
            let x86_64 = unsafe { self.x86_64 };
            write!(f, "{x86_64:?}")
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Exception reports are presumed to be from the target architecture.
            // Even if it was not, it's sound to treat the union as another variant as
            // the size and alignment are the same, there is no internal padding, and
            // the variants have no validity invariants.
            let arm_64 = unsafe { self.arm_64 };
            write!(f, "{arm_64:?}")
        }
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: Exception reports are presumed to be from the target architecture.
            // Even if it was not, it's sound to treat the union as another variant as
            // the size and alignment are the same, there is no internal padding, and
            // the variants have no validity invariants.
            let riscv_64 = unsafe { self.riscv_64 };
            write!(f, "{riscv_64:?}")
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, KnownLayout, FromBytes, Immutable)]
pub struct zx_exception_header_t {
    pub size: u32,
    pub type_: zx_excp_type_t,
}

pub type zx_excp_policy_code_t = u32;

multiconst!(zx_excp_policy_code_t, [
    ZX_EXCP_POLICY_CODE_BAD_HANDLE              = 0;
    ZX_EXCP_POLICY_CODE_WRONG_OBJECT            = 1;
    ZX_EXCP_POLICY_CODE_VMAR_WX                 = 2;
    ZX_EXCP_POLICY_CODE_NEW_ANY                 = 3;
    ZX_EXCP_POLICY_CODE_NEW_VMO                 = 4;
    ZX_EXCP_POLICY_CODE_NEW_CHANNEL             = 5;
    ZX_EXCP_POLICY_CODE_NEW_EVENT               = 6;
    ZX_EXCP_POLICY_CODE_NEW_EVENTPAIR           = 7;
    ZX_EXCP_POLICY_CODE_NEW_PORT                = 8;
    ZX_EXCP_POLICY_CODE_NEW_SOCKET              = 9;
    ZX_EXCP_POLICY_CODE_NEW_FIFO                = 10;
    ZX_EXCP_POLICY_CODE_NEW_TIMER               = 11;
    ZX_EXCP_POLICY_CODE_NEW_PROCESS             = 12;
    ZX_EXCP_POLICY_CODE_NEW_PROFILE             = 13;
    ZX_EXCP_POLICY_CODE_NEW_PAGER               = 14;
    ZX_EXCP_POLICY_CODE_AMBIENT_MARK_VMO_EXEC   = 15;
    ZX_EXCP_POLICY_CODE_CHANNEL_FULL_WRITE      = 16;
    ZX_EXCP_POLICY_CODE_PORT_TOO_MANY_PACKETS   = 17;
    ZX_EXCP_POLICY_CODE_BAD_SYSCALL             = 18;
    ZX_EXCP_POLICY_CODE_PORT_TOO_MANY_OBSERVERS = 19;
    ZX_EXCP_POLICY_CODE_HANDLE_LEAK             = 20;
    ZX_EXCP_POLICY_CODE_NEW_IOB                 = 21;
]);

#[repr(C)]
#[derive(Debug, Copy, Clone, KnownLayout, FromBytes, Immutable)]
pub struct zx_exception_context_t {
    pub arch: zx_exception_header_arch_t,
    pub synth_code: zx_excp_policy_code_t,
    pub synth_data: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, KnownLayout, FromBytes, Immutable)]
pub struct zx_exception_report_t {
    pub header: zx_exception_header_t,
    pub context: zx_exception_context_t,
}

pub type zx_exception_state_t = u32;

multiconst!(zx_exception_state_t, [
    ZX_EXCEPTION_STATE_TRY_NEXT    = 0;
    ZX_EXCEPTION_STATE_HANDLED     = 1;
    ZX_EXCEPTION_STATE_THREAD_EXIT = 2;
]);

pub type zx_exception_strategy_t = u32;

multiconst!(zx_exception_state_t, [
    ZX_EXCEPTION_STRATEGY_FIRST_CHANCE   = 0;
    ZX_EXCEPTION_STRATEGY_SECOND_CHANCE  = 1;
]);

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default, Copy, Clone, Eq, PartialEq, KnownLayout, FromBytes, Immutable)]
pub struct zx_thread_state_general_regs_t {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

#[cfg(target_arch = "x86_64")]
impl core::fmt::Debug for zx_thread_state_general_regs_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("rax", &format_args!("{:#x}", self.rax))
            .field("rbx", &format_args!("{:#x}", self.rbx))
            .field("rcx", &format_args!("{:#x}", self.rcx))
            .field("rdx", &format_args!("{:#x}", self.rdx))
            .field("rsi", &format_args!("{:#x}", self.rsi))
            .field("rdi", &format_args!("{:#x}", self.rdi))
            .field("rbp", &format_args!("{:#x}", self.rbp))
            .field("rsp", &format_args!("{:#x}", self.rsp))
            .field("r8", &format_args!("{:#x}", self.r8))
            .field("r9", &format_args!("{:#x}", self.r9))
            .field("r10", &format_args!("{:#x}", self.r10))
            .field("r11", &format_args!("{:#x}", self.r11))
            .field("r12", &format_args!("{:#x}", self.r12))
            .field("r13", &format_args!("{:#x}", self.r13))
            .field("r14", &format_args!("{:#x}", self.r14))
            .field("r15", &format_args!("{:#x}", self.r15))
            .field("rip", &format_args!("{:#x}", self.rip))
            .field("rflags", &format_args!("{:#x}", self.rflags))
            .field("fs_base", &format_args!("{:#x}", self.fs_base))
            .field("gs_base", &format_args!("{:#x}", self.gs_base))
            .finish()
    }
}

#[cfg(target_arch = "x86_64")]
impl From<&zx_restricted_state_t> for zx_thread_state_general_regs_t {
    fn from(state: &zx_restricted_state_t) -> Self {
        Self {
            rdi: state.rdi,
            rsi: state.rsi,
            rbp: state.rbp,
            rbx: state.rbx,
            rdx: state.rdx,
            rcx: state.rcx,
            rax: state.rax,
            rsp: state.rsp,
            r8: state.r8,
            r9: state.r9,
            r10: state.r10,
            r11: state.r11,
            r12: state.r12,
            r13: state.r13,
            r14: state.r14,
            r15: state.r15,
            rip: state.ip,
            rflags: state.flags,
            fs_base: state.fs_base,
            gs_base: state.gs_base,
        }
    }
}

#[cfg(target_arch = "aarch64")]
multiconst!(u64, [
    ZX_REG_CPSR_ARCH_32_MASK = 0x10;
    ZX_REG_CPSR_THUMB_MASK = 0x20;
]);

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_thread_state_general_regs_t {
    pub r: [u64; 30],
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u64,
    pub tpidr: u64,
}

#[cfg(target_arch = "aarch64")]
impl core::fmt::Debug for zx_thread_state_general_regs_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct RegisterAsHex(u64);
        impl core::fmt::Debug for RegisterAsHex {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        f.debug_struct(core::any::type_name::<Self>())
            .field("r", &self.r.map(RegisterAsHex))
            .field("lr", &format_args!("{:#x}", self.lr))
            .field("sp", &format_args!("{:#x}", self.sp))
            .field("pc", &format_args!("{:#x}", self.pc))
            .field("cpsr", &format_args!("{:#x}", self.cpsr))
            .field("tpidr", &format_args!("{:#x}", self.tpidr))
            .finish()
    }
}

#[cfg(target_arch = "aarch64")]
impl From<&zx_restricted_state_t> for zx_thread_state_general_regs_t {
    fn from(state: &zx_restricted_state_t) -> Self {
        if state.cpsr as u64 & ZX_REG_CPSR_ARCH_32_MASK == ZX_REG_CPSR_ARCH_32_MASK {
            // aarch32
            Self {
                r: [
                    state.r[0],
                    state.r[1],
                    state.r[2],
                    state.r[3],
                    state.r[4],
                    state.r[5],
                    state.r[6],
                    state.r[7],
                    state.r[8],
                    state.r[9],
                    state.r[10],
                    state.r[11],
                    state.r[12],
                    state.r[13],
                    state.r[14],
                    state.pc, // ELR overwrites this.
                    state.r[16],
                    state.r[17],
                    state.r[18],
                    state.r[19],
                    state.r[20],
                    state.r[21],
                    state.r[22],
                    state.r[23],
                    state.r[24],
                    state.r[25],
                    state.r[26],
                    state.r[27],
                    state.r[28],
                    state.r[29],
                ],
                lr: state.r[14], // R[14] for aarch32
                sp: state.r[13], // R[13] for aarch32
                // TODO(https://fxbug.dev/379669623) Should it be checked for thumb and make
                // sure it isn't over incrementing?
                pc: state.pc, // Zircon populated this from elr.
                cpsr: state.cpsr as u64,
                tpidr: state.tpidr_el0,
            }
        } else {
            Self {
                r: [
                    state.r[0],
                    state.r[1],
                    state.r[2],
                    state.r[3],
                    state.r[4],
                    state.r[5],
                    state.r[6],
                    state.r[7],
                    state.r[8],
                    state.r[9],
                    state.r[10],
                    state.r[11],
                    state.r[12],
                    state.r[13],
                    state.r[14],
                    state.r[15],
                    state.r[16],
                    state.r[17],
                    state.r[18],
                    state.r[19],
                    state.r[20],
                    state.r[21],
                    state.r[22],
                    state.r[23],
                    state.r[24],
                    state.r[25],
                    state.r[26],
                    state.r[27],
                    state.r[28],
                    state.r[29],
                ],
                lr: state.r[30],
                sp: state.sp,
                pc: state.pc,
                cpsr: state.cpsr as u64,
                tpidr: state.tpidr_el0,
            }
        }
    }
}

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_thread_state_general_regs_t {
    pub pc: u64,
    pub ra: u64,  // x1
    pub sp: u64,  // x2
    pub gp: u64,  // x3
    pub tp: u64,  // x4
    pub t0: u64,  // x5
    pub t1: u64,  // x6
    pub t2: u64,  // x7
    pub s0: u64,  // x8
    pub s1: u64,  // x9
    pub a0: u64,  // x10
    pub a1: u64,  // x11
    pub a2: u64,  // x12
    pub a3: u64,  // x13
    pub a4: u64,  // x14
    pub a5: u64,  // x15
    pub a6: u64,  // x16
    pub a7: u64,  // x17
    pub s2: u64,  // x18
    pub s3: u64,  // x19
    pub s4: u64,  // x20
    pub s5: u64,  // x21
    pub s6: u64,  // x22
    pub s7: u64,  // x23
    pub s8: u64,  // x24
    pub s9: u64,  // x25
    pub s10: u64, // x26
    pub s11: u64, // x27
    pub t3: u64,  // x28
    pub t4: u64,  // x29
    pub t5: u64,  // x30
    pub t6: u64,  // x31
}

#[cfg(target_arch = "riscv64")]
impl core::fmt::Debug for zx_thread_state_general_regs_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .field("pc", &format_args!("{:#x}", self.pc))
            .field("ra", &format_args!("{:#x}", self.ra)) // x1
            .field("sp", &format_args!("{:#x}", self.sp)) // x2
            .field("gp", &format_args!("{:#x}", self.gp)) // x3
            .field("tp", &format_args!("{:#x}", self.tp)) // x4
            .field("t0", &format_args!("{:#x}", self.t0)) // x5
            .field("t1", &format_args!("{:#x}", self.t1)) // x6
            .field("t2", &format_args!("{:#x}", self.t2)) // x7
            .field("s0", &format_args!("{:#x}", self.s0)) // x8
            .field("s1", &format_args!("{:#x}", self.s1)) // x9
            .field("a0", &format_args!("{:#x}", self.a0)) // x10
            .field("a1", &format_args!("{:#x}", self.a1)) // x11
            .field("a2", &format_args!("{:#x}", self.a2)) // x12
            .field("a3", &format_args!("{:#x}", self.a3)) // x13
            .field("a4", &format_args!("{:#x}", self.a4)) // x14
            .field("a5", &format_args!("{:#x}", self.a5)) // x15
            .field("a6", &format_args!("{:#x}", self.a6)) // x16
            .field("a7", &format_args!("{:#x}", self.a7)) // x17
            .field("s2", &format_args!("{:#x}", self.s2)) // x18
            .field("s3", &format_args!("{:#x}", self.s3)) // x19
            .field("s4", &format_args!("{:#x}", self.s4)) // x20
            .field("s5", &format_args!("{:#x}", self.s5)) // x21
            .field("s6", &format_args!("{:#x}", self.s6)) // x22
            .field("s7", &format_args!("{:#x}", self.s7)) // x23
            .field("s8", &format_args!("{:#x}", self.s8)) // x24
            .field("s9", &format_args!("{:#x}", self.s9)) // x25
            .field("s10", &format_args!("{:#x}", self.s10)) // x26
            .field("s11", &format_args!("{:#x}", self.s11)) // x27
            .field("t3", &format_args!("{:#x}", self.t3)) // x28
            .field("t4", &format_args!("{:#x}", self.t4)) // x29
            .field("t5", &format_args!("{:#x}", self.t5)) // x30
            .field("t6", &format_args!("{:#x}", self.t6)) // x31
            .finish()
    }
}

multiconst!(zx_restricted_reason_t, [
    ZX_RESTRICTED_REASON_SYSCALL = 0;
    ZX_RESTRICTED_REASON_EXCEPTION = 1;
    ZX_RESTRICTED_REASON_KICK = 2;
    ZX_RESTRICTED_REASON_EXCEPTION_LOST = 3;
]);

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_restricted_state_t {
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub ip: u64,
    pub flags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

#[cfg(target_arch = "x86_64")]
impl From<&zx_thread_state_general_regs_t> for zx_restricted_state_t {
    fn from(registers: &zx_thread_state_general_regs_t) -> Self {
        Self {
            rdi: registers.rdi,
            rsi: registers.rsi,
            rbp: registers.rbp,
            rbx: registers.rbx,
            rdx: registers.rdx,
            rcx: registers.rcx,
            rax: registers.rax,
            rsp: registers.rsp,
            r8: registers.r8,
            r9: registers.r9,
            r10: registers.r10,
            r11: registers.r11,
            r12: registers.r12,
            r13: registers.r13,
            r14: registers.r14,
            r15: registers.r15,
            ip: registers.rip,
            flags: registers.rflags,
            fs_base: registers.fs_base,
            gs_base: registers.gs_base,
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_restricted_state_t {
    pub r: [u64; 31], // Note: r[30] is `lr` which is separated out in the general regs.
    pub sp: u64,
    pub pc: u64,
    pub tpidr_el0: u64,
    // Contains only the user-controllable upper 4-bits (NZCV).
    pub cpsr: u32,
    padding1: [PadByte; 4],
}

#[cfg(target_arch = "aarch64")]
impl From<&zx_thread_state_general_regs_t> for zx_restricted_state_t {
    fn from(registers: &zx_thread_state_general_regs_t) -> Self {
        Self {
            r: [
                registers.r[0],
                registers.r[1],
                registers.r[2],
                registers.r[3],
                registers.r[4],
                registers.r[5],
                registers.r[6],
                registers.r[7],
                registers.r[8],
                registers.r[9],
                registers.r[10],
                registers.r[11],
                registers.r[12],
                registers.r[13],
                registers.r[14],
                registers.r[15],
                registers.r[16],
                registers.r[17],
                registers.r[18],
                registers.r[19],
                registers.r[20],
                registers.r[21],
                registers.r[22],
                registers.r[23],
                registers.r[24],
                registers.r[25],
                registers.r[26],
                registers.r[27],
                registers.r[28],
                registers.r[29],
                registers.lr, // for compat this works nicely with zircon.
            ],
            pc: registers.pc,
            tpidr_el0: registers.tpidr,
            sp: registers.sp,
            cpsr: registers.cpsr as u32,
            padding1: Default::default(),
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub type zx_restricted_state_t = zx_thread_state_general_regs_t;

#[cfg(target_arch = "riscv64")]
impl From<&zx_thread_state_general_regs_t> for zx_restricted_state_t {
    fn from(registers: &zx_thread_state_general_regs_t) -> Self {
        *registers
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "riscv64"))]
pub struct zx_restricted_syscall_t {
    pub state: zx_restricted_state_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "riscv64"))]
pub struct zx_restricted_exception_t {
    pub state: zx_restricted_state_t,
    pub exception: zx_exception_report_t,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_state_t {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Contains only the user-controllable lower 32-bits.
    pub rflags: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_state_t {
    pub x: [u64; 31],
    pub sp: u64,
    // Contains only the user-controllable upper 4-bits (NZCV).
    pub cpsr: u32,
    padding1: [PadByte; 4],
}

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_state_t {
    pub empty: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_vcpu_io_t {
    pub access_size: u8,
    padding1: [PadByte; 3],
    pub data: [u8; 4],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_mem_t {
    pub addr: zx_gpaddr_t,
    pub access_size: u8,
    pub sign_extend: bool,
    pub xt: u8,
    pub read: bool,
    pub data: u64,
}

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_mem_t {
    pub addr: zx_gpaddr_t,
    padding1: [PadByte; 24],
}

pub const X86_MAX_INST_LEN: usize = 15;

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_mem_t {
    pub addr: zx_gpaddr_t,
    pub cr3: zx_gpaddr_t,
    pub rip: zx_vaddr_t,
    pub instruction_size: u8,
    pub default_operand_size: u8,
}

/// Delivered when a guest raises an exception the hypervisor is configured to
/// trap to the host (e.g. an intercepted `INT3`). `rip` is the guest
/// instruction pointer at the exit; for an intercepted `#BP` it is the address
/// of the trapping `INT3` itself.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_exception_t {
    pub rip: u64,
    pub error_code: u64,
    pub vector: u32,
    padding1: [PadByte; 4],
    padding2: [PadByte; 8],
}

/// Delivered when a guest accesses a model-specific register the VMM has
/// claimed via the VCPU's synthetic-MSR delegation. The guest's instruction
/// pointer has already been advanced past the RDMSR/WRMSR.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_msr_t {
    /// The register selected by the guest in ecx.
    pub msr: u64,
    /// For a write, the value the guest supplied in edx:eax. Zero for a read.
    pub value: u64,
    /// True if the guest executed WRMSR, false for RDMSR.
    pub is_write: bool,
    padding1: [PadByte; 7],
    padding2: [PadByte; 8],
}

/// Delivered when a guest issues a hypercall the VMM has claimed. As with a
/// delegated MSR read, RIP is already past the instruction, so the VMM returns
/// a result by writing rax before resuming.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_hypercall_t {
    /// Guest rcx: the call code and flags identifying the requested operation.
    pub input: u64,
    /// Guest rdx: the first operand.
    pub arg0: u64,
    /// Guest r8: the second operand.
    pub arg1: u64,
    padding1: [PadByte; 8],
}

/// Delivered when a guest ends an interrupt whose vector the VMM registered with
/// `zx_guest_set_trap(ZX_GUEST_TRAP_EOI, vector, 1, ..)`.
///
/// The kernel's own local APIC has already consumed the EOI and RIP is already
/// past the WRMSR, so this reports something that has happened; there is nothing
/// to write back before resuming.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_eoi_t {
    /// The vector the guest's EOI ended: the highest vector that was in service.
    pub vector: u64,
    padding1: [PadByte; 24],
}

// Values for `zx_packet_guest_halt_t::reason`.
multiconst!(u32, [
    /// The guest faulted with no usable handler and shut itself down.
    ZX_PKT_GUEST_HALT_TRIPLE_FAULT = 0;
    /// The exit reason had no handler; resuming would retake the same exit.
    ZX_PKT_GUEST_HALT_UNHANDLED    = 1;
]);

/// Delivered when a VCPU stopped in a way it cannot be resumed from.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_halt_t {
    /// One of `ZX_PKT_GUEST_HALT_*`.
    pub reason: u32,
    /// For `ZX_PKT_GUEST_HALT_UNHANDLED`, the architectural exit reason.
    pub exit_reason: u32,
    /// Where the guest was executing when it stopped.
    pub rip: zx_vaddr_t,
    /// Guest-physical address the exit named, for EPT violation (48) and EPT
    /// misconfiguration (49). Zero for every other `exit_reason`.
    pub physical_address: zx_gpaddr_t,
    padding1: [PadByte; 8],
}

multiconst!(u32, [
    ZX_PKT_GUEST_EXIT_OBSERVATION_REASON = 1 << 0;
    ZX_PKT_GUEST_EXIT_OBSERVATION_BUDGET = 1 << 1;
]);

/// One-shot VM-exit boundary delivered after normal handling has completed.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_exit_observation_t {
    pub sequence: u64,
    pub exit_rip: zx_vaddr_t,
    pub resume_rip: zx_vaddr_t,
    pub exit_reason: u32,
    pub flags: u32,
}

const _: () = assert!(core::mem::size_of::<zx_packet_guest_exit_observation_t>() == 32);

/// Guest-only retired-instruction budget result.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_instruction_budget_t {
    pub sequence: u64,
    pub requested_budget: u64,
    pub retired_instructions: u64,
    pub rip: zx_vaddr_t,
}

const _: () = assert!(core::mem::size_of::<zx_packet_guest_instruction_budget_t>() == 32);

/// Guest-global pre-access EPT stop.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_memory_access_t {
    pub sequence: u64,
    pub guest_paddr: zx_gpaddr_t,
    pub guest_vaddr: zx_vaddr_t,
    pub rip: zx_vaddr_t,
}

const _: () = assert!(core::mem::size_of::<zx_packet_guest_memory_access_t>() == 32);

/// One immutable Intel PT watermark or terminal boundary.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_intel_pt_t {
    pub segment_sequence: u64,
    pub trace_generation: u64,
    pub producer_cursor: u64,
    pub status_flags: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<zx_packet_guest_intel_pt_t>() == 32);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_guest_hardware_breakpoint_t {
    pub sequence: u64,
    pub rip: zx_vaddr_t,
    pub condition_mask: u64,
    pub vpid: u16,
    pub slot_mask: u8,
    pub boundary: u8,
    pub reserved: u32,
}

const _: () =
    assert!(core::mem::size_of::<zx_packet_guest_hardware_breakpoint_t>() == 32);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_packet_interrupt_t {
    pub timestamp: zx_time_t,
    padding1: [PadByte; 24],
}

// Helper for constructing topics that have been versioned.
const fn info_topic(topic: u32, version: u32) -> u32 {
    (version << 28) | topic
}

multiconst!(zx_object_info_topic_t, [
    ZX_INFO_NONE                       = 0;
    ZX_INFO_HANDLE_VALID               = 1;
    ZX_INFO_HANDLE_BASIC               = 2;  // zx_info_handle_basic_t[1]
    ZX_INFO_PROCESS                    = info_topic(3, 1);  // zx_info_process_t[1]
    ZX_INFO_PROCESS_THREADS            = 4;  // zx_koid_t[n]
    ZX_INFO_VMAR                       = 7;  // zx_info_vmar_t[1]
    ZX_INFO_JOB_CHILDREN               = 8;  // zx_koid_t[n]
    ZX_INFO_JOB_PROCESSES              = 9;  // zx_koid_t[n]
    ZX_INFO_THREAD                     = 10; // zx_info_thread_t[1]
    ZX_INFO_THREAD_EXCEPTION_REPORT    = info_topic(11, 1); // zx_exception_report_t[1]
    ZX_INFO_TASK_STATS                 = info_topic(12, 1); // zx_info_task_stats_t[1]
    ZX_INFO_PROCESS_MAPS               = info_topic(13, 2); // zx_info_maps_t[n]
    ZX_INFO_PROCESS_VMOS               = info_topic(14, 3); // zx_info_vmo_t[n]
    ZX_INFO_THREAD_STATS               = 15; // zx_info_thread_stats_t[1]
    ZX_INFO_CPU_STATS                  = 16; // zx_info_cpu_stats_t[n]
    ZX_INFO_KMEM_STATS                 = info_topic(17, 1); // zx_info_kmem_stats_t[1]
    ZX_INFO_RESOURCE                   = 18; // zx_info_resource_t[1]
    ZX_INFO_HANDLE_COUNT               = 19; // zx_info_handle_count_t[1]
    ZX_INFO_BTI                        = 20; // zx_info_bti_t[1]
    ZX_INFO_PROCESS_HANDLE_STATS       = 21; // zx_info_process_handle_stats_t[1]
    ZX_INFO_SOCKET                     = 22; // zx_info_socket_t[1]
    ZX_INFO_VMO                        = info_topic(23, 3); // zx_info_vmo_t[1]
    ZX_INFO_JOB                        = 24; // zx_info_job_t[1]
    ZX_INFO_TIMER                      = 25; // zx_info_timer_t[1]
    ZX_INFO_STREAM                     = 26; // zx_info_stream_t[1]
    ZX_INFO_HANDLE_TABLE               = 27; // zx_info_handle_extended_t[n]
    ZX_INFO_MSI                        = 28; // zx_info_msi_t[1]
    ZX_INFO_GUEST_STATS                = 29; // zx_info_guest_stats_t[1]
    ZX_INFO_TASK_RUNTIME               = info_topic(30, 1); // zx_info_task_runtime_t[1]
    ZX_INFO_KMEM_STATS_EXTENDED        = 31; // zx_info_kmem_stats_extended_t[1]
    ZX_INFO_VCPU                       = 32; // zx_info_vcpu_t[1]
    ZX_INFO_KMEM_STATS_COMPRESSION     = 33; // zx_info_kmem_stats_compression_t[1]
    ZX_INFO_IOB                        = 34; // zx_info_iob_t[1]
    ZX_INFO_IOB_REGIONS                = 35; // zx_iob_region_info_t[n]
    ZX_INFO_VMAR_MAPS                  = 36; // zx_info_maps_t[n]
    ZX_INFO_POWER_DOMAINS              = 37; // zx_info_power_domain_info_t[n]
    ZX_INFO_MEMORY_STALL               = 38; // zx_info_memory_stall_t[1]
    ZX_INFO_CLOCK_MAPPED_SIZE          = 40; // usize[1]
]);

multiconst!(zx_system_memory_stall_type_t, [
    ZX_SYSTEM_MEMORY_STALL_SOME        = 0;
    ZX_SYSTEM_MEMORY_STALL_FULL        = 1;
]);

// This macro takes struct-like syntax and creates another macro that can be used to create
// different instances of the struct with different names. This is used to keep struct definitions
// from drifting between this crate and the fuchsia-zircon crate where they are identical other
// than in name and location.
macro_rules! struct_decl_macro {
    ( $(#[$attrs:meta])* $vis:vis struct <$macro_name:ident> $($any:tt)* ) => {
        #[macro_export]
        macro_rules! $macro_name {
            ($name:ident) => {
                $(#[$attrs])* $vis struct $name $($any)*
            }
        }
    }
}

// Don't need struct_decl_macro for this, the wrapper is different.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, Eq, KnownLayout, FromBytes, Immutable, PartialEq)]
pub struct zx_info_handle_basic_t {
    pub koid: zx_koid_t,
    pub rights: zx_rights_t,
    pub type_: zx_obj_type_t,
    pub related_koid: zx_koid_t,
    padding1: [PadByte; 4],
}

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_handle_count_t> {
        pub handle_count: u32,
    }
}

zx_info_handle_count_t!(zx_info_handle_count_t);

// Don't need struct_decl_macro for this, the wrapper is different.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, KnownLayout, FromBytes, Immutable)]
pub struct zx_info_socket_t {
    pub options: u32,
    pub rx_buf_max: usize,
    pub rx_buf_size: usize,
    pub rx_buf_available: usize,
    pub tx_buf_max: usize,
    pub tx_buf_size: usize,
}

multiconst!(u32, [
    ZX_INFO_PROCESS_FLAG_STARTED = 1 << 0;
    ZX_INFO_PROCESS_FLAG_EXITED = 1 << 1;
    ZX_INFO_PROCESS_FLAG_DEBUGGER_ATTACHED = 1 << 2;
]);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_process_t> {
        pub return_code: i64,
        pub start_time: zx_time_t,
        pub flags: u32,
    }
}

zx_info_process_t!(zx_info_process_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_job_t> {
        pub return_code: i64,
        pub exited: u8,
        pub kill_on_oom: u8,
        pub debugger_attached: u8,
    }
}

zx_info_job_t!(zx_info_job_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable)]
    pub struct <zx_info_timer_t> {
        pub options: u32,
        pub clock_id: zx_clock_t,
        pub deadline: zx_time_t,
        pub slack: zx_duration_t,
    }
}

zx_info_timer_t!(zx_info_timer_t);

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_policy_basic {
    pub condition: u32,
    pub policy: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_policy_timer_slack {
    pub min_slack: zx_duration_t,
    pub default_mode: u32,
}

multiconst!(u32, [
    // policy options
    ZX_JOB_POL_RELATIVE = 0;
    ZX_JOB_POL_ABSOLUTE = 1;

    // policy topic
    ZX_JOB_POL_BASIC = 0;
    ZX_JOB_POL_TIMER_SLACK = 1;

    // policy conditions
    ZX_POL_BAD_HANDLE            = 0;
    ZX_POL_WRONG_OBJECT          = 1;
    ZX_POL_VMAR_WX               = 2;
    ZX_POL_NEW_ANY               = 3;
    ZX_POL_NEW_VMO               = 4;
    ZX_POL_NEW_CHANNEL           = 5;
    ZX_POL_NEW_EVENT             = 6;
    ZX_POL_NEW_EVENTPAIR         = 7;
    ZX_POL_NEW_PORT              = 8;
    ZX_POL_NEW_SOCKET            = 9;
    ZX_POL_NEW_FIFO              = 10;
    ZX_POL_NEW_TIMER             = 11;
    ZX_POL_NEW_PROCESS           = 12;
    ZX_POL_NEW_PROFILE           = 13;
    ZX_POL_NEW_PAGER             = 14;
    ZX_POL_AMBIENT_MARK_VMO_EXEC = 15;

    // policy actions
    ZX_POL_ACTION_ALLOW           = 0;
    ZX_POL_ACTION_DENY            = 1;
    ZX_POL_ACTION_ALLOW_EXCEPTION = 2;
    ZX_POL_ACTION_DENY_EXCEPTION  = 3;
    ZX_POL_ACTION_KILL            = 4;

    // timer slack default modes
    ZX_TIMER_SLACK_CENTER = 0;
    ZX_TIMER_SLACK_EARLY  = 1;
    ZX_TIMER_SLACK_LATE   = 2;
]);

multiconst!(u32, [
    // critical options
    ZX_JOB_CRITICAL_PROCESS_RETCODE_NONZERO = 1 << 0;
]);

// Don't use struct_decl_macro, wrapper is different.
#[repr(C)]
#[derive(
    Default, Debug, Copy, Clone, Eq, PartialEq, KnownLayout, FromBytes, Immutable, IntoBytes,
)]
pub struct zx_info_vmo_t {
    pub koid: zx_koid_t,
    pub name: [u8; ZX_MAX_NAME_LEN],
    pub size_bytes: u64,
    pub parent_koid: zx_koid_t,
    pub num_children: usize,
    pub num_mappings: usize,
    pub share_count: usize,
    pub flags: u32,
    padding1: [PadByte; 4],
    pub committed_bytes: u64,
    pub handle_rights: zx_rights_t,
    pub cache_policy: u32,
    pub metadata_bytes: u64,
    pub committed_change_events: u64,
    pub populated_bytes: u64,
    pub committed_private_bytes: u64,
    pub populated_private_bytes: u64,
    pub committed_scaled_bytes: u64,
    pub populated_scaled_bytes: u64,
    pub committed_fractional_scaled_bytes: u64,
    pub populated_fractional_scaled_bytes: u64,
}

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_cpu_stats_t> {
        pub cpu_number: u32,
        pub flags: u32,
        pub idle_time: zx_duration_t,
        pub normalized_busy_time: zx_duration_t,
        pub reschedules: u64,
        pub context_switches: u64,
        pub irq_preempts: u64,
        pub preempts: u64,
        pub yields: u64,
        pub ints: u64,
        pub timer_ints: u64,
        pub timers: u64,
        pub page_faults: u64,
        pub exceptions: u64,
        pub syscalls: u64,
        pub reschedule_ipis: u64,
        pub generic_ipis: u64,
        pub active_energy_consumption_nj: u64,
        pub idle_energy_consumption_nj: u64,
    }
}

zx_info_cpu_stats_t!(zx_info_cpu_stats_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_kmem_stats_t> {
        pub total_bytes: u64,
        pub free_bytes: u64,
        pub free_loaned_bytes: u64,
        pub wired_bytes: u64,
        pub total_heap_bytes: u64,
        pub free_heap_bytes: u64,
        pub vmo_bytes: u64,
        pub mmu_overhead_bytes: u64,
        pub ipc_bytes: u64,
        pub cache_bytes: u64,
        pub slab_bytes: u64,
        pub zram_bytes: u64,
        pub other_bytes: u64,
        pub vmo_reclaim_total_bytes: u64,
        pub vmo_reclaim_newest_bytes: u64,
        pub vmo_reclaim_oldest_bytes: u64,
        pub vmo_reclaim_disabled_bytes: u64,
        pub vmo_discardable_locked_bytes: u64,
        pub vmo_discardable_unlocked_bytes: u64,
    }
}

zx_info_kmem_stats_t!(zx_info_kmem_stats_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_kmem_stats_extended_t> {
        pub total_bytes: u64,
        pub free_bytes: u64,
        pub wired_bytes: u64,
        pub total_heap_bytes: u64,
        pub free_heap_bytes: u64,
        pub vmo_bytes: u64,
        pub vmo_pager_total_bytes: u64,
        pub vmo_pager_newest_bytes: u64,
        pub vmo_pager_oldest_bytes: u64,
        pub vmo_discardable_locked_bytes: u64,
        pub vmo_discardable_unlocked_bytes: u64,
        pub mmu_overhead_bytes: u64,
        pub ipc_bytes: u64,
        pub other_bytes: u64,
        pub vmo_reclaim_disable_bytes: u64,
    }
}

zx_info_kmem_stats_extended_t!(zx_info_kmem_stats_extended_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_kmem_stats_compression_t> {
        pub uncompressed_storage_bytes: u64,
        pub compressed_storage_bytes: u64,
        pub compressed_fragmentation_bytes: u64,
        pub compression_time: zx_duration_t,
        pub decompression_time: zx_duration_t,
        pub total_page_compression_attempts: u64,
        pub failed_page_compression_attempts: u64,
        pub total_page_decompressions: u64,
        pub compressed_page_evictions: u64,
        pub eager_page_compressions: u64,
        pub memory_pressure_page_compressions: u64,
        pub critical_memory_page_compressions: u64,
        pub pages_decompressed_unit_ns: u64,
        pub pages_decompressed_within_log_time: [u64; 8],
    }
}

zx_info_kmem_stats_compression_t!(zx_info_kmem_stats_compression_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_resource_t> {
        pub kind: u32,
        pub flags: u32,
        pub base: u64,
        pub size: usize,
        pub name: [u8; ZX_MAX_NAME_LEN],
    }
}

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable)]
    pub struct <zx_info_bti_t> {
        pub minimum_contiguity: u64,
        pub aspace_size: u64,
        pub pmo_count: u64,
        pub quarantine_count: u64,
    }
}

zx_info_bti_t!(zx_info_bti_t);

pub type zx_thread_state_t = u32;

multiconst!(zx_thread_state_t, [
    ZX_THREAD_STATE_NEW = 0x0000;
    ZX_THREAD_STATE_RUNNING = 0x0001;
    ZX_THREAD_STATE_SUSPENDED = 0x0002;
    ZX_THREAD_STATE_BLOCKED = 0x0003;
    ZX_THREAD_STATE_DYING = 0x0004;
    ZX_THREAD_STATE_DEAD = 0x0005;
    ZX_THREAD_STATE_BLOCKED_EXCEPTION = 0x0103;
    ZX_THREAD_STATE_BLOCKED_SLEEPING = 0x0203;
    ZX_THREAD_STATE_BLOCKED_FUTEX = 0x0303;
    ZX_THREAD_STATE_BLOCKED_PORT = 0x0403;
    ZX_THREAD_STATE_BLOCKED_CHANNEL = 0x0503;
    ZX_THREAD_STATE_BLOCKED_WAIT_ONE = 0x0603;
    ZX_THREAD_STATE_BLOCKED_WAIT_MANY = 0x0703;
    ZX_THREAD_STATE_BLOCKED_INTERRUPT = 0x0803;
    ZX_THREAD_STATE_BLOCKED_PAGER = 0x0903;
]);

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, zerocopy::FromBytes, zerocopy::Immutable)]
pub struct zx_info_thread_t {
    pub state: zx_thread_state_t,
    pub wait_exception_channel_type: u32,
    pub cpu_affinity_mask: zx_cpu_set_t,
}

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_thread_stats_t> {
        pub total_runtime: zx_duration_t,
        pub last_scheduled_cpu: u32,
    }
}

zx_info_thread_stats_t!(zx_info_thread_stats_t);

zx_info_resource_t!(zx_info_resource_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_vmar_t> {
        pub base: usize,
        pub len: usize,
    }
}

zx_info_vmar_t!(zx_info_vmar_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_task_stats_t> {
        pub mem_mapped_bytes: usize,
        pub mem_private_bytes: usize,
        pub mem_shared_bytes: usize,
        pub mem_scaled_shared_bytes: usize,
        pub mem_fractional_scaled_shared_bytes: u64,
    }
}

zx_info_task_stats_t!(zx_info_task_stats_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_task_runtime_t> {
        pub cpu_time: zx_duration_t,
        pub queue_time: zx_duration_t,
        pub page_fault_time: zx_duration_t,
        pub lock_contention_time: zx_duration_t,
    }
}

zx_info_task_runtime_t!(zx_info_task_runtime_t);

multiconst!(zx_info_maps_type_t, [
    ZX_INFO_MAPS_TYPE_NONE    = 0;
    ZX_INFO_MAPS_TYPE_ASPACE  = 1;
    ZX_INFO_MAPS_TYPE_VMAR    = 2;
    ZX_INFO_MAPS_TYPE_MAPPING = 3;
]);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable, IntoBytes)]
    pub struct <zx_info_maps_mapping_t> {
        pub mmu_flags: zx_vm_option_t,
        padding1: [PadByte; 4],
        pub vmo_koid: zx_koid_t,
        pub vmo_offset: u64,
        pub committed_bytes: usize,
        pub populated_bytes: usize,
        pub committed_private_bytes: usize,
        pub populated_private_bytes: usize,
        pub committed_scaled_bytes: usize,
        pub populated_scaled_bytes: usize,
        pub committed_fractional_scaled_bytes: u64,
        pub populated_fractional_scaled_bytes: u64,
    }
}

zx_info_maps_mapping_t!(zx_info_maps_mapping_t);

#[repr(C)]
#[derive(Copy, Clone, KnownLayout, FromBytes, Immutable)]
pub union InfoMapsTypeUnion {
    pub mapping: zx_info_maps_mapping_t,
}

struct_decl_macro! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_maps_t> {
        pub name: [u8; ZX_MAX_NAME_LEN],
        pub base: zx_vaddr_t,
        pub size: usize,
        pub depth: usize,
        pub r#type: zx_info_maps_type_t,
        pub u: InfoMapsTypeUnion,
    }
}

zx_info_maps_t!(zx_info_maps_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_info_process_handle_stats_t> {
        pub handle_count: [u32; ZX_OBJ_TYPE_UPPER_BOUND],
    }
}

impl Default for zx_info_process_handle_stats_t {
    fn default() -> Self {
        Self { handle_count: [0; ZX_OBJ_TYPE_UPPER_BOUND] }
    }
}

zx_info_process_handle_stats_t!(zx_info_process_handle_stats_t);

struct_decl_macro! {
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable, zerocopy::IntoBytes)]
    pub struct <zx_info_memory_stall_t> {
        pub stall_time_some: zx_duration_mono_t,
        pub stall_time_full: zx_duration_mono_t,
    }
}

zx_info_memory_stall_t!(zx_info_memory_stall_t);

// from //zircon/system/public/zircon/syscalls/hypervisor.h
multiconst!(zx_guest_trap_t, [
    ZX_GUEST_TRAP_BELL = 0;
    ZX_GUEST_TRAP_MEM  = 1;
    ZX_GUEST_TRAP_IO   = 2;
    /// Deliver a `ZX_PKT_TYPE_GUEST_EOI` packet when the guest ends an interrupt
    /// whose vector is `addr`. `size` is 1 to register the vector, 0 to
    /// unregister it; `port` must be invalid.
    ZX_GUEST_TRAP_EOI  = 3;
]);

pub const ZX_LOG_RECORD_MAX: usize = 256;
pub const ZX_LOG_RECORD_DATA_MAX: usize = 216;

pub const DEBUGLOG_TRACE: u8 = 0x10;
pub const DEBUGLOG_DEBUG: u8 = 0x20;
pub const DEBUGLOG_INFO: u8 = 0x30;
pub const DEBUGLOG_WARNING: u8 = 0x40;
pub const DEBUGLOG_ERROR: u8 = 0x50;
pub const DEBUGLOG_FATAL: u8 = 0x60;

struct_decl_macro! {
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[derive(zerocopy::FromBytes, zerocopy::Immutable)]
    pub struct <zx_log_record_t> {
        pub sequence: u64,
        padding1: [PadByte; 4],
        pub datalen: u16,
        pub severity: u8,
        pub flags: u8,
        pub timestamp: zx_instant_boot_t,
        pub pid: u64,
        pub tid: u64,
        pub data: [u8; ZX_LOG_RECORD_DATA_MAX],
    }
}
const_assert_eq!(core::mem::size_of::<zx_log_record_t>(), ZX_LOG_RECORD_MAX);

zx_log_record_t!(zx_log_record_t);

impl Default for zx_log_record_t {
    fn default() -> zx_log_record_t {
        zx_log_record_t {
            sequence: 0,
            padding1: Default::default(),
            datalen: 0,
            severity: 0,
            flags: 0,
            timestamp: 0,
            pid: 0,
            tid: 0,
            data: [0; ZX_LOG_RECORD_DATA_MAX],
        }
    }
}

multiconst!(u32, [
    ZX_LOG_FLAG_READABLE = 0x40000000;
]);

// For C, the below types are currently forward declared for syscalls.h.
// We might want to investigate a better solution for Rust or removing those
// forward declarations.
//
// These are hand typed translations from C types into Rust structures using a C
// layout

// source: zircon/system/public/zircon/syscalls/system.h
#[repr(C)]
pub struct zx_system_powerctl_arg_t {
    // rust can't express anonymous unions at this time
    // https://github.com/rust-lang/rust/issues/49804
    pub powerctl_internal: zx_powerctl_union,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union zx_powerctl_union {
    acpi_transition_s_state: acpi_transition_s_state,
    x86_power_limit: x86_power_limit,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Copy, Clone)]
pub struct acpi_transition_s_state {
    target_s_state: u8, // Value between 1 and 5 indicating which S-state
    sleep_type_a: u8,   // Value from ACPI VM (SLP_TYPa)
    sleep_type_b: u8,   // Value from ACPI VM (SLP_TYPb)
    padding1: [PadByte; 9],
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Copy, Clone)]
pub struct x86_power_limit {
    power_limit: u32, // PL1 value in milliwatts
    time_window: u32, // PL1 time window in microseconds
    clamp: u8,        // PL1 clamping enable
    enable: u8,       // PL1 enable
    padding1: [PadByte; 2],
}

// source: zircon/system/public/zircon/syscalls/pci.h
pub type zx_pci_bar_types_t = u32;

multiconst!(zx_pci_bar_types_t, [
            ZX_PCI_BAR_TYPE_UNUSED = 0;
            ZX_PCI_BAR_TYPE_MMIO = 1;
            ZX_PCI_BAR_TYPE_PIO = 2;
]);

#[repr(C)]
pub struct zx_pci_bar_t {
    pub id: u32,
    pub ty: u32,
    pub size: usize,
    // rust can't express anonymous unions at this time
    // https://github.com/rust-lang/rust/issues/49804
    pub zx_pci_bar_union: zx_pci_bar_union,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union zx_pci_bar_union {
    addr: usize,
    zx_pci_bar_union_struct: zx_pci_bar_union_struct,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Copy, Clone)]
pub struct zx_pci_bar_union_struct {
    handle: zx_handle_t,
    padding1: [PadByte; 4],
}

// source: zircon/system/public/zircon/syscalls/smc.h
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct zx_smc_parameters_t {
    pub func_id: u32,
    padding1: [PadByte; 4],
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
    pub client_id: u16,
    pub secure_os_id: u16,
    padding2: [PadByte; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_smc_result_t {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg6: u64,
}

pub const ZX_CPU_SET_MAX_CPUS: usize = 512;
pub const ZX_CPU_SET_BITS_PER_WORD: usize = 64;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, zerocopy::FromBytes, zerocopy::Immutable)]
pub struct zx_cpu_set_t {
    pub mask: [u64; ZX_CPU_SET_MAX_CPUS / ZX_CPU_SET_BITS_PER_WORD],
}

// source: zircon/system/public/zircon/syscalls/scheduler.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct zx_profile_info_t {
    pub flags: u32,
    padding1: [PadByte; 4],
    pub zx_profile_info_union: zx_profile_info_union,
    pub cpu_affinity_mask: zx_cpu_set_t,
}

#[cfg(feature = "zerocopy")]
impl Default for zx_profile_info_t {
    fn default() -> Self {
        Self {
            flags: Default::default(),
            padding1: Default::default(),
            zx_profile_info_union: FromZeros::new_zeroed(),
            cpu_affinity_mask: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable))]
pub struct priority_params {
    pub priority: i32,
    padding1: [PadByte; 20],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable))]
pub union zx_profile_info_union {
    pub priority_params: priority_params,
    pub deadline_params: zx_sched_deadline_params_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable, KnownLayout))]
pub struct zx_sched_deadline_params_t {
    pub capacity: zx_duration_t,
    pub relative_deadline: zx_duration_t,
    pub period: zx_duration_t,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_cpu_performance_scale_t {
    pub integer_part: u32,
    pub fractional_part: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_cpu_performance_info_t {
    pub logical_cpu_number: u32,
    pub performance_scale: zx_cpu_performance_scale_t,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_cpu_perf_limit_t {
    pub logical_cpu_number: u32,
    pub limit_type: u32,
    pub min: u64,
    pub max: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_iommu_desc_stub_t {
    padding1: PadByte,
}

multiconst!(u32, [
    ZX_IOMMU_TYPE_STUB = 0;
    ZX_IOMMU_TYPE_INTEL = 1;
]);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct zx_sampler_config_t {
    pub period: zx_duration_t,
    pub buffer_size: usize,
    pub iobuffer_discipline: u64,
}

multiconst!(zx_processor_power_level_options_t, [
    ZX_PROCESSOR_POWER_LEVEL_OPTIONS_DOMAIN_INDEPENDENT = 1 << 0;
]);

multiconst!(zx_processor_power_control_t, [
    ZX_PROCESSOR_POWER_CONTROL_CPU_DRIVER = 0;
    ZX_PROCESSOR_POWER_CONTROL_ARM_PSCI = 1;
    ZX_PROCESSOR_POWER_CONTROL_ARM_WFI = 2;
    ZX_PROCESSOR_POWER_CONTROL_RISCV_SBI = 3;
    ZX_PROCESSOR_POWER_CONTROL_RISCV_WFI = 4;
]);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_processor_power_level_t {
    pub options: zx_processor_power_level_options_t,
    pub processing_rate: u64,
    pub power_coefficient_nw: u64,
    pub control_interface: zx_processor_power_control_t,
    pub control_argument: u64,
    pub diagnostic_name: [u8; ZX_MAX_NAME_LEN],
    padding1: [PadByte; 32],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_processor_power_level_transition_t {
    pub latency: zx_duration_t,
    pub energy: u64,
    pub from: u8,
    pub to: u8,
    padding1: [PadByte; 6],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct zx_packet_processor_power_level_transition_request_t {
    pub domain_id: u32,
    pub options: u32,
    pub control_interface: u64,
    pub control_argument: u64,
    padding1: [PadByte; 8],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_processor_power_state_t {
    pub domain_id: u32,
    pub options: u32,
    pub control_interface: u64,
    pub control_argument: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct zx_processor_power_domain_t {
    pub cpus: zx_cpu_set_t,
    pub domain_id: u32,
    padding1: [PadByte; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct zx_power_domain_info_t {
    pub cpus: zx_cpu_set_t,
    pub domain_id: u32,
    pub idle_power_levels: u8,
    pub active_power_levels: u8,
    padding1: [PadByte; 2],
}

multiconst!(u32, [
    ZX_BTI_PERM_READ = 1 << 0;
    ZX_BTI_PERM_WRITE = 1 << 1;
    ZX_BTI_PERM_EXECUTE = 1 << 2;
    ZX_BTI_COMPRESS = 1 << 3;
    ZX_BTI_CONTIGUOUS = 1 << 4;
]);

// Options for zx_port_create
multiconst!(u32, [
    ZX_PORT_BIND_TO_INTERRUPT = 1 << 0;
]);

// Options for zx_interrupt_create
multiconst!(u32, [
    ZX_INTERRUPT_VIRTUAL = 0x10;
    ZX_INTERRUPT_TIMESTAMP_MONO = 1 << 6;
]);

// Options for zx_interrupt_bind
multiconst!(u32, [
    ZX_INTERRUPT_BIND = 0;
    ZX_INTERRUPT_UNBIND = 1;
]);

#[repr(C)]
pub struct zx_iob_region_t {
    pub r#type: zx_iob_region_type_t,
    pub access: zx_iob_access_t,
    pub size: u64,
    pub discipline: zx_iob_discipline_t,
    pub extension: zx_iob_region_extension_t,
}

multiconst!(zx_iob_region_type_t, [
    ZX_IOB_REGION_TYPE_PRIVATE = 0;
    ZX_IOB_REGION_TYPE_SHARED = 1;
]);

multiconst!(zx_iob_access_t, [
    ZX_IOB_ACCESS_EP0_CAN_MAP_READ = 1 << 0;
    ZX_IOB_ACCESS_EP0_CAN_MAP_WRITE = 1 << 1;
    ZX_IOB_ACCESS_EP0_CAN_MEDIATED_READ = 1 << 2;
    ZX_IOB_ACCESS_EP0_CAN_MEDIATED_WRITE = 1 << 3;
    ZX_IOB_ACCESS_EP1_CAN_MAP_READ = 1 << 4;
    ZX_IOB_ACCESS_EP1_CAN_MAP_WRITE = 1 << 5;
    ZX_IOB_ACCESS_EP1_CAN_MEDIATED_READ = 1 << 6;
    ZX_IOB_ACCESS_EP1_CAN_MEDIATED_WRITE = 1 << 7;
]);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct zx_iob_discipline_t {
    pub r#type: zx_iob_discipline_type_t,
    pub extension: zx_iob_discipline_extension_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union zx_iob_discipline_extension_t {
    // This is in vdso-next.
    pub ring_buffer: zx_iob_discipline_mediated_write_ring_buffer_t,
    pub reserved: [PadByte; 64],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct zx_iob_discipline_mediated_write_ring_buffer_t {
    pub tag: u64,
    pub padding: [PadByte; 56],
}

multiconst!(zx_iob_discipline_type_t, [
    ZX_IOB_DISCIPLINE_TYPE_NONE = 0;
    ZX_IOB_DISCIPLINE_TYPE_MEDIATED_WRITE_RING_BUFFER = 2;
]);

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct zx_iob_region_private_t {
    options: u32,
    padding: [PadByte; 28],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct zx_iob_region_shared_t {
    pub options: u32,
    pub shared_region: zx_handle_t,
    pub padding: [PadByte; 24],
}

#[repr(C)]
pub union zx_iob_region_extension_t {
    pub private_region: zx_iob_region_private_t,
    pub shared_region: zx_iob_region_shared_t,
    pub max_extension: [u8; 32],
}

#[repr(C)]
pub struct zx_wake_source_report_entry_t {
    pub koid: zx_koid_t,
    pub name: [u8; ZX_MAX_NAME_LEN],
    pub initial_signal_time: zx_instant_boot_t,
    pub last_signal_time: zx_instant_boot_t,
    pub last_ack_time: zx_instant_boot_t,
    pub signal_count: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct zx_wake_source_report_header_t {
    pub report_time: zx_instant_boot_t,
    pub suspend_start_time: zx_instant_boot_t,
    pub total_wake_sources: u32,
    pub unreported_wake_report_entries: u32,
}

#[cfg(test)]
mod test {
    #[cfg(test)]
    extern crate alloc;

    use super::*;

    #[test]
    fn padded_struct_equality() {
        let test_struct = zx_clock_update_args_v1_t {
            rate_adjust: 222,
            padding1: Default::default(),
            value: 333,
            error_bound: 444,
        };

        let different_data = zx_clock_update_args_v1_t { rate_adjust: 999, ..test_struct.clone() };

        let different_padding = zx_clock_update_args_v1_t {
            padding1: [PadByte(0), PadByte(1), PadByte(2), PadByte(3)],
            ..test_struct.clone()
        };

        // Structures with different data should not be equal.
        assert_ne!(test_struct, different_data);
        // Structures with only different padding should not be equal.
        assert_eq!(test_struct, different_padding);
    }

    #[test]
    fn padded_struct_debug() {
        let test_struct = zx_clock_update_args_v1_t {
            rate_adjust: 222,
            padding1: Default::default(),
            value: 333,
            error_bound: 444,
        };
        let expectation = "zx_clock_update_args_v1_t { \
            rate_adjust: 222, \
            padding1: [-, -, -, -], \
            value: 333, \
            error_bound: 444 }";
        assert_eq!(alloc::format!("{:?}", test_struct), expectation);
    }
}

#[repr(C, align(32))]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "zerocopy", derive(FromBytes, Immutable, IntoBytes, KnownLayout))]
pub struct zx_rseq_t {
    pub cpu_id: u32,
    pub reserved: u32,
    pub start_ip: u64,
    pub post_commit_offset: u64,
    pub abort_ip: u64,
}

pub const ZX_INFO_INVALID_CPU: u32 = 0xFFFFFFFF;
