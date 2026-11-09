// Cerise stand-in for measure_tape_for_events.
//
// The real measure-tape is generated code that computes a FIDL object's exact encoded
// size. component_manager's event router (model/events/use_router.rs::get_next_events)
// uses it to pack as many events into one channel message as fit under
// ZX_CHANNEL_MAX_MSG_{BYTES,HANDLES}. A measurement of 0 (the old stub) tells the router
// every event is free, so it batches the entire queue into one message that can blow past
// the 64KiB / 64-handle channel limit and fail the write — a latent landmine.
//
// Instead of the (generated-code-heavy) exact measure, return the channel maximum per
// event. In the router's loop the size threshold then trips after a single event, so each
// event is sent in its own message: provably never an overflow, and never a spin (one
// event's size equals the limit, which is not strictly greater, so it is still pushed). A
// single component Event is always far below one channel message. Replace with real
// measure-tape only if event-batching throughput ever matters.
const ZX_CHANNEL_MAX_MSG_BYTES: usize = 65536;
const ZX_CHANNEL_MAX_MSG_HANDLES: usize = 64;

pub struct Size {
    pub num_bytes: usize,
    pub num_handles: usize,
}

pub trait Measurable {
    fn measure(&self) -> Size;
}

impl Measurable for fidl_fuchsia_component::Event {
    fn measure(&self) -> Size {
        Size { num_bytes: ZX_CHANNEL_MAX_MSG_BYTES, num_handles: ZX_CHANNEL_MAX_MSG_HANDLES }
    }
}
