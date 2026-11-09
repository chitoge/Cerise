// Cerise stand-in for measure_tape_for_instance (FIDL byte size of fuchsia.sys2/Instance).
//
// Used by realm_query.rs::serve_instance_iterator to page Instances into channel messages:
// it starts bytes_used at the message/vector header size, adds each Instance's measure(),
// and breaks (without counting that Instance) once the total exceeds ZX_CHANNEL_MAX_MSG_BYTES.
// The old stub returned 0, so it never broke and packed every Instance into one message —
// a latent channel overflow on large realms (a developer-tool path, hence colder than the
// event router, but the same size-0 landmine).
//
// Return a per-Instance size that leaves headroom for the headers so exactly one Instance
// fits per page: provably no overflow and no spin (one Instance always fits; two never do).
// A single component Instance is far below this bound. Replace with real measure-tape if
// realm_query paging throughput ever matters.
const ZX_CHANNEL_MAX_MSG_BYTES: usize = 65536;
const HEADER_HEADROOM: usize = 16384; // > any FIDL message+vector header; keeps 1-per-page

pub struct Size {
    pub num_bytes: usize,
    pub num_handles: usize,
}

pub trait Measurable {
    fn measure(&self) -> Size;
}

impl Measurable for fidl_fuchsia_sys2::Instance {
    fn measure(&self) -> Size {
        Size { num_bytes: ZX_CHANNEL_MAX_MSG_BYTES - HEADER_HEADROOM, num_handles: 0 }
    }
}
