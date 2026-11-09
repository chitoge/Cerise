// Cerise stub for scudo allocator (memory purging, used by boot_controller).
pub const M_PURGE_ALL: i32 = -101;
pub fn mallopt(_param: i32, _value: i32) -> Result<(), ()> { Ok(()) }
