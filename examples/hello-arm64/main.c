// Minimal arm64 Zircon userland binary.
// Resolves vDSO symbols, prints a boot marker.
// Channel ping-pong IPC demo (single-thread, two-endpoint echo).
// No standard-library includes — uses LP64 native types directly.

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef int            i32;
typedef long           i64;
typedef unsigned long  uptr;

typedef u32 zx_handle_t;
typedef i32 zx_status_t;

#define ZX_HANDLE_INVALID ((zx_handle_t)0u)
#define ZX_OK             ((zx_status_t)0)

// ----- ELF symbol resolution -----------------------------------------------

static int streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

static unsigned long elf_hash(const char *name) {
    unsigned long h = 0, g;
    while (*name) {
        h = (h << 4) + (unsigned char)*name++;
        if ((g = h & 0xf0000000UL)) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

// Walk the vDSO ELF at `base` and return the absolute VA of `name`,
// or 0 if not found.  Uses the SYSV hash table for lookup.
static uptr resolve_vdso(uptr base, const char *name) {
    // Elf64_Ehdr: e_phoff at +32 (u64), e_phnum at +56 (u16).
    u64  e_phoff = *(u64 *)(base + 32);
    u16  e_phnum = *(u16 *)(base + 56);

    // Find PT_DYNAMIC (type 2). Elf64_Phdr = 56 bytes.
    uptr dyn_vaddr = 0;
    for (u16 i = 0; i < e_phnum; i++) {
        uptr phdr = base + e_phoff + (u64)i * 56;
        if (*(u32 *)phdr == 2) {
            dyn_vaddr = *(u64 *)(phdr + 16);
            break;
        }
    }
    if (!dyn_vaddr) return 0;

    // Walk _DYNAMIC. Elf64_Dyn = 16 bytes: tag(i64) + val(u64).
    uptr hash_off = 0, strtab_off = 0, symtab_off = 0;
    uptr dyn = base + dyn_vaddr;
    for (;;) {
        i64 tag = *(i64 *)dyn;
        u64 val = *(u64 *)(dyn + 8);
        if (tag == 0) break;  // DT_NULL
        if (tag == 4) hash_off   = (uptr)val;  // DT_HASH
        if (tag == 5) strtab_off = (uptr)val;  // DT_STRTAB
        if (tag == 6) symtab_off = (uptr)val;  // DT_SYMTAB
        dyn += 16;
    }
    if (!hash_off || !strtab_off || !symtab_off) return 0;

    // SYSV hash table: [nbucket(u32), nchain(u32), bucket[], chain[]]
    u32 *htab    = (u32 *)(base + hash_off);
    u32  nbucket = htab[0];
    u32 *buckets = htab + 2;
    u32 *chains  = buckets + nbucket;

    unsigned long h = elf_hash(name);
    u32 idx = buckets[h % nbucket];
    while (idx) {
        // Elf64_Sym = 24 bytes: st_name(u32) at +0, st_value(u64) at +8.
        uptr sym      = base + symtab_off + (u64)idx * 24;
        u32  st_name  = *(u32 *)sym;
        u64  st_value = *(u64 *)(sym + 8);
        const char *sym_name = (const char *)(base + strtab_off + st_name);
        if (st_value && streq(sym_name, name))
            return base + (uptr)st_value;
        idx = chains[idx];
    }
    return 0;
}

// ----- Entry point called from entry.S -------------------------------------

void userland_main(u32 bootstrap, uptr vdso_base) {
    (void)bootstrap;

    typedef zx_status_t (*debug_write_fn)(const void *, uptr);
    typedef zx_status_t (*chan_create_fn)(u32, zx_handle_t *, zx_handle_t *);
    typedef zx_status_t (*chan_write_fn)(zx_handle_t, u32, const void *, u32, const void *, u32);
    typedef zx_status_t (*chan_read_fn)(zx_handle_t, u32, void *, void *, u32, u32, u32 *, u32 *);
    typedef zx_status_t (*handle_close_fn)(zx_handle_t);
    typedef void        (*proc_exit_fn)(i32) __attribute__((noreturn));

    debug_write_fn  zx_debug_write    = (debug_write_fn) resolve_vdso(vdso_base, "_zx_debug_write");
    chan_create_fn  zx_channel_create  = (chan_create_fn) resolve_vdso(vdso_base, "_zx_channel_create");
    chan_write_fn   zx_channel_write   = (chan_write_fn)  resolve_vdso(vdso_base, "_zx_channel_write");
    chan_read_fn    zx_channel_read    = (chan_read_fn)   resolve_vdso(vdso_base, "_zx_channel_read");
    handle_close_fn zx_handle_close   = (handle_close_fn)resolve_vdso(vdso_base, "_zx_handle_close");
    proc_exit_fn    zx_process_exit   = (proc_exit_fn)   resolve_vdso(vdso_base, "_zx_process_exit");

    if (!zx_debug_write || !zx_channel_create || !zx_channel_write ||
        !zx_channel_read || !zx_handle_close || !zx_process_exit)
        for (;;) {}  // resolution failure — hang

    // boot marker
    static const char boot_msg[] = "hello-arm64: userspace booted\n";
    zx_debug_write(boot_msg, sizeof(boot_msg) - 1);

    // channel ping-pong
    zx_handle_t h0 = ZX_HANDLE_INVALID, h1 = ZX_HANDLE_INVALID;
    zx_status_t st = zx_channel_create(0, &h0, &h1);
    if (st != ZX_OK) {
        static const char err[] = "hello-arm64: channel_create failed\n";
        zx_debug_write(err, sizeof(err) - 1);
        zx_process_exit(1);
    }

    // Send "ping" on h0
    static const char ping[] = "ping";
    st = zx_channel_write(h0, 0, ping, sizeof(ping) - 1, 0, 0);
    if (st != ZX_OK) {
        static const char err[] = "hello-arm64: channel_write(ping) failed\n";
        zx_debug_write(err, sizeof(err) - 1);
        zx_process_exit(1);
    }

    // Receive "ping" on h1, send "pong" back
    char rbuf[16];
    u32 rlen = 0;
    st = zx_channel_read(h1, 0, rbuf, 0, sizeof(rbuf), 0, &rlen, 0);
    if (st != ZX_OK || rlen != 4) {
        static const char err[] = "hello-arm64: channel_read(ping) failed\n";
        zx_debug_write(err, sizeof(err) - 1);
        zx_process_exit(1);
    }

    static const char ipc_ping[] = "hello-arm64: ipc ping received\n";
    zx_debug_write(ipc_ping, sizeof(ipc_ping) - 1);

    static const char pong[] = "pong";
    st = zx_channel_write(h1, 0, pong, sizeof(pong) - 1, 0, 0);
    if (st != ZX_OK) {
        static const char err[] = "hello-arm64: channel_write(pong) failed\n";
        zx_debug_write(err, sizeof(err) - 1);
        zx_process_exit(1);
    }

    // Receive "pong" on h0
    st = zx_channel_read(h0, 0, rbuf, 0, sizeof(rbuf), 0, &rlen, 0);
    if (st != ZX_OK || rlen != 4) {
        static const char err[] = "hello-arm64: channel_read(pong) failed\n";
        zx_debug_write(err, sizeof(err) - 1);
        zx_process_exit(1);
    }

    static const char ipc_pong[] = "hello-arm64: ipc pong received\n";
    zx_debug_write(ipc_pong, sizeof(ipc_pong) - 1);

    zx_handle_close(h0);
    zx_handle_close(h1);

    static const char done[] = "hello-arm64: ipc done\n";
    zx_debug_write(done, sizeof(done) - 1);

    zx_process_exit(0);
}
