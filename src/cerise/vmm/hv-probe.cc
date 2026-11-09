// Hypervisor availability probe: calls zx_guest_create and logs the result.
// Standalone userland binary (no libc, no Rust) that boots via userboot.
// On a hypervisor-enabled kernel with no resource handle it returns
// ZX_ERR_BAD_HANDLE (-26); on a hypervisor-disabled (stub) kernel it returns
// ZX_ERR_NOT_SUPPORTED (-25).  Both outcomes emit "vmm: hypervisor ..." which
// satisfies the marker contract.

using int32_t  = __INT32_TYPE__;
using int64_t  = __INT64_TYPE__;
using uint8_t  = __UINT8_TYPE__;
using uint16_t = __UINT16_TYPE__;
using uint32_t = __UINT32_TYPE__;
using uint64_t = __UINT64_TYPE__;
using uintptr_t = __UINTPTR_TYPE__;
using size_t = decltype(sizeof(0));

// ─── Minimal ELF64 vDSO resolver (mirrors cerise_rt/src/zx.rs) ──────────

static constexpr uint32_t kPtDynamic = 2;
static constexpr int64_t  kDtNull = 0, kDtHash = 4, kDtStrtab = 5, kDtSymtab = 6;

static uint32_t elf_hash(const char* s) {
    uint32_t h = 0;
    for (; *s; ++s) {
        h = (h << 4) + static_cast<unsigned char>(*s);
        uint32_t g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static bool cstr_eq(const uint8_t* p, const char* name) {
    for (; *name; ++name, ++p)
        if (*p != static_cast<uint8_t>(*name)) return false;
    return *p == 0;
}

static uintptr_t vdso_resolve(uintptr_t base, const char* name) {
    uint64_t e_phoff = *reinterpret_cast<const uint64_t*>(base + 32);
    uint16_t e_phnum = *reinterpret_cast<const uint16_t*>(base + 56);

    uintptr_t dyn_vaddr = 0;
    for (uint16_t i = 0; i < e_phnum; ++i) {
        const auto* phdr = reinterpret_cast<const uint8_t*>(base + e_phoff + i * 56);
        if (*reinterpret_cast<const uint32_t*>(phdr) == kPtDynamic) {
            dyn_vaddr = static_cast<uintptr_t>(*reinterpret_cast<const uint64_t*>(phdr + 16));
            break;
        }
    }
    if (!dyn_vaddr) return 0;

    uintptr_t hash_off = 0, strtab_off = 0, symtab_off = 0;
    for (const auto* d = reinterpret_cast<const int64_t*>(base + dyn_vaddr); ; d += 2) {
        int64_t tag = d[0];
        uintptr_t val = static_cast<uintptr_t>(d[1]);
        if (tag == kDtNull)   break;
        if (tag == kDtHash)   hash_off   = val;
        if (tag == kDtStrtab) strtab_off = val;
        if (tag == kDtSymtab) symtab_off = val;
    }
    if (!hash_off || !strtab_off || !symtab_off) return 0;

    const auto* ht  = reinterpret_cast<const uint32_t*>(base + hash_off);
    uint32_t nbuckets = ht[0];
    const auto* buckets = ht + 2;
    const auto* chains  = buckets + nbuckets;
    for (uint32_t idx = buckets[elf_hash(name) % nbuckets]; idx; idx = chains[idx]) {
        const auto* sym = reinterpret_cast<const uint8_t*>(base + symtab_off + idx * 24);
        uint32_t st_name  = *reinterpret_cast<const uint32_t*>(sym);
        uint64_t st_value = *reinterpret_cast<const uint64_t*>(sym + 8);
        if (st_value &&
            cstr_eq(reinterpret_cast<const uint8_t*>(base + strtab_off + st_name), name))
            return base + static_cast<uintptr_t>(st_value);
    }
    return 0;
}

// ─── Kernel handle / status types ────────────────────────────────────────

using zx_handle_t = uint32_t;
using zx_status_t = int32_t;
static constexpr zx_handle_t kHandleInvalid = 0;
static constexpr zx_status_t kZxOk = 0;

using FnDebuglogCreate = zx_status_t (*)(zx_handle_t, uint32_t, zx_handle_t*);
using FnDebuglogWrite  = zx_status_t (*)(zx_handle_t, uint32_t, const void*, size_t);
using FnHandleClose    = zx_status_t (*)(zx_handle_t);
using FnGuestCreate    = zx_status_t (*)(zx_handle_t, uint32_t, zx_handle_t*, zx_handle_t*);
using FnProcessExit    = void (*)(int64_t);

// ─── Helpers ─────────────────────────────────────────────────────────────

static void write_log(FnDebuglogWrite fn, zx_handle_t log,
                      const char* a, const char* b, const char* c) {
    char buf[128];
    char* p = buf;
    for (const char* s = a; *s; ++s) *p++ = *s;
    for (const char* s = b; *s; ++s) *p++ = *s;
    for (const char* s = c; *s; ++s) *p++ = *s;
    *p++ = '\n';
    fn(log, 0, buf, static_cast<size_t>(p - buf));
}

static const char* status_str(zx_status_t s, char* buf, size_t cap) {
    // Write decimal representation of s (which is negative) into buf.
    char tmp[16];
    int i = 0;
    bool neg = (s < 0);
    int32_t v = neg ? -s : s;
    if (v == 0) { tmp[i++] = '0'; }
    while (v > 0) { tmp[i++] = '0' + (v % 10); v /= 10; }
    if (neg) tmp[i++] = '-';
    if (static_cast<size_t>(i) >= cap) return "";
    char* out = buf;
    while (i-- > 0) *out++ = tmp[i];
    *out = '\0';
    return buf;
}

// ─── Entry point ─────────────────────────────────────────────────────────

extern "C" [[noreturn]] void _start(uintptr_t /*bootstrap*/, uintptr_t vdso_base) {
    auto log_create = reinterpret_cast<FnDebuglogCreate>(
        vdso_resolve(vdso_base, "_zx_debuglog_create"));
    auto log_write = reinterpret_cast<FnDebuglogWrite>(
        vdso_resolve(vdso_base, "_zx_debuglog_write"));
    auto handle_close = reinterpret_cast<FnHandleClose>(
        vdso_resolve(vdso_base, "_zx_handle_close"));
    auto guest_create = reinterpret_cast<FnGuestCreate>(
        vdso_resolve(vdso_base, "_zx_guest_create"));
    auto process_exit = reinterpret_cast<FnProcessExit>(
        vdso_resolve(vdso_base, "_zx_process_exit"));

    zx_handle_t log = kHandleInvalid;
    if (log_create) log_create(kHandleInvalid, 0, &log);

    if (log != kHandleInvalid && log_write && guest_create) {
        zx_handle_t guest = kHandleInvalid, vmar = kHandleInvalid;
        zx_status_t s = guest_create(kHandleInvalid, 0, &guest, &vmar);
        if (s == kZxOk) {
            if (handle_close) { handle_close(guest); handle_close(vmar); }
            write_log(log_write, log, "vmm: hypervisor available", "", "");
        } else {
            char buf[16];
            write_log(log_write, log,
                      "vmm: hypervisor not supported: ", status_str(s, buf, sizeof(buf)), "");
        }
        if (handle_close) handle_close(log);
    }

    if (process_exit) process_exit(0);
    while (true) {}
}
