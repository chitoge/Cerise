// Cerise libc.so malloc family (the C malloc/free/calloc/realloc/... surface).
//
// History: an early bring-up drop shipped a bump allocator whose free() was a no-op. It "worked" for
// short probes but never reclaimed memory, so any sustained heap use exhausted its
// fixed arena and OOM'd (Rust std and C/C++ alike route through these symbols). That
// is the classic success-shaped workaround — green build, runtime failure far away.
//
// This is a real reclaiming allocator. Design (deliberately the low-bug-density one):
//   * Small allocations (<= MAX_SMALL, alignment <= 16): a 32-byte header + power-of-two
//     size classes over a single bump arena. free() pushes the block onto its class
//     freelist; malloc() pops the freelist before bumping. No coalescing (coalescing
//     boundary-tags are the highest-bug-density allocator design; a subtly wrong malloc
//     trades a predictable OOM for heap corruption — worse). Freed small blocks stay
//     committed and are reused; that bounds RSS for the churny small-object workload.
//   * Large / over-aligned allocations: a standalone OS mapping each, returned to the
//     OS on free(). This truly releases RSS and dissolves the large-block fragmentation
//     that a no-coalescing small allocator would otherwise suffer (e.g. Vec growth).
//   * One global spinlock guards the shared small-path state (freelists + bump pointer).
//     Correctness over scalability; early-boot/ldso calls are uncontended. The large
//     path touches no shared state and runs lockless.
//
// scudo (the full concurrent allocator Fuchsia ships) remains the eventual replacement;
// this exists so libc.so is correct and stable in the interim.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// OS page-mapping primitives, factored so this file also compiles for the host
// stress test (libc-malloc:malloc_stress_test) where zx syscalls don't exist.
#ifdef CERISE_MALLOC_HOST_TEST
#include <sys/mman.h>
#define LV_PAGE ((size_t)4096)
static void* os_map(size_t len) {
  void* p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return p == MAP_FAILED ? NULL : p;
}
static void os_unmap(void* p, size_t len) { munmap(p, len); }
#else
#include <zircon/syscalls.h>
#include <zircon/types.h>
extern zx_handle_t _zx_vmar_root_self(void);
#define LV_PAGE ((size_t)4096)  // x86_64 base page
static void* os_map(size_t len) {
  zx_handle_t vmo;
  if (_zx_vmo_create(len, 0, &vmo) != ZX_OK) return NULL;
  zx_vaddr_t addr;
  zx_status_t st = _zx_vmar_map(_zx_vmar_root_self(), ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
                                0, vmo, 0, len, &addr);
  _zx_handle_close(vmo);  // the mapping holds its own reference
  return st == ZX_OK ? (void*)addr : NULL;
}
static void os_unmap(void* p, size_t len) {
  _zx_vmar_unmap(_zx_vmar_root_self(), (zx_vaddr_t)p, len);
}
#endif

// ---- block header (32 bytes; immediately precedes the user pointer) ----
#define MAGIC_SMALL 0x6c61766d736d6c31ULL  // live small block
#define MAGIC_LARGE 0x6c61766d6c726731ULL  // live standalone mapping
#define MAGIC_FREED 0x6672656564217830ULL  // on a class freelist (double-free guard)

typedef struct hdr {
  uint64_t magic;
  uint64_t size;    // small: class payload size; large: requested size
  uint64_t base;    // underlying alloc start (small: == hdr; large: mapping base)
  uint64_t maplen;  // large: mapping length for os_unmap; small: 0
} hdr_t;

#define HDR_SZ ((size_t)sizeof(hdr_t))  // 32, keeps the user region 16-aligned

// ---- size classes: 16,32,...,65536 (powers of two) ----
#define MIN_CLASS_SHIFT 4               // 16 bytes
#define NUM_CLASSES 13                  // 16 << 12 == 65536
#define MAX_SMALL ((size_t)1 << (MIN_CLASS_SHIFT + NUM_CLASSES - 1))  // 65536

static int size_to_class(size_t n) {
  size_t s = (size_t)1 << MIN_CLASS_SHIFT;
  int i = 0;
  while (s < n) { s <<= 1; i++; }
  return i;  // caller checks i < NUM_CLASSES
}
static size_t class_size(int i) { return (size_t)1 << (MIN_CLASS_SHIFT + i); }

// ---- shared small-path state (guarded by g_lock) ----
static void* g_free[NUM_CLASSES];  // freelists; node->next stored in the payload
static uintptr_t g_base, g_off, g_cap;
#define ARENA_SIZE ((size_t)512 * 1024 * 1024)

// ---- spinlock (compiler atomics; no libc/pthread dependency) ----
#if defined(__x86_64__) || defined(__i386__)
#define LV_CPU_RELAX() __asm__ __volatile__("pause" ::: "memory")
#else
#define LV_CPU_RELAX() __atomic_thread_fence(__ATOMIC_RELAXED)
#endif
static volatile int g_lock;
static void lock(void) {
  while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE)) {
    while (__atomic_load_n(&g_lock, __ATOMIC_RELAXED)) LV_CPU_RELAX();
  }
}
static void unlock(void) { __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE); }

static int ensure_arena_locked(void) {
  if (g_base) return 0;
  void* a = os_map(ARENA_SIZE);
  if (!a) return -1;
  g_base = (uintptr_t)a;
  g_cap = ARENA_SIZE;
  g_off = 0;
  return 0;
}

static inline hdr_t* hdr_of(void* user) { return (hdr_t*)((uintptr_t)user - HDR_SZ); }

// Small allocation: pop the class freelist, else bump. *fresh set to 1 only when the
// returned payload came from never-touched arena (so calloc can skip the memset).
static void* alloc_small(int cls, int* fresh) {
  void* node = g_free[cls];
  if (node) {
    g_free[cls] = *(void**)node;  // unlink
    hdr_of(node)->magic = MAGIC_SMALL;
    *fresh = 0;
    return node;
  }
  if (ensure_arena_locked()) return NULL;
  size_t need = HDR_SZ + class_size(cls);
  uintptr_t block = (g_base + g_off + 15) & ~(uintptr_t)15;
  size_t end = (block - g_base) + need;
  if (end > g_cap) return NULL;  // arena exhausted
  g_off = end;
  hdr_t* h = (hdr_t*)block;
  h->magic = MAGIC_SMALL;
  h->size = class_size(cls);
  h->base = block;
  h->maplen = 0;
  *fresh = 1;
  return (void*)(block + HDR_SZ);
}

// Large / over-aligned allocation: its own OS mapping, lockless.
static void* alloc_large(size_t n, size_t align) {
  if (align < 16) align = 16;
  // Worst case: header + alignment slack + payload, page-rounded.
  size_t raw = HDR_SZ + align + n;
  size_t maplen = (raw + LV_PAGE - 1) & ~(LV_PAGE - 1);
  if (maplen < raw) return NULL;  // overflow
  void* base = os_map(maplen);
  if (!base) return NULL;
  uintptr_t user = ((uintptr_t)base + HDR_SZ + (align - 1)) & ~(uintptr_t)(align - 1);
  hdr_t* h = hdr_of((void*)user);
  h->magic = MAGIC_LARGE;
  h->size = n;
  h->base = (uintptr_t)base;
  h->maplen = maplen;
  return (void*)user;
}

// Core allocate. align<=16 && n<=MAX_SMALL -> small path; else large path.
static void* alloc(size_t n, size_t align, int* fresh) {
  *fresh = 0;
  if (n == 0) n = 1;
  if (align <= 16 && n <= MAX_SMALL) {
    int cls = size_to_class(n);
    lock();
    void* p = alloc_small(cls, fresh);
    unlock();
    return p;
  }
  *fresh = 1;  // os_map returns zeroed pages
  return alloc_large(n, align);
}

void* malloc(size_t n) {
  int fresh;
  return alloc(n, 16, &fresh);
}

void free(void* p) {
  if (!p) return;
  hdr_t* h = hdr_of(p);
  if (h->magic == MAGIC_SMALL) {
    int cls = size_to_class(h->size);
    lock();
    h->magic = MAGIC_FREED;
    *(void**)p = g_free[cls];  // push (payload >= 16 bytes holds the next pointer)
    g_free[cls] = p;
    unlock();
    return;
  }
  if (h->magic == MAGIC_LARGE) {
    os_unmap((void*)h->base, h->maplen);
    return;
  }
  // MAGIC_FREED (double free) or garbage (wild pointer): a real bug. Trap so it
  // surfaces here instead of corrupting the heap and failing elsewhere.
  __builtin_trap();
}

void* calloc(size_t a, size_t b) {
  if (a && b > (size_t)-1 / a) return NULL;  // overflow
  size_t n = a * b;
  int fresh;
  void* p = alloc(n, 16, &fresh);
  if (p && !fresh) memset(p, 0, n);  // reused blocks are dirty; fresh ones are zero
  return p;
}

void* realloc(void* old, size_t n) {
  if (!old) return malloc(n);
  if (n == 0) { free(old); return NULL; }
  size_t old_size = hdr_of(old)->size;
  int fresh;
  void* p = alloc(n, 16, &fresh);
  if (!p) return NULL;  // old left intact, per C
  memcpy(p, old, old_size < n ? old_size : n);
  free(old);
  return p;
}

void* aligned_alloc(size_t align, size_t n) {
  int fresh;
  return alloc(n, align, &fresh);
}
void* memalign(size_t align, size_t n) {
  int fresh;
  return alloc(n, align, &fresh);
}
int posix_memalign(void** out, size_t align, size_t n) {
  int fresh;
  void* p = alloc(n, align, &fresh);
  if (!p) return 12;  // ENOMEM
  *out = p;
  return 0;
}
size_t malloc_usable_size(void* p) { return p ? hdr_of(p)->size : 0; }
