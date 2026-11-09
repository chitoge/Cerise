// Runtime bring-up: stub libfdio.so —, LINK-TIME ONLY (libfdf.so's
// dynamic_dep; see BUILD.bazel). The runtime libfdio.so and the sysroot's
// -lfdio are the REAL shared fdio built from the vendored sources
// (//src/upstream/fuchsia/sdk/lib/fdio:libfdio.so); these ENOSYS bodies are
// never loaded into any image — only the symbol names matter, to satisfy the
// libfdf link.
//
// Self-contained types (no sysroot header dependency): the only contract that matters
// for the link is the SYMBOL NAMES; sizes/ABI are irrelevant for stubs that fail.
typedef unsigned long size_t;
typedef long ssize_t;
typedef long off_t;

extern int* __errno_location(void);
#define ENOSYS 38
static int fail(void) {
  *__errno_location() = ENOSYS;
  return -1;
}

ssize_t write(int fd, const void* buf, size_t count) { return fail(); }
ssize_t read(int fd, void* buf, size_t count) { return fail(); }
ssize_t writev(int fd, const void* iov, int iovcnt) { return fail(); }
int open(const char* path, int flags, ...) { return fail(); }
int close(int fd) { return 0; }
int fstat(int fd, void* statbuf) { return fail(); }
int stat(const char* path, void* statbuf) { return fail(); }
off_t lseek(int fd, off_t offset, int whence) { return fail(); }
char* getcwd(char* buf, size_t size) {
  *__errno_location() = ENOSYS;
  return 0;
}
char* realpath(const char* path, char* resolved) {
  *__errno_location() = ENOSYS;
  return 0;
}

// fdio_unsafe_* stubs: symbols referenced by fuchsia-async's net module.
// These resolve at link time against libfdio.so; networking is not used in
// Cerise yet, so they can be no-ops / return-null stubs.
typedef void fdio_t;
typedef unsigned int zx_handle_t;
typedef unsigned int zx_signals_t;

fdio_t* fdio_unsafe_fd_to_io(int fd) { return 0; }
void fdio_unsafe_release(fdio_t* io) {}
void fdio_unsafe_wait_begin(fdio_t* io, unsigned int events,
                             zx_handle_t* handle_out, zx_signals_t* signals_out) {
  if (handle_out) *handle_out = 0;
  if (signals_out) *signals_out = 0;
}
void fdio_unsafe_wait_end(fdio_t* io, zx_signals_t signals,
                           unsigned int* events_out) {
  if (events_out) *events_out = 0;
}

// fdio_spawn stub: returns ZX_ERR_NOT_SUPPORTED until a real launcher is wired.
// ZX_ERR_NOT_SUPPORTED = -25.
#define ZX_ERR_NOT_SUPPORTED (-25)
int fdio_spawn(zx_handle_t job, unsigned int flags, const char* path,
               const char* const* argv, zx_handle_t* process_out) {
  return ZX_ERR_NOT_SUPPORTED;
}

// fdio namespace/directory stubs needed by sdk/lib/component/incoming/cpp,
// which is pulled in transitively by driver_runtime/dispatcher.cc via
// component::Connect<fuchsia_scheduler::RoleManager>().
// Real implementations come from the full fdio library; these stubs allow
// libfdf.so to link and the call to fail cleanly at runtime.
typedef int zx_status_t;
zx_status_t fdio_open3(const char* path, unsigned long long flags,
                        zx_handle_t request) {
  return ZX_ERR_NOT_SUPPORTED;
}
zx_status_t fdio_open3_at(zx_handle_t dir, const char* path,
                           unsigned long long flags, zx_handle_t request) {
  return ZX_ERR_NOT_SUPPORTED;
}
zx_status_t fdio_service_connect(const char* path, zx_handle_t h) {
  return ZX_ERR_NOT_SUPPORTED;
}
zx_status_t fdio_service_connect_at(zx_handle_t dir, const char* path,
                                     zx_handle_t h) {
  return ZX_ERR_NOT_SUPPORTED;
}
