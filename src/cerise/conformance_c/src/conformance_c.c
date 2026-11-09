// Cerise runtime-conformance C probe. A PLAIN C component linking
// only the default sysroot (libc + libzircon + the runtime libfdio.so; NO
// static fdio) that EXERCISES — on a real boot, in a real component — the libc
// runtime surface expected to work so
// each row flips to boot-proven or is exposed as broken.
//
// It exercises, each asserted (not merely called), emitting a granular
// zx_debug_write marker per area so a failure localizes to the exact subsystem:
//   * pthreads with N=4 threads: real futex contention (a contended shared
//     counter) + a mutex/condvar baton handoff across all four; join all.
//   * math: sin / pow / lgamma / exp results asserted within epsilon.
//   * string/mem: memcpy / memmove(overlap) / strcmp / memcmp / strlen asserted.
//   * setjmp/longjmp: value preservation of a volatile local, a longjmp OUT of a
//     nested call, longjmp(buf,0)->setjmp==1, and the _setjmp/_longjmp pair.
//   * buffered stdio: fmemopen write+readback round-trip AND fread of the
//     component's own /pkg data file through the real libfdio.so.
//   * a final printf to fd1 (musl stdio -> writev -> libfdio.so -> elf_runner's
//     LogSink socket): the LogSink path, asserted by fflush()==0 && !ferror.
//
// Markers (all raw serial via zx_debug_write; the boot gate asserts the ordered
// per-probe subsequence + a terminal -DONE, and fails on any -FAIL):
//   CERISE-CONF-C-START      CERISE-CONF-C-THREADS-OK  CERISE-CONF-C-MATH-OK
//   CERISE-CONF-C-STRING-OK  CERISE-CONF-C-SETJMP-OK   CERISE-CONF-C-STDIO-OK
//   CERISE-CONF-C-LOGSINK-OK CERISE-CONF-C-DONE        CERISE-CONF-C-FAIL <why>
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zircon/syscalls.h>

// Needle in the staged /pkg/data/conf.txt (buffered-stdio read path).
#define FILE_NEEDLE "cerise-conf-c-file-needle-3b1e"
// Needle the final printf emits down the LogSink path.
#define PRINTF_NEEDLE "cerise-conf-c-printf-needle-6d20"

static void dbg(const char* s) { zx_debug_write(s, strlen(s)); }

static void fail(const char* why) {
  dbg("CERISE-CONF-C-FAIL ");
  dbg(why);
  dbg("\n");
}

// --------------------------------------------------------------------------
// (1) pthreads: futex contention + condvar baton handoff across 4 threads.
// --------------------------------------------------------------------------
#define NTHREADS 4
#define CONTEND_ITERS 50000

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static long g_counter;  // guarded by g_mtx; contended by all workers
static int g_baton;     // guarded by g_mtx; handed off in id order via g_cv

static void* worker(void* arg) {
  int id = (int)(long)arg;
  // Real futex contention: all four threads hammer one lock.
  for (int i = 0; i < CONTEND_ITERS; ++i) {
    pthread_mutex_lock(&g_mtx);
    ++g_counter;
    pthread_mutex_unlock(&g_mtx);
  }
  // Condvar baton handoff: block until it is exactly this thread's turn, then
  // advance and wake the others (proves cond wait/broadcast + predicate loop).
  pthread_mutex_lock(&g_mtx);
  while (g_baton != id) {
    pthread_cond_wait(&g_cv, &g_mtx);
  }
  ++g_baton;
  pthread_cond_broadcast(&g_cv);
  pthread_mutex_unlock(&g_mtx);
  return (void*)(long)id;
}

static int run_threads(void) {
  pthread_t th[NTHREADS];
  for (int i = 0; i < NTHREADS; ++i) {
    if (pthread_create(&th[i], NULL, worker, (void*)(long)i) != 0) {
      fail("pthread_create");
      return -1;
    }
  }
  for (int i = 0; i < NTHREADS; ++i) {
    void* ret = NULL;
    if (pthread_join(th[i], &ret) != 0 || (int)(long)ret != i) {
      fail("pthread_join");
      return -1;
    }
  }
  if (g_counter != (long)NTHREADS * CONTEND_ITERS) {
    fail("contended-counter");
    return -1;
  }
  if (g_baton != NTHREADS) {
    fail("condvar-baton");
    return -1;
  }
  return 0;
}

// --------------------------------------------------------------------------
// (2) math: assert real results within epsilon (never exact float equality).
// --------------------------------------------------------------------------
static int close_to(double got, double want, double eps) {
  double d = got - want;
  if (d < 0) d = -d;
  return d < eps;
}

static int run_math(void) {
  const double eps = 1e-9;
  if (!close_to(sin(M_PI / 6.0), 0.5, 1e-12)) { fail("sin"); return -1; }
  if (!close_to(pow(2.0, 10.0), 1024.0, eps)) { fail("pow"); return -1; }
  // lgamma(5) = ln(4!) = ln(24).
  if (!close_to(lgamma(5.0), log(24.0), eps)) { fail("lgamma"); return -1; }
  if (!close_to(exp(1.0), 2.718281828459045, 1e-12)) { fail("exp"); return -1; }
  if (!close_to(sqrt(2.0), 1.4142135623730951, 1e-12)) { fail("sqrt"); return -1; }
  return 0;
}

// --------------------------------------------------------------------------
// (3) string/mem: assert results.
// --------------------------------------------------------------------------
static int run_string(void) {
  const char* src = "cerise-conformance-string";
  char dst[64];
  memset(dst, 0, sizeof(dst));
  memcpy(dst, src, strlen(src) + 1);
  if (strcmp(dst, src) != 0) { fail("strcmp"); return -1; }
  if (memcmp(dst, src, strlen(src)) != 0) { fail("memcmp"); return -1; }
  if (strlen(dst) != strlen(src)) { fail("strlen"); return -1; }
  // Overlapping memmove: shift left by one.
  char buf[16] = "0123456789";
  memmove(buf, buf + 1, 9);
  buf[9] = '\0';
  if (strcmp(buf, "123456789") != 0) { fail("memmove"); return -1; }
  return 0;
}

// --------------------------------------------------------------------------
// (4) setjmp/longjmp.
// --------------------------------------------------------------------------
static jmp_buf g_jb;
[[gnu::noinline]] static void nested_longjmp(int v) {
  // longjmp OUT of a nested call frame: the unwinder-free save/restore must
  // restore g_jb's frame past this one.
  longjmp(g_jb, v);
}

static int run_setjmp(void) {
  // (a) value preservation of a volatile local + longjmp out of nested call.
  volatile int preserved = 0x0ABCD;
  int r = setjmp(g_jb);
  if (r == 0) {
    nested_longjmp(7);
    fail("setjmp-fallthrough");
    return -1;
  }
  if (r != 7) { fail("setjmp-retval"); return -1; }
  if (preserved != 0x0ABCD) { fail("setjmp-preserve"); return -1; }

  // (b) longjmp(buf, 0) must make setjmp return 1, not 0.
  jmp_buf jb0;
  int r0 = setjmp(jb0);
  if (r0 == 0) {
    longjmp(jb0, 0);
    fail("setjmp0-fallthrough");
    return -1;
  }
  if (r0 != 1) { fail("setjmp-zero-arg"); return -1; }

  // (c) the _setjmp/_longjmp pair (also exported by libc).
  jmp_buf jb2;
  int r2 = _setjmp(jb2);
  if (r2 == 0) {
    _longjmp(jb2, 5);
    fail("_setjmp-fallthrough");
    return -1;
  }
  if (r2 != 5) { fail("_setjmp-retval"); return -1; }
  return 0;
}

// --------------------------------------------------------------------------
// (5) buffered stdio: fmemopen write+readback + fread of the /pkg data file.
// --------------------------------------------------------------------------
static int run_stdio(void) {
  // (a) fmemopen round-trip (pure libc buffered stdio, no fs).
  char mem[128];
  memset(mem, 0, sizeof(mem));
  FILE* mf = fmemopen(mem, sizeof(mem), "w+");
  if (!mf) { fail("fmemopen"); return -1; }
  if (fprintf(mf, "roundtrip-%d-%s", 42, "ok") < 0) { fail("fmemopen-write"); fclose(mf); return -1; }
  if (fflush(mf) != 0) { fail("fmemopen-flush"); fclose(mf); return -1; }
  rewind(mf);
  char rb[128];
  memset(rb, 0, sizeof(rb));
  size_t got = fread(rb, 1, sizeof(rb) - 1, mf);
  fclose(mf);
  if (got == 0 || strcmp(rb, "roundtrip-42-ok") != 0) { fail("fmemopen-readback"); return -1; }

  // (b) fread the packaged data file through the REAL libfdio.so (buffered).
  FILE* f = fopen("/pkg/data/conf.txt", "r");
  if (!f) { fail(errno == ENOSYS ? "fopen-enosys" : "fopen"); return -1; }
  char fb[256];
  memset(fb, 0, sizeof(fb));
  size_t fn = fread(fb, 1, sizeof(fb) - 1, f);
  int ferr = ferror(f);
  fclose(f);
  if (fn == 0 || ferr) { fail("fread"); return -1; }
  if (strstr(fb, FILE_NEEDLE) == NULL) { fail("fread-content"); return -1; }
  return 0;
}

// --------------------------------------------------------------------------
// (6) final printf down the LogSink path (fd1 socket -> LogSink).
// --------------------------------------------------------------------------
static int run_logsink(void) {
  // fd1 is a zx socket: unbuffer so the record is flushed before we exit.
  setvbuf(stdout, NULL, _IONBF, 0);
  int rc = printf("CERISE-CONF-C-LOGSINK %s\n", PRINTF_NEEDLE);
  if (rc < 0 || ferror(stdout) || fflush(stdout) != 0) { fail("printf"); return -1; }
  return 0;
}

int main(void) {
  dbg("CERISE-CONF-C-START\n");
  if (run_threads() != 0) return 1;
  dbg("CERISE-CONF-C-THREADS-OK\n");
  if (run_math() != 0) return 1;
  dbg("CERISE-CONF-C-MATH-OK\n");
  if (run_string() != 0) return 1;
  dbg("CERISE-CONF-C-STRING-OK\n");
  if (run_setjmp() != 0) return 1;
  dbg("CERISE-CONF-C-SETJMP-OK\n");
  if (run_stdio() != 0) return 1;
  dbg("CERISE-CONF-C-STDIO-OK\n");
  if (run_logsink() != 0) return 1;
  dbg("CERISE-CONF-C-LOGSINK-OK\n");
  dbg("CERISE-CONF-C-DONE\n");
  return 0;
}
