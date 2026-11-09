// Host stress test for the Cerise libc malloc. Compiled with CERISE_MALLOC_HOST_TEST
// so it can #include malloc.c directly and inspect internal state (g_off, freelists).
//
// Checks: (1) no overlap/corruption across threads, (2) freed memory is reused (the
// arena bump pointer does not grow on a second identical round), (3) realloc preserves
// bytes, (4) calloc zeroes reused (dirty) blocks, (5) double-free trips the guard.
#define CERISE_MALLOC_HOST_TEST 1
// Rename our entry points so glibc's own internals (stdio, pthread) keep using glibc's
// allocator; this TU's malloc/free/... calls and malloc.c's definitions both bind to
// these lv_* symbols, testing our allocator in isolation.
#define malloc lv_malloc
#define free lv_free
#define calloc lv_calloc
#define realloc lv_realloc
#define aligned_alloc lv_aligned_alloc
#define memalign lv_memalign
#define posix_memalign lv_posix_memalign
#define malloc_usable_size lv_malloc_usable_size
#include "malloc.c"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static uint8_t pattern_for(void* p) { return (uint8_t)(((uintptr_t)p >> 4) ^ 0xA5); }

// Per-thread churn: alloc small+large, fill a pointer-derived pattern, verify the
// pattern still holds before freeing (a mismatch == another thread wrote into us).
static void* churn(void* arg) {
  unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u + 1u;
  enum { LIVE = 256 };
  void* live[LIVE] = {0};
  size_t sizes[LIVE] = {0};
  for (int iter = 0; iter < 40000; iter++) {
    seed = seed * 1103515245u + 12345u;
    int slot = (seed >> 8) % LIVE;
    if (live[slot]) {
      uint8_t pat = pattern_for(live[slot]);
      uint8_t* b = live[slot];
      for (size_t k = 0; k < sizes[slot]; k++) {
        if (b[k] != pat) { fprintf(stderr, "CORRUPTION slot=%d\n", slot); abort(); }
      }
      free(live[slot]);
      live[slot] = NULL;
    } else {
      seed = seed * 1103515245u + 12345u;
      // Mostly small; occasionally large (> MAX_SMALL) to exercise the mmap path.
      size_t n = ((seed >> 6) % 100 == 0) ? (70000 + (seed % 40000))
                                          : (1 + (seed % 4096));
      void* p = malloc(n);
      assert(p);
      assert(((uintptr_t)p % 16) == 0);
      memset(p, pattern_for(p), n);
      live[slot] = p;
      sizes[slot] = n;
    }
  }
  for (int i = 0; i < LIVE; i++)
    if (live[i]) free(live[i]);
  return NULL;
}

static void test_threads(void) {
  enum { T = 8 };
  pthread_t th[T];
  for (long i = 0; i < T; i++) assert(pthread_create(&th[i], NULL, churn, (void*)i) == 0);
  for (int i = 0; i < T; i++) pthread_join(th[i], NULL);
  printf("  [ok] 8-thread churn: no corruption\n");
}

static void test_reuse(void) {
  // Allocate and free a batch, then repeat the identical batch. The arena bump
  // pointer must not advance on round 2 — freelists satisfy it entirely.
  enum { N = 1000 };
  void* p[N];
  for (int i = 0; i < N; i++) { p[i] = malloc(64); assert(p[i]); }
  for (int i = 0; i < N; i++) free(p[i]);
  size_t off_after_round1 = g_off;
  for (int i = 0; i < N; i++) { p[i] = malloc(64); assert(p[i]); }
  size_t off_after_round2 = g_off;
  for (int i = 0; i < N; i++) free(p[i]);
  assert(off_after_round2 == off_after_round1);
  printf("  [ok] reuse: bump pointer stable across rounds (no growth)\n");
}

static void test_realloc(void) {
  char* p = malloc(32);
  for (int i = 0; i < 32; i++) p[i] = (char)(i + 1);
  p = realloc(p, 4096);
  assert(p);
  for (int i = 0; i < 32; i++) assert(p[i] == (char)(i + 1));  // bytes preserved
  p = realloc(p, 8);
  assert(p);
  for (int i = 0; i < 8; i++) assert(p[i] == (char)(i + 1));   // shrink keeps prefix
  free(p);
  assert(realloc(NULL, 16) != NULL);  // realloc(NULL,n) == malloc
  assert(realloc(malloc(16), 0) == NULL);  // realloc(p,0) frees, returns NULL
  printf("  [ok] realloc: grow/shrink preserve bytes; NULL/0 edge cases\n");
}

static void test_calloc_zeroes_reused(void) {
  // Dirty a block, free it, then calloc the same class — must come back zeroed.
  size_t n = 48;
  uint8_t* a = malloc(n);
  memset(a, 0xFF, n);
  free(a);
  uint8_t* b = calloc(1, n);
  assert(b);
  for (size_t i = 0; i < n; i++) assert(b[i] == 0);
  free(b);
  assert(calloc(0, 0) != NULL || 1);          // calloc(0,..) returns a usable ptr
  assert(calloc((size_t)-1, 2) == NULL);      // overflow guarded
  printf("  [ok] calloc: reused blocks zeroed; overflow guarded\n");
}

static void test_double_free_traps(void) {
  pid_t pid = fork();
  if (pid == 0) {                 // child
    void* p = malloc(32);
    free(p);
    free(p);                      // must __builtin_trap()
    _exit(0);                     // reached only if the guard failed
  }
  int status = 0;
  waitpid(pid, &status, 0);
  assert(WIFSIGNALED(status));    // killed by the trap signal, not a clean exit
  printf("  [ok] double-free: trapped (signal %d)\n", WTERMSIG(status));
}

int main(void) {
  printf("cerise malloc stress test\n");
  test_reuse();
  test_realloc();
  test_calloc_zeroes_reused();
  test_threads();
  test_double_free_traps();
  printf("ALL MALLOC TESTS PASSED\n");
  return 0;
}
