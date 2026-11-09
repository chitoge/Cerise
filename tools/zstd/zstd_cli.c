// Copyright 2026 The Cerise Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.
//
// Minimal hermetic zstd compress/decompress CLI, built from the vendored
// //third_party/zstd sources (no dependency on a host /usr/bin/zstd). Used by:
//
//   * tools/zbi/simple_zbi.py  -- to zstd-compress the STORAGE_BOOTFS payload
//     of a product ZBI (build-time), matching upstream zbi.cc's default
//     compression level (4).
//   * the host-side bootfs inspectors (assembly/tools/bootfs_diff.py and the
//     //validation ELF gates) -- to decompress a compressed STORAGE_BOOTFS
//     item before parsing it.
//
// Frame format: plain one-shot ZSTD_compress. Long-distance matching is
// deliberately NOT enabled (unlike upstream zbi.cc at level >= 4) so the frame
// stays inside a modest window log -- userboot decompresses the bootfs with a
// fixed-size static DCtx (src/lib/zbitl/zstd.cc), and a small window keeps that
// one-shot path unconditionally safe. ZSTD_compress writes the decompressed
// content size into the frame header, so `decompress` needs no side channel.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zstd/zstd.h>

static void* read_file(const char* path, size_t* out_size) {
  FILE* f = fopen(path, "rb");
  if (!f) {
    perror(path);
    exit(1);
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    perror("fseek");
    exit(1);
  }
  long n = ftell(f);
  if (n < 0) {
    perror("ftell");
    exit(1);
  }
  rewind(f);
  void* buf = malloc((size_t)n ? (size_t)n : 1);
  if (!buf) {
    fprintf(stderr, "out of memory reading %s\n", path);
    exit(1);
  }
  if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
    perror("fread");
    exit(1);
  }
  fclose(f);
  *out_size = (size_t)n;
  return buf;
}

static void write_file(const char* path, const void* data, size_t n) {
  FILE* f = fopen(path, "wb");
  if (!f) {
    perror(path);
    exit(1);
  }
  if (n > 0 && fwrite(data, 1, n, f) != n) {
    perror("fwrite");
    exit(1);
  }
  if (fclose(f) != 0) {
    perror("fclose");
    exit(1);
  }
}

int main(int argc, char** argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s compress|decompress IN OUT [LEVEL]\n", argv[0]);
    return 2;
  }
  const char* mode = argv[1];
  const char* in_path = argv[2];
  const char* out_path = argv[3];

  size_t in_size = 0;
  void* in_buf = read_file(in_path, &in_size);

  if (strcmp(mode, "compress") == 0) {
    int level = (argc >= 5) ? atoi(argv[4]) : 4;
    size_t bound = ZSTD_compressBound(in_size);
    void* out_buf = malloc(bound ? bound : 1);
    if (!out_buf) {
      fprintf(stderr, "out of memory\n");
      return 1;
    }
    size_t r = ZSTD_compress(out_buf, bound, in_buf, in_size, level);
    if (ZSTD_isError(r)) {
      fprintf(stderr, "zstd compress failed: %s\n", ZSTD_getErrorName(r));
      return 1;
    }
    write_file(out_path, out_buf, r);
    free(out_buf);
  } else if (strcmp(mode, "decompress") == 0) {
    unsigned long long content = ZSTD_getFrameContentSize(in_buf, in_size);
    if (content == ZSTD_CONTENTSIZE_ERROR) {
      fprintf(stderr, "zstd decompress: %s is not a valid zstd frame\n", in_path);
      return 1;
    }
    if (content == ZSTD_CONTENTSIZE_UNKNOWN) {
      fprintf(stderr, "zstd decompress: %s has unknown content size\n", in_path);
      return 1;
    }
    void* out_buf = malloc((size_t)content ? (size_t)content : 1);
    if (!out_buf) {
      fprintf(stderr, "out of memory\n");
      return 1;
    }
    size_t r = ZSTD_decompress(out_buf, (size_t)content, in_buf, in_size);
    if (ZSTD_isError(r)) {
      fprintf(stderr, "zstd decompress failed: %s\n", ZSTD_getErrorName(r));
      return 1;
    }
    write_file(out_path, out_buf, r);
    free(out_buf);
  } else {
    fprintf(stderr, "unknown mode %s (want compress|decompress)\n", mode);
    return 2;
  }

  free(in_buf);
  return 0;
}
