/* BLOCKER_STRATEGY_CONTRACT
required_state: strm->next_out == Z_NULL when calling inflate()
state_constructor: After a normal deflate/inflate sequence, a new z_stream is initialized with inflateInit(). Then, its next_out member is explicitly set to Z_NULL before calling inflate().
trigger_api: inflate()
preserved_invariants: The original test_deflate() and test_inflate() calls are preserved. The new logic is added after them and reuses the compressed buffer created by test_deflate().
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        return 0; \
    } \
}

static const uint8_t *data;
static size_t dataLen;
static alloc_func zalloc = NULL;
static free_func zfree = NULL;

/* ===========================================================================
 * Test deflate() with small buffers
 */
int test_deflate(unsigned char *compr, size_t comprLen) {
  z_stream c_stream; /* compression stream */
  int err;
  unsigned long len = dataLen;

  c_stream.zalloc = zalloc;
  c_stream.zfree = zfree;
  c_stream.opaque = (void *)0;

  err = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);
  CHECK_ERR(err, "deflateInit");

  c_stream.next_in = (Bytef *)data;
  c_stream.next_out = compr;

  while (c_stream.total_in != len && c_stream.total_out < comprLen) {
    c_stream.avail_in = c_stream.avail_out = 1; /* force small buffers */
    err = deflate(&c_stream, Z_NO_FLUSH);
    CHECK_ERR(err, "deflate small 1");
  }
  /* Finish the stream, still forcing small buffers: */
  for (;;) {
    c_stream.avail_out = 1;
    err = deflate(&c_stream, Z_FINISH);
    if (err == Z_STREAM_END)
      break;
    CHECK_ERR(err, "deflate small 2");
  }

  err = deflateEnd(&c_stream);
  CHECK_ERR(err, "deflateEnd");
  return 0;
}

/* ===========================================================================
 * Test inflate() with small buffers
 */
int test_inflate(unsigned char *compr, size_t comprLen, unsigned char *uncompr,
                  size_t uncomprLen) {
  int err;
  z_stream d_stream; /* decompression stream */

  d_stream.zalloc = zalloc;
  d_stream.zfree = zfree;
  d_stream.opaque = (void *)0;

  d_stream.next_in = compr;
  d_stream.avail_in = 0;
  d_stream.next_out = uncompr;

  err = inflateInit(&d_stream);
  CHECK_ERR(err, "inflateInit");

  while (d_stream.total_out < uncomprLen && d_stream.total_in < comprLen) {
    d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
    err = inflate(&d_stream, Z_NO_FLUSH);
    if (err == Z_STREAM_END)
      break;
    CHECK_ERR(err, "inflate");
  }

  err = inflateEnd(&d_stream);
  CHECK_ERR(err, "inflateEnd");

  if (memcmp(uncompr, data, dataLen)) {
    fprintf(stderr, "bad inflate\n");
    return 0;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {
  size_t comprLen = compressBound(size);
  size_t uncomprLen = size;
  uint8_t *compr, *uncompr;

  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;

  if (size < 1 || size > kMaxSize)
    return 0;

  data = d;
  dataLen = size;
  compr = (uint8_t *)calloc(1, comprLen);
  uncompr = (uint8_t *)calloc(1, uncomprLen);

  test_deflate(compr, comprLen);
  test_inflate(compr, comprLen, uncompr, uncomprLen);

  // --- Start of blocker-specific code ---
  // The goal is to call inflate() with a stream where next_out is NULL.
  // This triggers the `strm->next_out == Z_NULL` check in inflate.c:610.
  z_stream d_stream_blocker;
  d_stream_blocker.zalloc = zalloc;
  d_stream_blocker.zfree = zfree;
  d_stream_blocker.opaque = (void *)0;
  d_stream_blocker.avail_in = 0;
  d_stream_blocker.next_in = Z_NULL;

  int err = inflateInit(&d_stream_blocker);
  if (err == Z_OK) {
    // Setup stream state to trigger the blocker.
    d_stream_blocker.next_in = compr;
    d_stream_blocker.avail_in = comprLen;
    d_stream_blocker.next_out = Z_NULL;
    d_stream_blocker.avail_out = 0;

    // This call to inflate() is intended to trigger the blocker.
    // The return value is expected to be Z_STREAM_ERROR.
    inflate(&d_stream_blocker, Z_NO_FLUSH);

    inflateEnd(&d_stream_blocker);
  }
  // --- End of blocker-specific code ---

  free(compr);
  free(uncompr);

  /* This function must return 0. */
  return 0;
}