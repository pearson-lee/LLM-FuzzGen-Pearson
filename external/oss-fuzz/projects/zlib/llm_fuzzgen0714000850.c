#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "/src/zlib/zlib.h"

// Compile-time macro to ensure unique temporary filenames.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzzer"
#endif

// --- Fuzz data provider helpers ---
typedef struct {
  const uint8_t *Data;
  size_t Size;
  size_t Offset;
} FuzzData;

// Returns 1 on success, 0 on failure
static int Consume(FuzzData *f, void *dest, size_t size) {
  if (f->Offset + size > f->Size) {
    return 0;
  }
  memcpy(dest, f->Data + f->Offset, size);
  f->Offset += size;
  return 1;
}

static int ConsumeInRange(FuzzData *f, int min, int max) {
  if (min > max)
    return min;
  int value;
  if (!Consume(f, &value, sizeof(value))) {
    return min;
  }
  if (min == max)
    return min;
  return min + (abs(value) % (max - min + 1));
}

static int ConsumeBool(FuzzData *f) {
  uint8_t b;
  if (!Consume(f, &b, sizeof(b))) {
    return 0;
  }
  return b & 1;
}

static size_t ConsumeBytes(FuzzData *f, const uint8_t **out_ptr,
                           size_t desired_size) {
  if (f->Offset + desired_size > f->Size) {
    desired_size = f->Size - f->Offset;
  }
  *out_ptr = f->Data + f->Offset;
  f->Offset += desired_size;
  return desired_size;
}
// --- End of helpers ---

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzData fdp = {data, size, 0};

  // Generate a unique path for the temporary file.
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

  // Create and open the temporary file.
  FILE *fp = fopen(path, "wb");
  if (!fp) {
    return 0;
  }
  int fd = fileno(fp);

  gzFile file_w = gzdopen(fd, "wb");
  if (file_w) {
    if (ConsumeBool(&fdp)) {
      gzseek(file_w, ConsumeInRange(&fdp, 0, 1024), SEEK_SET);
    }
    gzsetparams(file_w, ConsumeInRange(&fdp, -1, 9),
                ConsumeInRange(&fdp, -1, Z_FIXED + 1));
    gzclose(file_w);
  }
  fclose(fp);

  fp = fopen(path, "rb");
  if (fp) {
    fd = fileno(fp);
    gzFile file_r = gzdopen(fd, "rb");
    if (file_r) {
      gzsetparams(file_r, ConsumeInRange(&fdp, -1, 9),
                  ConsumeInRange(&fdp, -1, Z_FIXED + 1));
      gzclose(file_r);
    }
    fclose(fp);
  }

  gzsetparams(NULL, ConsumeInRange(&fdp, -1, 9),
              ConsumeInRange(&fdp, -1, Z_FIXED + 1));

  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;

  if (deflateInit(&strm,
                  ConsumeInRange(&fdp, -1, Z_DEFAULT_COMPRESSION)) == Z_OK) {
    const uint8_t *input_buf = NULL;
    size_t input_buf_size = ConsumeBytes(
        &fdp, &input_buf, (size_t)ConsumeInRange(&fdp, 0, 1024));
    strm.avail_in = (uInt)input_buf_size;
    strm.next_in = (Bytef *)input_buf;
    deflateParams(&strm, ConsumeInRange(&fdp, -1, 9),
                  ConsumeInRange(&fdp, -2, Z_FIXED + 2));
    deflateEnd(&strm);
  }
  // Call with an invalid stream to trigger state check.
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  deflateParams(&strm, 0, 0);

  if (inflateInit(&strm) == Z_OK) {
    if (ConsumeBool(&fdp)) {
      inflateReset2(&strm, ConsumeInRange(&fdp, -20, -1));
    } else {
      inflateReset2(&strm, ConsumeInRange(&fdp, 8, 15));
      inflateReset2(&strm, ConsumeInRange(&fdp, 8, 15));
    }
    inflateEnd(&strm);
  }
  // Call with an invalid stream to trigger state check.
  inflateReset2(NULL, 15);

  // Clean up the temporary file.
  unlink(path);

  return 0;
}