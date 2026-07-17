#include "/src/zlib/zlib.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_ERR(err, msg)                                                    \
  {                                                                            \
    if (err != Z_OK) {                                                         \
      return 0;                                                                \
    }                                                                          \
  }

static const int kMaxDecompressedSize = 1024 * 1024; // 1MB

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char *decompressed_buffer =
      (unsigned char *)malloc(kMaxDecompressedSize);
  if (!decompressed_buffer) {
    return 0;
  }

  z_stream z;
  memset(&z, 0, sizeof(z));

  z.next_in = (Bytef *)data;
  z.avail_in = size;
  z.next_out = decompressed_buffer;
  z.avail_out = kMaxDecompressedSize;

  int err = inflateInit(&z);
  CHECK_ERR(err, "inflateInit");

  err = inflate(&z, Z_FINISH);
  if (err != Z_STREAM_END) {
    inflateEnd(&z);
    free(decompressed_buffer);
    return 0;
  }

  inflateEnd(&z);
  free(decompressed_buffer);
  return 0;
}