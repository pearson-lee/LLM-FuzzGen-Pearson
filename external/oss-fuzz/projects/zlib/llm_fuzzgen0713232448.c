#include "/src/zlib/zlib.h"
#include "/src/zlib/zconf.h"
#include "/src/zlib/deflate.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// Helper to consume one byte for configuration.
static uint8_t consume_byte(const uint8_t **data, size_t *size) {
    if (*size < 1) {
        return 0;
    }
    uint8_t val = **data;
    (*data)++;
    (*size)--;
    return val;
}

// Helper to consume a long for configuration.
static long consume_long(const uint8_t **data, size_t *size) {
    if (*size < sizeof(long)) {
        return 0;
    }
    long val;
    memcpy(&val, *data, sizeof(long));
    *data += sizeof(long);
    *size -= sizeof(long);
    return val;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // A copy of the pointers is used for consuming configuration bytes.
  const uint8_t *fuzz_ptr = data;
  size_t fuzz_size = size;

  // The original data and size are passed to functions that use the whole buffer.
  const Bytef *initial_data = (const Bytef *)data;
  size_t initial_size = size;

  // Target: zlibCompileFlags (low coverage)
  zlibCompileFlags();

  // Target: crc32_z
  {
    uLong crc = crc32(0L, Z_NULL, 0);
    crc32_z(crc, initial_data, initial_size);
  }

  // Target: inflateCopy (error paths)
  {
    z_stream dest_stream;
    z_stream source_stream;

    // Invalid source (uninitialized stream)
    // First, ensure all fields are NULL to avoid using uninitialized memory.
    memset(&source_stream, 0, sizeof(z_stream));
    inflateCopy(&dest_stream, &source_stream);

    // NULL destination
    source_stream.zalloc = Z_NULL;
    source_stream.zfree = Z_NULL;
    source_stream.opaque = Z_NULL;
    if (inflateInit(&source_stream) == Z_OK) {
        inflateCopy(NULL, &source_stream);
        inflateEnd(&source_stream);
    }

    z_stream src, dst;
    src.zalloc = Z_NULL;
    src.zfree = Z_NULL;
    src.opaque = Z_NULL;
    src.avail_in = (uInt)initial_size;
    src.next_in = (Bytef *)initial_data;

    if (inflateInit(&src) == Z_OK) {
        size_t out_buffer_size = initial_size > 500000 ? 1000000 : initial_size * 2 + 100;
        unsigned char *out_buffer = (unsigned char *)malloc(out_buffer_size);
        if (out_buffer) {
            src.avail_out = out_buffer_size;
            src.next_out = out_buffer;
            inflate(&src, Z_NO_FLUSH);

            if (inflateCopy(&dst, &src) == Z_OK) {
                inflateEnd(&dst);
            }
            free(out_buffer);
        }
        inflateEnd(&src);
    }
  }

  // Target: _tr_tally (0% coverage)
  {
    z_stream def_stream;
    def_stream.zalloc = Z_NULL;
    def_stream.zfree = Z_NULL;
    def_stream.opaque = Z_NULL;

    int level = (consume_byte(&fuzz_ptr, &fuzz_size) % 9) + 1;
    if (deflateInit(&def_stream, level) == Z_OK) {
      uLong bound = deflateBound(&def_stream, initial_size);
      if (bound < 1000000) { // Prevent excessive allocation
          unsigned char* def_buffer = (unsigned char*)malloc(bound);
          if (def_buffer) {
            def_stream.avail_in = initial_size;
            def_stream.next_in = (Bytef *)initial_data;
            def_stream.avail_out = bound;
            def_stream.next_out = def_buffer;

            int flush_options[] = {Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH};
            int flush = flush_options[consume_byte(&fuzz_ptr, &fuzz_size) % 4];

            deflate(&def_stream, flush);
            free(def_buffer);
          }
      }
      deflateEnd(&def_stream);
    }
  }

  // Target: gz functions (gzopen, gzclose, gzwrite, gzread, gzseek, gztell)
  {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    gzFile file = gzopen(path, "wb");
    if (file) {
      gzwrite(file, initial_data, initial_size);
      gzclose(file);
    }

    file = gzopen(path, "rb");
    if (file) {
      unsigned char* read_buffer = (unsigned char*)malloc(initial_size);
      if (read_buffer) {
        gzread(file, read_buffer, initial_size);
        free(read_buffer);
      }
      gzseek(file, consume_long(&fuzz_ptr, &fuzz_size), SEEK_SET);
      gztell(file);
      gzclose(file);
    }
    unlink(path);
  }

  return 0;
}