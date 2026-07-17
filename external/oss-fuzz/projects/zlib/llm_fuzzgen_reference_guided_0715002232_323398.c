/* BLOCKER_STRATEGY_CONTRACT
required_state: The `gzFile` handle passed to `gzclose_w` must have a `state->mode` that is not `GZ_WRITE`.
state_constructor: A `gzFile` handle is created in read mode by calling `gzdopen` with a mode string of "rb".
trigger_api: `gzclose_w(file)` is called on the read-mode handle.
preserved_invariants: The fuzzer's input consumption sequence is preserved. The call to create the read-mode handle is part of the original fuzzer's logic.
END_BLOCKER_STRATEGY_CONTRACT */

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

  // BLOCKER-SPECIFIC CHANGE: Add the 'T' flag to the mode string to set
  // the `state->direct` flag. This is required to reach the blocked code
  // path in `gz_comp`.
  gzFile file_w = gzdopen(fd, "wbT");
  if (file_w) {
    if (ConsumeBool(&fdp)) {
      gzseek(file_w, ConsumeInRange(&fdp, 0, 1024), SEEK_SET);
    }
    gzsetparams(file_w, ConsumeInRange(&fdp, -1, 9),
                ConsumeInRange(&fdp, -1, Z_FIXED + 1));

    const uint8_t *write_buf = NULL;
    size_t write_buf_size =
        ConsumeBytes(&fdp, &write_buf, (size_t)ConsumeInRange(&fdp, 0, 1024));
    if (write_buf_size > 0) {
      gzwrite(file_w, write_buf, write_buf_size);
      char *s = (char *)malloc(write_buf_size + 1);
      if (s) {
        memcpy(s, write_buf, write_buf_size);
        s[write_buf_size] = '\0';
        gzputs(file_w, s);
        /*
         * ANALYSIS: The function-level coverage report showed `gzvprintf` in
         *           `gzwrite.c` had low coverage and was not being called.
         * IMPLEMENTATION: Add a call to `gzprintf` to exercise the
         *                 formatted-writing code path.
         */
        
        // BLOCKER-SPECIFIC CHANGE: Call `gzseek` right before `gzprintf` to set
        // the `state->seek` flag, which is required to pass the blocker at
        // `gzwrite.c:381`. The `seek` flag is cleared by any write operation,
        // so we must call `gzseek` after other writes (`gzwrite`, `gzputs`).
        // The offset is derived from an existing buffer to preserve the input
        // consumption contract.
        if (write_buf_size >= sizeof(int)) {
          int offset_raw = 0;
          memcpy(&offset_raw, write_buf, sizeof(offset_raw));
          // REPAIR: Constrain the seek offset to a small range to prevent
          // timeouts. A large offset causes gz_zero to loop for a long time.
          int offset = abs(offset_raw) % 1025;
          gzseek(file_w, offset, SEEK_SET);
        }

        gzprintf(file_w, "%s", s);
        free(s);
      }
    }
    gzflush(file_w, ConsumeInRange(&fdp, Z_NO_FLUSH, Z_FINISH));
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

      char read_buf[256];
      gzread(file_r, read_buf, sizeof(read_buf) - 1);
      gzgets(file_r, read_buf, sizeof(read_buf) - 1);
      int c = gzgetc(file_r);
      if (c != -1) {
        gzungetc(c, file_r);
      }
      gzeof(file_r);
      int err;
      gzerror(file_r, &err);
      gzclearerr(file_r);

      // BLOCKER-SPECIFIC CHANGE: Call gzclose_w on a read-mode handle.
      // This will cause the predicate `state->mode != GZ_WRITE` to be true,
      // thus crossing the blocker at gzwrite.c:605.
      gzclose_w(file_r);

      // REPAIR: The previous call to gzclose_w on a read handle returns an
      // error without freeing the underlying state, causing a memory leak.
      // gzclose() is called here to correctly free the resources. It will
      // dispatch to gzclose_r() for the read-mode handle.
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
    /*
     * ANALYSIS: The function `_tr_tally` in `trees.c` was completely
     *           uncovered (0% coverage). This is because purely random data
     *           is incompressible and does not trigger the match-finding logic.
     * IMPLEMENTATION: Use `deflateSetDictionary` to provide a predictable
     *                 dictionary. This allows the deflate algorithm to find
     *                 matches between the random input and the dictionary,
     *                 which in turn exercises the `_tr_tally` function.
     */
    const uint8_t *dict = NULL;
    size_t dict_size = ConsumeBytes(&fdp, &dict, (size_t)ConsumeInRange(&fdp, 0, 2048));
    if (dict_size > 0) {
        deflateSetDictionary(&strm, dict, dict_size);
    }

    const uint8_t *input_buf = NULL;
    size_t input_buf_size = ConsumeBytes(
        &fdp, &input_buf, (size_t)ConsumeInRange(&fdp, 0, 1024));
    strm.avail_in = (uInt)input_buf_size;
    strm.next_in = (Bytef *)input_buf;

    char out[4096];
    int flush = Z_NO_FLUSH;
    do {
      strm.avail_out = sizeof(out);
      strm.next_out = (Bytef *)out;
      deflate(&strm, flush);
    } while (strm.avail_out == 0);
    deflate(&strm, Z_FINISH);

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

  /*
   * ANALYSIS: The function-level coverage showed `crc32_z`, `byte_swap`, and
   *           `crc_word_big` had low or zero coverage.
   * IMPLEMENTATION: Call `crc32_z` and `crc32_combine` to exercise the CRC32
   *                 calculation logic, which will improve coverage in these functions.
   */
  const uint8_t *crc_buf = NULL;
  size_t crc_buf_size = ConsumeBytes(&fdp, &crc_buf, (size_t)ConsumeInRange(&fdp, 0, 1024));
  uLong crc1 = crc32_z(0L, crc_buf, crc_buf_size);
  uLong crc2 = crc32_z(crc1, crc_buf, crc_buf_size);
  crc32_combine(crc1, crc2, crc_buf_size);


  zlibCompileFlags();

  // Clean up the temporary file.
  unlink(path);

  return 0;
}