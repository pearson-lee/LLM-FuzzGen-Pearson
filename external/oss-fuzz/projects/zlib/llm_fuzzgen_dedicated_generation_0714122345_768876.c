/* BLOCKER_STRATEGY_CONTRACT
required_state: The `z_stream`'s internal state must have an allocated window (`state->window != Z_NULL`) and the window bits (`state->wbits`) must differ from the `windowBits` parameter passed to `inflateReset2`.
state_constructor: Call `inflateInit()` to initialize the stream, which sets `state->wbits` to the default of 15. Then call `inflate()` on some compressed data, which forces the allocation of `state->window`.
trigger_api: A subsequent call to `inflateReset2()` with a `windowBits` parameter that is not 15.
preserved_invariants: N/A, this is a new target.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

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

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    // Initialize with default window bits (15)
    if (inflateInit(&strm) != Z_OK) {
        return 0;
    }

    const int max_input_size = 4096;
    const uint8_t *compr_buf = NULL;
    size_t compr_buf_size = ConsumeBytes(&fdp, &compr_buf, (size_t)ConsumeInRange(&fdp, 0, max_input_size));

    if (compr_buf_size > 0) {
        unsigned char out_buf[4096];

        strm.next_in = (Bytef *)compr_buf;
        strm.avail_in = compr_buf_size;
        strm.next_out = out_buf;
        strm.avail_out = sizeof(out_buf);

        // This call to inflate() is expected to allocate state->window if the input
        // stream is valid and contains distance codes.
        inflate(&strm, Z_SYNC_FLUSH);
    }

    // Now, call inflateReset2 with different windowBits to trigger the free.
    // The original wbits is 15. We use a fuzzer-derived value between 8 and 14.
    int new_window_bits = ConsumeInRange(&fdp, 8, 14);
    inflateReset2(&strm, new_window_bits);

    inflateEnd(&strm);

    return 0;
}