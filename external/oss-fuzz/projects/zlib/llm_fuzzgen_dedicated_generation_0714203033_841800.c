/* BLOCKER_STRATEGY_CONTRACT
required_state: The `state->head` member of the internal `inflate_state` struct must not be `Z_NULL` when the predicate at `inflate.c:684` is evaluated.
state_constructor: `inflateInit2` is called with `windowBits = 15 + 16` to enable gzip stream processing. A `gz_header` struct is initialized and passed to `inflateGetHeader` to associate it with the `z_stream`, which sets the internal `state->head` pointer.
trigger_api: `inflate()` is called with a `z_stream` configured for gzip header parsing and with input data provided by the fuzzer.
preserved_invariants: This is a new target, so there are no invariants to preserve from a previous version of this specific target. It's a complete departure from the reference target's logic.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    z_stream strm;
    gz_header head;
    unsigned char out[4096];

    /* Basic stream initialization */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    /*
     * ANALYSIS: The blocker `if (state->head != Z_NULL)` requires the internal
     *           `head` pointer to be non-NULL. This pointer is used for storing
     *           gzip header information. The previous attempt via `gzread` failed
     *           because the underlying `inflateInit2` call did not enable gzip
     *           header parsing.
     * IMPLEMENTATION: To solve this, we call `inflateInit2` directly with a
     *                 `windowBits` parameter of `15 + 16`, which enables gzip
     *                 decoding. Then, we call `inflateGetHeader` to register a
     *                 `gz_header` struct with the stream. This ensures that the
     *                 internal `state->head` pointer is non-NULL, satisfying the
     *                 blocker's predicate.
     */
    if (inflateInit2(&strm, 15 + 16) != Z_OK) {
        return 0;
    }

    memset(&head, 0, sizeof(head));
    if (inflateGetHeader(&strm, &head) != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    /* Provide buffers for header fields to be filled by inflate */
    unsigned char extra[256];
    unsigned char name[256];
    unsigned char comment[256];
    head.extra = extra;
    head.extra_max = sizeof(extra);
    head.name = name;
    head.name_max = sizeof(name);
    head.comment = comment;
    head.comm_max = sizeof(comment);

    strm.avail_in = size;
    strm.next_in = (Bytef*)data;

    /* Decompress until the input is consumed or an error occurs */
    int ret;
    do {
        strm.avail_out = sizeof(out);
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret < 0 && ret != Z_BUF_ERROR) { /* Z_BUF_ERROR is not fatal */
            break;
        }
    } while (strm.avail_in > 0 && ret != Z_STREAM_END);

    inflateEnd(&strm);

    return 0;
}
