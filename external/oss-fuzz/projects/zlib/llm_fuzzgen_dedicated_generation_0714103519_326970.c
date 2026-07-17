/* BLOCKER_STRATEGY_CONTRACT
required_state: huff != 0 in inflate_table. This is reached when processing an incomplete Huffman code, which is only permitted by the function's internal validation if the maximum code length is 1 and the table type is not CODES (i.e., LENS or DISTS).
state_constructor: The fuzzer initializes a z_stream with inflateInit() to obtain an allocated internal state. It then directly manipulates this state to construct a 'lens' array with a single code of length 1, making the code set incomplete. The position of this single code is determined by the fuzzer input.
trigger_api: inflate_table()
preserved_invariants: The fuzzer must correctly use zlib's memory management via inflateInit/inflateEnd. The call to inflate_table must use the buffers allocated within the internal zlib state.
END_BLOCKER_STRATEGY_CONTRACT */

#define ZLIB_INTERNAL
#include "zlib.h"
#include "inftrees.h"
#include "inflate.h"
#include "zutil.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (inflateInit(&strm) != Z_OK) {
        return 0;
    }

    struct inflate_state *state = (struct inflate_state *)strm.state;
    if (state == NULL) {
        inflateEnd(&strm);
        return 0;
    }

    codetype type = LENS;
    unsigned codes = 288;
    
    for (unsigned i = 0; i < codes; i++) {
        state->lens[i] = 0;
    }
    state->lens[data[0] % codes] = 1;

    code *table = state->codes;
    unsigned bits = 9;

    inflate_table(type, state->lens, codes, &table, &bits, state->work);

    inflateEnd(&strm);

    return 0;
}
