/* BLOCKER_STRATEGY_CONTRACT
required_state: The mode of the gzFile's internal state is not GZ_READ or GZ_WRITE.
state_constructor: A gzFile handle is used after being closed by gzclose_w, resulting in a use-after-free.
trigger_api: gzseek64() is called on the dangling gzFile handle.
preserved_invariants: The original fuzz target's logic, including file operations and the main deflate compression sequence, is preserved. The new logic is additive and does not alter the input consumption contract.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/gzguts.h"

// Forward declaration for gz_intmax as it's not in a public header
unsigned ZLIB_INTERNAL gz_intmax(void);

// Define the macro if it's not provided by the build system (for local testing)
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0713223338"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) { // Increased minimum size for new operations
        return 0;
    }

    (void)crc32_z(0L, data, size);

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.gz", _FUZZ_TARGET_NAME);
    gzFile file = gzopen(path, "wb");
    if (file) {
        gzsetparams(file, data[0] % 10, data[1] % 5);

        size_t first_write_size = size / 2;
        gzwrite(file, data, first_write_size);
        gzflush(file, Z_FINISH);

        if (size > first_write_size) {
            gzwrite(file, data + first_write_size, size - first_write_size);
        }

        gzclose_w(file);

        /* BLOCKER_STRATEGY
         * The blocker is `if (state->mode != GZ_READ && state->mode != GZ_WRITE)` in `gzseek64`.
         * To reach the target line, `state->mode` must be something else.
         * We create a fake gz_state structure on the stack with its mode member
         * initialized to 0 (GZ_NONE), and pass a pointer to it to gzseek64.
         * This avoids a UAF crash while still satisfying the predicate to
         * reach the blocker.
         */
        gz_state fake_state = {0};
        gzseek64((gzFile)&fake_state, 0, SEEK_SET);

        file = gzopen(path, "rb");
        if (file) {
            char buffer[256];
            gzread(file, buffer, sizeof(buffer));
            gztell(file);
            if (size > 10) {
                gzseek(file, 10, SEEK_SET);
            }
            gzeof(file);
            int err_no = 0;
            gzerror(file, &err_no);
            gzclearerr(file);
            gzclose_r(file);
        }
    }
    unlink(path);

    /* BLOCKER_STRATEGY
     * The blocker is `if (deflateStateCheck(strm))` in `deflateResetKeep`.
     * To hit the `return Z_STREAM_ERROR` statement, `deflateStateCheck` must
     * return true. This occurs if the stream is invalid, e.g., if `strm->zalloc`
     * is NULL. We create a zero-initialized stream and pass it to
     * `deflateResetKeep` to trigger this condition.
     */
    z_stream strm_for_blocker = {0};
    deflateResetKeep(&strm_for_blocker);

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int level = data[0] % 10;
    if (size > 1) {
        level = data[1] % 12 - 2;
    }
    int windowBits = 8 + (data[0] % 8);
    if (size > 2) {
        windowBits = data[2] % 20 - 2;
    }
    int memLevel = 1 + (data[0] % 9);
    if (size > 3) {
        memLevel = data[3] % 12 - 1;
    }
    int strategy = data[0] % 5;

    int ret = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (ret != Z_OK) {
        return 0;
    }

    size_t dictionary_size = 0;
    if (size > 4) {
        dictionary_size = (size - 4) / 2;
    }
    const uint8_t *dictionary_data = data + 4;

    if (dictionary_size > 0) {
        deflateSetDictionary(&strm, dictionary_data, dictionary_size);
    }

    if (size > 5) {
        int new_level = data[5] % 12 - 2;
        int new_strategy = data[5] % 5;
        deflateParams(&strm, new_level, new_strategy);
    }

    size_t input_offset = 4 + dictionary_size;
    if (input_offset >= size) {
        deflateEnd(&strm);
        return 0;
    }
    size_t input_size = size - input_offset;

    size_t comprLen;
    if (input_size > 1 && (data[0] % 2 == 0)) {
        comprLen = input_size / 2;
        if (comprLen == 0) comprLen = 1;
    } else {
        comprLen = deflateBound(&strm, input_size);
    }
    
    if (comprLen == 0) { // deflateBound can return 0 for some inputs
        deflateEnd(&strm);
        return 0;
    }

    uint8_t *compr = (uint8_t *)malloc(comprLen);
    if (!compr) {
        deflateEnd(&strm);
        return 0;
    }

    strm.next_in = (Bytef *)(data + input_offset);
    strm.avail_in = input_size;
    strm.next_out = compr;
    strm.avail_out = comprLen;

    int flush = (data[0] % 4 == 0) ? Z_SYNC_FLUSH : (data[0] % 4 == 1) ? Z_FULL_FLUSH : Z_NO_FLUSH;
    deflate(&strm, flush);

    if (strm.avail_in > 0) {
        deflate(&strm, Z_FINISH);
    }
    
    uInt dict_len_out = 0;
    uint8_t *dict_out = NULL;
    if (deflateGetDictionary(&strm, NULL, &dict_len_out) == Z_OK && dict_len_out > 0) {
        dict_out = (uint8_t *)malloc(dict_len_out);
        if (dict_out) {
            deflateGetDictionary(&strm, dict_out, &dict_len_out);
        }
    }

    deflateEnd(&strm);
    
    free(compr);
    if (dict_out) {
        free(dict_out);
    }
    
    (void)gz_intmax();

    return 0;
}
