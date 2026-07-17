/* BLOCKER_STRATEGY_CONTRACT
required_state: `state->reset == 1` and `strm->avail_in > 0` when `gz_comp` is called.
state_constructor: Call `gzflush(file, Z_FINISH)` to set `state->reset = 1`. Then, call `gzwrite()` with new data to set `strm->avail_in > 0`.
trigger_api: The `gz_comp` call inside the second `gzwrite()` call will have the required state to trigger `deflateReset`.
preserved_invariants: The original fuzz target's sequence of file operations and deflate initializations is maintained. The input consumption contract is not violated; data is just split between two `gzwrite` calls instead of one.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"

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

    /*
     * ANALYSIS: The function-level coverage report showed crc32_z and its
     *           helpers (byte_swap, crc_word_big) had low or zero coverage.
     * IMPLEMENTATION: Directly call crc32_z with fuzzer data to ensure it is
     *                 exercised.
     */
    (void)crc32_z(0L, data, size);

    /*
     * ANALYSIS: The function-level coverage report showed very low coverage for
     *           numerous functions in gzwrite.c and gzread.c (e.g., gzopen,
     *           gzwrite, gzread, gzseek). These file-based APIs were not being
     *           exercised at all.
     * IMPLEMENTATION: Added a block to perform file I/O operations using the
     *                 gz* APIs. This involves creating a temporary file, writing
     *                 compressed data to it, and then reading it back, calling
     *                 various related functions along the way. The temporary file
     *                 is created with a unique name and is deleted before exit to
     *                 maintain a stateless execution.
     */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.gz", _FUZZ_TARGET_NAME);
    gzFile file = gzopen(path, "wb");
    if (file) {
        gzsetparams(file, data[0] % 10, data[1] % 5);

        size_t first_write_size = size / 2;
        gzwrite(file, data, first_write_size);
        gzflush(file, Z_FINISH);

        /* BLOCKER_STRATEGY
         * The blocker is in gz_comp at gzwrite.c:92: `if (strm->avail_in == 0)`,
         * which prevents `deflateReset` from being called. This happens when
         * `state->reset` is true but there's no input.
         * By calling `gzflush(file, Z_FINISH)`, we ensure `state->reset` becomes
         * true. Then, by performing a second `gzwrite()`, we provide input
         * (`strm->avail_in > 0`). The subsequent call to `gz_comp` within this
         * `gzwrite` will have the necessary state to bypass the blocker.
         */
        if (size > first_write_size) {
            gzwrite(file, data + first_write_size, size - first_write_size);
        }

        gzclose_w(file);

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

    /*
     * ANALYSIS: The function-level coverage report showed _tr_tally at 0% and
     *           deflateParams with low coverage. Changing compression parameters
     *           mid-stream can trigger different internal logic.
     * IMPLEMENTATION: Call deflateParams() to change the level and strategy
     *                 dynamically. This increases the chances of hitting different
     *                 compression algorithms and helper functions like _tr_tally.
     */
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
    /*
     * ANALYSIS: The fuzzer coverage report showed the branch at line 72
     *           `if (strm.avail_in > 0)` was never taken. This is because the
     *           output buffer, sized by deflateBound(), was always large enough
     *           to consume all input in a single deflate() call.
     * IMPLEMENTATION: In 50% of cases, the output buffer `comprLen` is
     *                 intentionally made smaller than the input size. This forces
     *                 deflate() to perform partial compression, leaving data in
     *                 `strm.avail_in` and thus exercising the previously uncovered
     *                 branch which calls deflate() with Z_FINISH.
     */
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

    // This block is now reachable due to the smaller comprLen.
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
