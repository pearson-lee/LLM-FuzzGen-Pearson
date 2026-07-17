#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/gzguts.h"

// Forward declaration for gz_intmax as it's not in a public header
unsigned ZLIB_INTERNAL gz_intmax(void);

// Define the macro if it's not provided by the build system (for local testing)
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0713224313"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) { // Increased minimum size for new operations
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
        gzwrite(file, data, size);
        gzflush(file, Z_FINISH);
        gzclose_w(file);

        file = gzopen(path, "rb");
        if (file) {
            char buffer[256];
            gzread(file, buffer, sizeof(buffer));
            gztell(file);
            if (size > 10) {
                gzseek(file, 10, SEEK_SET);
            }
            /*
             * ANALYSIS: The function-level coverage report showed gzgetc_ at 0%.
             * IMPLEMENTATION: Call gzgetc_ to exercise this previously uncovered function.
             */
            (void)gzgetc_(file);
            gzeof(file);
            int err_no = 0;
            gzerror(file, &err_no);
            gzclearerr(file);
            /*
             * ANALYSIS: The function-level coverage report showed gzclose had a missed
             *           branch, while gzclose_r and gzclose_w were being used.
             * IMPLEMENTATION: Use gzclose to target the generic close function's
             *                 dispatch logic.
             */
            gzclose(file);
        }
    }
    unlink(path);

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    gz_header header; // Moved declaration to outer scope to fix use-after-scope

    int level = data[0] % 10;
    if (size > 1) {
        level = data[1] % 12 - 2;
    }
    
    int windowBits;
    /*
     * ANALYSIS: The existing fuzzer generated a narrow range of windowBits,
     *           failing to create gzip or raw deflate streams. This left code
     *           paths, such as gzip header handling in deflateBound, uncovered.
     * IMPLEMENTATION: Explicitly generate windowBits values for zlib, gzip,
     *                 and raw deflate streams to ensure all three modes are tested.
     */
    uint8_t choice = data[2] % 3;
    if (choice == 0) { // zlib
        windowBits = 8 + (data[0] % 8);
    } else if (choice == 1) { // raw
        windowBits = -(8 + (data[0] % 8));
    } else { // gzip
        windowBits = 16 + (8 + (data[0] % 8));
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

    /*
     * ANALYSIS: The line-coverage for deflateBound showed that the code path for
     *           handling user-supplied gzip headers was not exercised. This occurs
     *           when s->gzhead is non-NULL.
     * IMPLEMENTATION: When gzip wrapping is requested via windowBits ( > 15),
     *                 we call deflateSetHeader() with a fuzzer-populated gz_header
     *                 structure. This covers the previously unreachable code in
     *                 deflateBound and also exercises deflateSetHeader itself.
     */
    if (windowBits > 15 && size > 15) {
        header.text = data[4] % 2;
        header.hcrc = data[5] % 2;
        header.done = 0;
        header.os = data[6];
        header.time = data[7] | (data[8] << 8) | (data[9] << 16) | (data[10] << 24);
        header.extra = Z_NULL;
        header.extra_len = 0;
        header.name = Z_NULL;
        header.comment = Z_NULL;
        deflateSetHeader(&strm, &header);
    }

    size_t dictionary_size = 0;
    if (size > 4) {
        dictionary_size = (size - 4) / 4; // Reduced size to avoid starving input
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

    uint8_t* mutable_input = (uint8_t*)malloc(input_size);
    if (!mutable_input) {
        deflateEnd(&strm);
        return 0;
    }
    memcpy(mutable_input, data + input_offset, input_size);

    /*
     * ANALYSIS: The function-level coverage report showed _tr_tally at 0%.
     *           This function is called when the compressor finds matching
     *           sequences. Random data from the fuzzer is unlikely to have
     *           many matches.
     * IMPLEMENTATION: To increase the likelihood of matches, we make the
     *                 input data more repetitive. If the input is large enough,
     *                 we copy the first quarter of the data over the second
     *                 quarter. This should create repetitions that the deflate
     *                 algorithm can find and report via _tr_tally.
     */
    if (input_size > 100) {
        memcpy(mutable_input + (input_size / 4), mutable_input, input_size / 4);
    }

    size_t comprLen;
    if (input_size > 1 && (data[0] % 2 == 0)) {
        comprLen = input_size / 2;
        if (comprLen == 0) comprLen = 1;
    } else {
        comprLen = deflateBound(&strm, input_size);
    }
    
    if (comprLen == 0) {
        free(mutable_input);
        deflateEnd(&strm);
        return 0;
    }

    uint8_t *compr = (uint8_t *)malloc(comprLen);
    if (!compr) {
        free(mutable_input);
        deflateEnd(&strm);
        return 0;
    }

    strm.next_in = (Bytef *)mutable_input;
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
    
    free(mutable_input);
    free(compr);
    if (dict_out) {
        free(dict_out);
    }
    
    (void)gz_intmax();

    return 0;
}