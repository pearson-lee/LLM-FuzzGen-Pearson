#include "/src/zlib/zlib.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// FuzzedDataProvider is not available in C, so we will use the raw data.

// Helper function to allocate memory
static void *zalloc(void *opaque, unsigned int items, unsigned int size) {
    (void)opaque;
    return calloc(items, size);
}

// Helper function to free memory
static void zfree(void *opaque, void *address) {
    (void)opaque;
    free(address);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0;
    }

    z_stream strm_deflate, strm_inflate;
    memset(&strm_deflate, 0, sizeof(strm_deflate));
    memset(&strm_inflate, 0, sizeof(strm_inflate));

    strm_deflate.zalloc = zalloc;
    strm_deflate.zfree = zfree;
    strm_deflate.opaque = Z_NULL;

    strm_inflate.zalloc = zalloc;
    strm_inflate.zfree = zfree;
    strm_inflate.opaque = Z_NULL;

    /*
     * ANALYSIS: The function-level coverage report showed that many functions in
     *           deflate.c, such as deflate, deflateInit2_, and deflateSetDictionary,
     *           have low branch coverage. The line-level report revealed that many
     *           error-handling paths and specific parameter combinations were not
     *           being exercised. For example, in deflateInit2_, checks for invalid
     *           versions, stream pointers, and parameter ranges were uncovered.
     * IMPLEMENTATION: The following code calls deflateInit2_ with a variety of
     *                 parameters derived from the fuzzer input to increase coverage
     *                 of these branches. It also includes specific calls with invalid
     *                 arguments to target error-handling code.
     */
    int level = data[0] % 10;
    int windowBits = 8 + (data[1] % 8);
    int memLevel = 1 + (data[2] % 9);
    int strategy = data[3] % 5;
    data += 4;
    size -= 4;

    // Call with invalid version to trigger Z_VERSION_ERROR
    deflateInit2_(&strm_deflate, level, Z_DEFLATED, windowBits, memLevel, strategy, "1.2.10", sizeof(z_stream));
    deflateEnd(&strm_deflate);

    // Call with NULL stream to trigger Z_STREAM_ERROR
    deflateInit2_(NULL, level, Z_DEFLATED, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

    if (deflateInit2_(&strm_deflate, level, Z_DEFLATED, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream)) != Z_OK) {
        return 0;
    }

    size_t dictionary_len = 0;
    if (size > 10) {
        dictionary_len = data[0] % (size / 2);
        data++;
        size--;
        /*
         * ANALYSIS: The function deflateSetDictionary has uncovered branches related
         *           to the dictionary size and stream state.
         * IMPLEMENTATION: A portion of the fuzzing input is used as a dictionary to
         *                 exercise this functionality.
         */
        if (dictionary_len > 0) {
            deflateSetDictionary(&strm_deflate, data, dictionary_len);
            data += dictionary_len;
            size -= dictionary_len;
        }
    }

    size_t compr_len = deflateBound(&strm_deflate, size);
    uint8_t *compr = (uint8_t *)malloc(compr_len);
    if (!compr) {
        deflateEnd(&strm_deflate);
        return 0;
    }

    strm_deflate.next_in = (Bytef *)data;
    strm_deflate.avail_in = size;
    strm_deflate.next_out = compr;
    strm_deflate.avail_out = compr_len;

    /*
     * ANALYSIS: The main deflate function has complex logic with many branches
     *           related to different flush strategies (Z_NO_FLUSH, Z_SYNC_FLUSH,
     *           Z_FULL_FLUSH, Z_FINISH), which were not fully covered.
     * IMPLEMENTATION: The fuzzer calls deflate with a flush strategy determined
     *                 by the input data, allowing exploration of these different paths.
     */
    int flush = data[0] % 5; // Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH
    if (size > 0) data++, size--;
    deflate(&strm_deflate, flush);

    compr_len = strm_deflate.total_out;
    deflateEnd(&strm_deflate);

    // Create a temporary file for round-trip testing
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", "zlib_fuzzer");
    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(compr, 1, compr_len, fp);
        fclose(fp);

        /*
         * ANALYSIS: Functions in gzread.c, such as gz_avail, have low coverage.
         *           Specifically, the path where data is already available in the
         *           stream's input buffer was not being hit.
         * IMPLEMENTATION: By writing the compressed data to a file and then reading
         *                 it back with gzread, we can create scenarios that exercise
         *                 more of the internal buffering logic within the gz* functions.
         */
        gzFile gzfp = gzopen(path, "rb");
        if (gzfp) {
            size_t uncompr_len = size + dictionary_len;
            uint8_t *uncompr = (uint8_t *)malloc(uncompr_len);
            if (uncompr) {
                gzread(gzfp, uncompr, uncompr_len);
                free(uncompr);
            }
            gzclose(gzfp);
        }
        unlink(path);
    }

    free(compr);

    return 0;
}