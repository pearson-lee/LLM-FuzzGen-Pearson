#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "/src/zlib/zlib.h"
#include "/src/zlib/zconf.h"

// FuzzedDataProvider is not available in C, so we will use the raw bytes from the fuzzer.
// We will deterministically split the data and use it to exercise different APIs.

#define MAX_COMPRESSED_SIZE 1024 * 1024 // 1MB

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Allocate buffers for compression and decompression
    unsigned char* compressed_buffer = (unsigned char*)malloc(MAX_COMPRESSED_SIZE);
    if (!compressed_buffer) {
        return 0;
    }
    unsigned char* decompressed_buffer = (unsigned char*)malloc(MAX_COMPRESSED_SIZE);
    if (!decompressed_buffer) {
        free(compressed_buffer);
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed zlibCompileFlags had low coverage.
     * IMPLEMENTATION: Call zlibCompileFlags() to exercise this function.
     */
    zlibCompileFlags();

    /*
     * ANALYSIS: The function-level coverage report showed crc32_z had low coverage.
     * IMPLEMENTATION: Call crc32_z on the input data to improve its coverage.
     */
    crc32_z(0L, data, size);


    /*
     * ANALYSIS: The deflate and inflate functions have many uncovered branches.
     *           Specifically, internal functions like _tr_tally are completely uncovered.
     * IMPLEMENTATION: Use deflate and inflate to compress and decompress the input data.
     *                 The parameters for deflateInit2_ are varied based on the input
     *                 data to explore different compression strategies and code paths.
     */
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = size;
    strm.next_in = (Bytef *)data;
    strm.avail_out = MAX_COMPRESSED_SIZE;
    strm.next_out = compressed_buffer;

    // Vary compression parameters based on fuzzer input
    int level = (data[0] % 10) - 1;
    int windowBits = (data[0] % 8) + 8;
    int memLevel = (data[0] % 9) + 1;
    if (size > 1) {
        windowBits = (data[1] % 8) + 8;
        memLevel = (data[1] % 9) + 1;
    }


    if (deflateInit2_(&strm, level, Z_DEFLATED, windowBits, memLevel, Z_DEFAULT_STRATEGY, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
        deflate(&strm, Z_FINISH);
        deflateEnd(&strm);

        // Decompress the data back
        strm.avail_in = strm.total_out;
        strm.next_in = compressed_buffer;
        strm.avail_out = MAX_COMPRESSED_SIZE;
        strm.next_out = decompressed_buffer;

        if (inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
            inflate(&strm, Z_NO_FLUSH);
            inflateEnd(&strm);
        }
    }


    /*
     * ANALYSIS: The gz* functions in gzwrite.c (gzwrite, gzputs, etc.) have low coverage.
     * IMPLEMENTATION: Use gzopen, gzwrite, and gzclose to write compressed data to a
     *                 temporary file, exercising these file-related functions. The file
     *                 is created with a unique name and cleaned up to ensure statelessness.
     */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", "fuzz_target"); // Using a fixed name for simplicity as _FUZZ_TARGET_NAME is a compile-time macro
    gzFile file = gzopen(path, "wb");
    if (file) {
        gzwrite(file, data, size);
        gzclose(file);
        unlink(path);
    }

    // Cleanup
    free(compressed_buffer);
    free(decompressed_buffer);

    return 0;
}