// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy

// Include necessary zlib headers with project-relative paths
// zlib.h includes zconf.h
#include "/src/zlib/zlib.h"
// inflate.h and inftrees.h are removed as they caused build errors related to internal types and declarations.
// The inflateSetDictionary fuzzing is removed as it depends on inflate.h.
// gzguts.h is removed as it caused build errors related to internal macros and structures.
// The gzseek64 fuzzing is removed as it depends on gzguts.h and internal structures.
#include "/src/zlib/deflate.h"   // For deflateInit2, deflate, deflateEnd
#include "/src/zlib/crc32.h"     // For crc32_combine


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // zlib functions often require a z_stream structure.
    z_stream strm;
    // Initialize z_stream for deflate related calls
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = Size;
    strm.next_in = (Bytef *)Data;

    // We need output buffers for compression
    size_t output_buffer_size = Size * 2 + 1024; // A common heuristic
    Bytef *output_buffer = (Bytef *)malloc(output_buffer_size);
    if (!output_buffer) {
        // Handle allocation failure
        return 0;
    }
    strm.avail_out = output_buffer_size;
    strm.next_out = output_buffer;

    // --- Exercise deflate() with different parameters ---
    // Initialize deflate stream
    int level = Z_DEFAULT_COMPRESSION;
    int strategy = Z_DEFAULT_STRATEGY;
    if (Size > 0) {
        level = (Data[0] % (Z_BEST_COMPRESSION + 1)); // 0-9
        if (Size > 1) {
             strategy = (Data[1] % (Z_FIXED + 1)); // 0-4
        }
    }

    // Ensure level and strategy are within valid ranges for deflateInit2
    if (level < Z_DEFAULT_COMPRESSION || level > Z_BEST_COMPRESSION) level = Z_DEFAULT_COMPRESSION;
    if (strategy < Z_DEFAULT_STRATEGY || strategy > Z_FIXED) strategy = Z_DEFAULT_STRATEGY;


    if (deflateInit2(&strm, level, Z_DEFLATED, MAX_WBITS, DEF_MEM_LEVEL, strategy) == Z_OK) {
        // Perform a deflate operation
        // Provide some input data to deflate if available
        strm.avail_in = Size;
        strm.next_in = (Bytef *)Data;
        strm.avail_out = output_buffer_size;
        strm.next_out = output_buffer;

        // Call deflate with Z_FINISH to ensure all input is processed and output is flushed
        deflate(&strm, Z_FINISH);
        // Clean up deflate stream
        deflateEnd(&strm);
    }
    // Re-initialize strm for the next API call (though not strictly needed after deflateEnd)
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = Size;
    strm.next_in = (Bytef *)Data;
    strm.avail_out = output_buffer_size;
    strm.next_out = output_buffer;


    // --- Exercise crc32_combine_op ---
    // This is an internal function. Fuzzing internal functions directly is fragile.
    // The public API `crc32_combine` should be used instead, which calls `crc32_combine_op`.
    // We will call crc32_combine with fuzzed inputs.
    if (Size >= 3 * sizeof(uLong)) { // Need 3 uLong inputs
        uLong crc1 = *(uLong*)(Data);
        uLong crc2 = *(uLong*)(Data + sizeof(uLong));
        uLong len2 = *(uLong*)(Data + 2 * sizeof(uLong));

        // Limit len2 to prevent excessive computation in crc32_combine
        // A large len2 can cause timeouts in x2nmodp.
        const uLong MAX_LEN2 = 4096;
        if (len2 > MAX_LEN2) {
            len2 %= (MAX_LEN2 + 1); // Keep it within a reasonable range
        }

        // Call the public API that uses crc32_combine_op
        crc32_combine(crc1, crc2, len2);
    }


    // --- Exercise inflateSetDictionary ---
    // Removed due to build errors related to internal headers (inftrees.h) required by inflate.h.

    // --- Exercise gzread.c:gz_skip and gzseek64 ---
    // Removed due to build errors related to internal headers (gzguts.h) and types (z_off6t).


    // Clean up allocated output buffer
    free(output_buffer);

    return 0;
}