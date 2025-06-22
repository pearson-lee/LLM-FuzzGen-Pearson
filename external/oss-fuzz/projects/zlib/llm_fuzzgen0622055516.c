// Your generated fuzz target code here
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy

// Include necessary zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For zlibCompileFlags

// LLVMFuzzerTestOneInput is the entry point for the fuzzer.
// It takes a pointer to the fuzzed data and its size.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t current_offset = 0;

    // Helper macro to safely get a byte from Data and advance the offset.
    // Returns 0 if the offset is out of bounds, preventing out-of-bounds reads.
    #define GET_BYTE_OR_ZERO(data_ptr, offset_ptr, data_size) \
        ((*(offset_ptr) < (data_size)) ? (data_ptr)[(*offset_ptr)++] : 0)

    // 1. Fuzz zlibCompileFlags
    // This function takes no arguments and simply returns a uLong.
    // It's called to exercise its internal logic, which reports compile-time flags.
    zlibCompileFlags();

    // 2. Fuzz deflateInit2_
    z_stream strm_deflate;
    // Initialize z_stream structure to avoid undefined behavior and ensure clean state.
    strm_deflate.zalloc = Z_NULL;
    strm_deflate.zfree = Z_NULL;
    strm_deflate.opaque = Z_NULL;
    strm_deflate.avail_in = 0;
    strm_deflate.next_in = Z_NULL;
    strm_deflate.avail_out = 0;
    strm_deflate.next_out = Z_NULL;

    // Consume bytes from fuzzer input for deflateInit2_ parameters.
    // The modulo operations and additions ensure parameters fall within valid ranges.
    int level = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 10) - 1; // -1 to 9
    // windowBits: 8 to 15 for zlib, -8 to -15 for raw deflate, 24 to 31 for gzip.
    // We use modulo 24 and add 8 to cover a wide range (8 to 31) for better coverage.
    int windowBits_deflate = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 24) + 8;
    int memLevel = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 9) + 1; // 1 to 9
    int strategy = GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 5; // 0-4

    // Map the fuzzed strategy value to a valid Z_ constant defined in zlib.h.
    switch (strategy) {
        case 0: strategy = Z_DEFAULT_STRATEGY; break;
        case 1: strategy = Z_FILTERED; break;
        case 2: strategy = Z_HUFFMAN_ONLY; break;
        case 3: strategy = Z_RLE; break;
        case 4: strategy = Z_FIXED; break;
    }

    // Call deflateInit2_ with the fuzzed parameters.
    int ret_deflate_init = deflateInit2_(&strm_deflate, level, Z_DEFLATED, windowBits_deflate, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));
    if (ret_deflate_init == Z_OK) {
        // 4. Fuzz deflateSetDictionary
        // If deflateInit2_ was successful, attempt to set a dictionary.
        // Use the remaining fuzzer input as dictionary data.
        if (Size > current_offset) {
            uInt dict_len = (uInt)(Size - current_offset);
            // Limit dictionary size to prevent excessive memory allocation or long operations,
            // which could slow down fuzzing or lead to OOM errors.
            if (dict_len > 1024) { // Arbitrary limit (1KB) to keep fuzzing efficient
                dict_len = 1024;
            }
            // Call deflateSetDictionary with a portion of the fuzzer input.
            deflateSetDictionary(&strm_deflate, (const Bytef *)(Data + current_offset), dict_len);
        }
        // Clean up deflate stream resources by calling deflateEnd.
        deflateEnd(&strm_deflate);
    }

    // 3. Fuzz inflateReset2
    z_stream strm_inflate;
    // Initialize z_stream structure for inflate, similar to deflate.
    strm_inflate.zalloc = Z_NULL;
    strm_inflate.zfree = Z_NULL;
    strm_inflate.opaque = Z_NULL;
    strm_inflate.avail_in = 0;
    strm_inflate.next_in = Z_NULL;
    strm_inflate.avail_out = 0;
    strm_inflate.next_out = Z_NULL;

    // Consume a byte for inflate's windowBits, covering the same range as deflate.
    int windowBits_inflate = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 24) + 8; // 8 to 31

    // inflateReset2 requires an already initialized inflate stream.
    // First, initialize the stream using inflateInit2_.
    int ret_inflate_init = inflateInit2_(&strm_inflate, windowBits_inflate, ZLIB_VERSION, sizeof(z_stream));
    if (ret_inflate_init == Z_OK) {
        // If initialization is successful, call inflateReset2 to exercise its reset logic.
        inflateReset2(&strm_inflate, windowBits_inflate);
        // Clean up inflate stream resources by calling inflateEnd.
        inflateEnd(&strm_inflate);
    }

    // 5. Fuzz uncompress2
    // Check if there's enough data remaining in the fuzzer input to act as source for uncompress2.
    if (Size > current_offset) {
        const Bytef *source = Data + current_offset;
        uLongf sourceLen = (uLongf)(Size - current_offset);

        // Allocate a destination buffer for decompressed data.
        // A common heuristic is that decompressed data can be significantly larger than compressed data.
        // We use a factor of 10 plus a small overhead, but cap the total size to prevent excessive memory allocation.
        uLongf destLen = sourceLen * 10 + 100;
        if (destLen > 1024 * 1024) { // Cap destination buffer size to 1MB to avoid OOM
            destLen = 1024 * 1024;
        }
        Bytef *dest = (Bytef *)malloc(destLen);

        if (dest != NULL) {
            // Call uncompress2 to attempt decompression.
            uncompress2(dest, &destLen, source, &sourceLen);
            // Free the allocated destination buffer to prevent memory leaks.
            free(dest);
        }
    }

    // The fuzzer returns 0 to indicate successful execution of the fuzzed code.
    return 0;
}