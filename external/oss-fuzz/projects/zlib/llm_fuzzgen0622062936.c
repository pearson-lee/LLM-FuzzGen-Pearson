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
        // Added call to deflateReset to improve coverage of deflateReset.
        deflateReset(&strm_deflate);

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

        // Added call to deflateGetDictionary to improve coverage.
        // This call queries the dictionary size; a subsequent call with an allocated buffer would retrieve the dictionary.
        Bytef *get_dict_buf = NULL;
        uInt get_dict_len = 0;
        deflateGetDictionary(&strm_deflate, get_dict_buf, &get_dict_len);

        // Added calls to deflate() to improve coverage of the main compression logic.
        // This addresses low coverage in deflate.c, specifically the deflate() function.
        const Bytef *deflate_in_buf = (const Bytef *)(Data + current_offset);
        uInt deflate_in_len = (uInt)(Size - current_offset);
        // Removed cap on deflate_in_len to allow larger inputs and hit more branches (e.g., internal buffer handling).
        // The fuzzer will manage the actual input size.

        // Fuzz deflate_out_len to sometimes be very small to trigger Z_BUF_ERROR,
        // and sometimes large enough for normal operation.
        uLongf deflate_out_len = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 256) + 1; // 1 to 256 bytes (small)
        if (deflate_in_len > 0) { // Add heuristic size if there's input, allowing for larger outputs too.
            deflate_out_len += deflate_in_len * 2 + 100;
        }

        Bytef *deflate_out_buf = (Bytef *)malloc(deflate_out_len);

        if (deflate_out_buf != NULL) {
            strm_deflate.avail_in = deflate_in_len;
            strm_deflate.next_in = (Bytef *)deflate_in_buf;
            strm_deflate.avail_out = deflate_out_len;
            strm_deflate.next_out = deflate_out_buf;

            // Added call to deflateParams to improve coverage of deflateParams.
            int new_level = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 10) - 1;
            int new_strategy = GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 5;
            switch (new_strategy) {
                case 0: new_strategy = Z_DEFAULT_STRATEGY; break;
                case 1: new_strategy = Z_FILTERED; break;
                case 2: new_strategy = Z_HUFFMAN_ONLY; break;
                case 3: new_strategy = Z_RLE; break;
                case 4: new_strategy = Z_FIXED; break;
            }
            deflateParams(&strm_deflate, new_level, new_strategy);

            // Added call to deflatePrime to improve coverage of deflatePrime.
            int bits = GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 16; // 0-15 bits
            int value = GET_BYTE_OR_ZERO(Data, &current_offset, Size);
            deflatePrime(&strm_deflate, bits, value);

            // Call deflate in a loop until input is consumed or stream ends.
            int ret_deflate = Z_OK;
            while (strm_deflate.avail_in > 0 && ret_deflate == Z_OK) {
                ret_deflate = deflate(&strm_deflate, Z_NO_FLUSH);
            }
            // Call deflate with Z_FINISH to ensure all pending output is flushed.
            if (ret_deflate == Z_OK || ret_deflate == Z_BUF_ERROR) {
                deflate(&strm_deflate, Z_FINISH);
            }
            free(deflate_out_buf); // Free allocated output buffer to prevent memory leaks.
        }

        // Added call to deflateCopy to improve coverage of deflateCopy.
        // Ensures memory safety by initializing and properly ending the copied stream.
        z_stream strm_deflate_copy;
        strm_deflate_copy.zalloc = Z_NULL; // Initialize for safety
        strm_deflate_copy.zfree = Z_NULL;
        strm_deflate_copy.opaque = Z_NULL;
        int ret_deflate_copy = deflateCopy(&strm_deflate_copy, &strm_deflate);
        if (ret_deflate_copy == Z_OK) {
            deflateEnd(&strm_deflate_copy); // Clean up the copied stream to prevent memory leaks.
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

        // Added call to inflateReset to improve coverage of inflateReset.
        inflateReset(&strm_inflate);

        // Added call to inflateSetDictionary to improve coverage.
        if (Size > current_offset) {
            uInt inflate_dict_len = (uInt)(Size - current_offset);
            if (inflate_dict_len > 1024) {
                inflate_dict_len = 1024;
            }
            inflateSetDictionary(&strm_inflate, (const Bytef *)(Data + current_offset), inflate_dict_len);
        }

        // Added call to inflateGetDictionary to improve coverage.
        // This call queries the dictionary size; a subsequent call with an allocated buffer would retrieve the dictionary.
        Bytef *inflate_get_dict_buf = NULL;
        uInt inflate_get_dict_len = 0;
        inflateGetDictionary(&strm_inflate, inflate_get_dict_buf, &inflate_get_dict_len);

        // Added calls to inflate() to improve coverage of the main decompression logic.
        // This addresses low coverage in inflate.c, specifically the inflate() function.
        const Bytef *inflate_in_buf = (const Bytef *)(Data + current_offset);
        uInt inflate_in_len = (uInt)(Size - current_offset);
        // Removed cap on inflate_in_len to allow larger inputs and hit more branches.
        // The fuzzer will manage the actual input size.

        // Fuzz inflate_out_len to sometimes be very small to trigger Z_BUF_ERROR,
        // and sometimes large enough for normal operation.
        uLongf inflate_out_len = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 256) + 1; // 1 to 256 bytes (small)
        if (inflate_in_len > 0) { // Add heuristic size if there's input, allowing for larger outputs too.
            inflate_out_len += inflate_in_len * 10 + 100;
        }

        Bytef *inflate_out_buf = (Bytef *)malloc(inflate_out_len);

        if (inflate_out_buf != NULL) {
            strm_inflate.avail_in = inflate_in_len;
            strm_inflate.next_in = (Bytef *)inflate_in_buf;
            strm_inflate.avail_out = inflate_out_len;
            strm_inflate.next_out = inflate_out_buf;

            // Added call to inflatePrime to improve coverage of inflatePrime.
            int bits_inflate = GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 16; // 0-15 bits
            int value_inflate = GET_BYTE_OR_ZERO(Data, &current_offset, Size);
            inflatePrime(&strm_inflate, bits_inflate, value_inflate);

            // Call inflate in a loop until input is consumed or stream ends.
            int ret_inflate = Z_OK;
            while (strm_inflate.avail_in > 0 && ret_inflate == Z_OK) {
                ret_inflate = inflate(&strm_inflate, Z_NO_FLUSH);
            }
            // Call inflate with Z_FINISH to ensure all pending output is flushed.
            if (ret_inflate == Z_OK || ret_inflate == Z_BUF_ERROR) {
                inflate(&strm_inflate, Z_FINISH);
            }
            free(inflate_out_buf); // Free allocated output buffer to prevent memory leaks.
        }

        // Added call to inflateCopy to improve coverage of inflateCopy.
        // Ensures memory safety by initializing and properly ending the copied stream.
        z_stream strm_inflate_copy;
        strm_inflate_copy.zalloc = Z_NULL; // Initialize for safety
        strm_inflate_copy.zfree = Z_NULL;
        strm_inflate_copy.opaque = Z_NULL;
        int ret_inflate_copy = inflateCopy(&strm_inflate_copy, &strm_inflate);
        if (ret_inflate_copy == Z_OK) {
            inflateEnd(&strm_inflate_copy); // Clean up the copied stream to prevent memory leaks.
        }

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
        // We use a factor of 10 plus a small overhead.
        uLongf destLen = sourceLen * 10 + 100;
        // Removed cap on destLen to allow larger outputs and hit more branches (e.g., large allocation paths).
        // The fuzzer will manage the actual input size.
        Bytef *dest = (Bytef *)malloc(destLen);

        if (dest != NULL) {
            // Call uncompress2 to attempt decompression.
            uncompress2(dest, &destLen, source, &sourceLen);
            // Free the allocated destination buffer to prevent memory leaks.
            free(dest);
        }
    }

    // Added call to compress2() to improve coverage of the compress2 function.
    // This addresses low coverage in compress.c, specifically the compress2() function.
    if (Size > current_offset) {
        const Bytef *compress_in_buf = (const Bytef *)(Data + current_offset);
        uLongf compress_in_len = (uLongf)(Size - current_offset);
        // Removed cap on compress_in_len to allow larger inputs and hit more branches.
        // The fuzzer will manage the actual input size.

        uLongf compress_out_len = compressBound(compress_in_len); // Use compressBound for accurate sizing
        Bytef *compress_out_buf = (Bytef *)malloc(compress_out_len);

        if (compress_out_buf != NULL) {
            // Consume a byte for compress level.
            int compress_level = (GET_BYTE_OR_ZERO(Data, &current_offset, Size) % 10) - 1; // -1 to 9
            compress2(compress_out_buf, &compress_out_len, compress_in_buf, compress_in_len, compress_level);
            free(compress_out_buf); // Free allocated output buffer to prevent memory leaks.
        }
    }

    // Added call to compress() to improve coverage of the compress function.
    // This is a simpler compression API.
    if (Size > current_offset) {
        const Bytef *compress_simple_in_buf = (const Bytef *)(Data + current_offset);
        uLongf compress_simple_in_len = (uLongf)(Size - current_offset);
        uLongf compress_simple_out_len = compressBound(compress_simple_in_len); // Use compressBound for accurate sizing
        Bytef *compress_simple_out_buf = (Bytef *)malloc(compress_simple_out_len);

        if (compress_simple_out_buf != NULL) {
            compress(compress_simple_out_buf, &compress_simple_out_len, compress_simple_in_buf, compress_simple_in_len);
            free(compress_simple_out_buf); // Free allocated output buffer to prevent memory leaks.
        }
    }

    // Added call to uncompress() to improve coverage of the uncompress function.
    // This is a simpler decompression API.
    if (Size > current_offset) {
        const Bytef *uncompress_simple_in_buf = (const Bytef *)(Data + current_offset);
        uLongf uncompress_simple_in_len = (uLongf)(Size - current_offset);
        uLongf uncompress_simple_out_len = uncompress_simple_in_len * 10 + 100; // Heuristic for decompressed size
        Bytef *uncompress_simple_out_buf = (Bytef *)malloc(uncompress_simple_out_len);

        if (uncompress_simple_out_buf != NULL) {
            uncompress(uncompress_simple_out_buf, &uncompress_simple_out_len, uncompress_simple_in_buf, uncompress_simple_in_len);
            free(uncompress_simple_out_buf); // Free allocated output buffer to prevent memory leaks.
        }
    }

    // The fuzzer returns 0 to indicate successful execution of the fuzzed code.
    return 0;
}