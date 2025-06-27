// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy
#include <math.h>   // For fabs, needed by crc32_combine_op which is called by crc32_combine

// Include necessary zlib headers with project-relative paths
// zlib.h includes zconf.h
#include "/src/zlib/zlib.h" // Includes zconf.h
#include "/src/zlib/zutil.h" // Contains utility functions and definitions
#include "/src/zlib/inftrees.h" // Defines 'code' and related structures
#include "/src/zlib/inffixed.h" // Contains fixed inflate tables and constants like ENOUGH
#include "/src/zlib/deflate.h"   // For deflateInit2, deflate, deflateEnd
#include "/src/zlib/inflate.h"   // For inflateInit2, inflate, inflateEnd
#include "/src/zlib/crc32.h"     // For crc32_combine

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Handle empty input to cover the false branch of Size > 0 checks.
    if (Size == 0) {
        return 0;
    }

    // --- Exercise deflate() ---
    z_stream strm_def;
    strm_def.zalloc = Z_NULL;
    strm_def.zfree = Z_NULL;
    strm_def.opaque = Z_NULL;
    strm_def.avail_in = Size;
    strm_def.next_in = (Bytef *)Data;

    // We need output buffers for compression
    size_t output_buffer_size = Size * 2 + 1024; // A common heuristic
    Bytef *output_buffer = (Bytef *)malloc(output_buffer_size);
    if (!output_buffer) {
        // Handle allocation failure
        return 0;
    }
    strm_def.avail_out = output_buffer_size;
    strm_def.next_out = output_buffer;

    // Fuzz level and strategy
    int level = (Data[0] % (Z_BEST_COMPRESSION + 1)); // 0-9
    int strategy = (Size > 1) ? (Data[1] % (Z_FIXED + 1)) : Z_DEFAULT_STRATEGY;

    if (deflateInit2(&strm_def, level, Z_DEFLATED, MAX_WBITS, DEF_MEM_LEVEL, strategy) == Z_OK) {
        // Perform a deflate operation
        strm_def.avail_in = Size;
        strm_def.next_in = (Bytef *)Data;
        strm_def.avail_out = output_buffer_size;
        strm_def.next_out = output_buffer;

        // Call deflate with Z_FINISH to ensure all input is processed and output is flushed
        deflate(&strm_def, Z_FINISH);
        // Get actual compressed size before ending the stream
        size_t compressed_size = strm_def.total_out;
        // Clean up deflate stream
        deflateEnd(&strm_def);

        // --- Exercise inflate() using the compressed data ---
        z_stream strm_inf;
        strm_inf.zalloc = Z_NULL;
        strm_inf.zfree = Z_NULL;
        strm_inf.opaque = Z_NULL;
        strm_inf.avail_in = compressed_size;
        strm_inf.next_in = output_buffer; // Input is the compressed data

        // Output buffer for inflation - size should be at least original Size
        // Allocating original Size is a reasonable heuristic for successful decompression
        Bytef *inflate_output_buffer = (Bytef *)malloc(Size);
        if (inflate_output_buffer) {
            strm_inf.avail_out = Size;
            strm_inf.next_out = inflate_output_buffer;

            // Initialize inflate stream
            if (inflateInit2(&strm_inf, MAX_WBITS) == Z_OK) {
                 // Perform inflate operation
                 inflate(&strm_inf, Z_FINISH);
                 // Clean up inflate stream
                 inflateEnd(&strm_inf);
            }
            // Clean up allocated inflate output buffer
            free(inflate_output_buffer);
        }
    }
    // Clean up allocated output buffer from deflate (or if deflateInit2 failed)
    free(output_buffer);


    // --- Exercise crc32_combine ---
    // This calls crc32_combine_op internally.
    if (Size >= 3 * sizeof(uLong)) { // Need 3 uLong inputs
        uLong crc1 = *(uLong*)(Data);
        uLong crc2 = *(uLong*)(Data + sizeof(uLong));
        uLong len2 = *(uLong*)(Data + 2 * sizeof(uLong));

        // Limit len2 to prevent excessive computation in crc32_combine
        // A large len2 can cause timeouts in x2nmodp.
        const uLong MAX_LEN2 = 4096;
        if (len2 > MAX_LEN2) {
            len2 %= (MAX_LEN2 + 1);
        }

        // Ensure len2 is non-zero to hit the loop in crc32_combine_gen
        // which calls crc32_combine_op.
        if (len2 == 0) {
            len2 = 1;
        }

        // Call the public API that uses crc32_combine_op
        crc32_combine(crc1, crc2, len2);
    }

    // --- Exercise compress2() ---
    // Added to cover the compress2 function.
    size_t compress2_output_buffer_size = Size * 2 + 1024;
    Bytef *compress2_output_buffer = (Bytef *)malloc(compress2_output_buffer_size);
    if (compress2_output_buffer) {
        uLongf destLen = compress2_output_buffer_size;
        // Use the fuzzed level and strategy for variety
        compress2(compress2_output_buffer, &destLen, Data, Size, level);
        free(compress2_output_buffer);
    }

    // --- Exercise uncompress2() ---
    // Added to cover the uncompress2 function.
    // Using original Data as input to exercise error paths in uncompress2
    // if Data is not valid compressed data.
    size_t uncompress2_output_buffer_size = Size * 4 + 1024; // Generous size
    Bytef *uncompress2_output_buffer = (Bytef *)malloc(uncompress2_output_buffer_size);
    if (uncompress2_output_buffer) {
        uLongf destLen = uncompress2_output_buffer_size;
        uLong sourceLen = Size;
        uncompress2(uncompress2_output_buffer, &destLen, Data, &sourceLen);
        free(uncompress2_output_buffer);
    }

    // --- Exercise deflateSetDictionary ---
    // Added to cover deflateSetDictionary.
    if (Size > 10) { // Need at least 10 bytes for a dictionary
        z_stream strm_dict_def;
        strm_dict_def.zalloc = Z_NULL;
        strm_dict_def.zfree = Z_NULL;
        strm_dict_def.opaque = Z_NULL;

        if (deflateInit2(&strm_dict_def, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY) == Z_OK) {
            // Use part of the input data as the dictionary
            const Bytef *dictionary = Data;
            uInt dict_size = Size / 2; // Use half the input size as dictionary size

            deflateSetDictionary(&strm_dict_def, dictionary, dict_size);

            // Clean up
            deflateEnd(&strm_dict_def);
        }
    }

    // --- Exercise inflateSetDictionary ---
    // Added to cover inflateSetDictionary.
    if (Size > 10) { // Need at least 10 bytes for a dictionary
        z_stream strm_dict_inf;
        strm_dict_inf.zalloc = Z_NULL;
        strm_dict_inf.zfree = Z_NULL;
        strm_dict_inf.opaque = Z_NULL;

        if (inflateInit2(&strm_dict_inf, MAX_WBITS) == Z_OK) {
            // Use part of the input data as the dictionary
            const Bytef *dictionary = Data;
            uInt dict_size = Size / 2; // Use half the input size as dictionary size

            inflateSetDictionary(&strm_dict_inf, dictionary, dict_size);

            // Clean up
            inflateEnd(&strm_dict_inf);
        }
    }

    return 0;
}