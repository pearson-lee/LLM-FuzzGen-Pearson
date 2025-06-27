#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy
#include <math.h>   // For fabs (though not strictly needed for the fix, good practice if used)
#include <float.h>  // For DBL_EPSILON (though not strictly needed for the fix, good practice if used)

// Include necessary zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For zlibCompileFlags

// Custom allocation/free functions for zlib to track memory usage (optional, but good practice for fuzzing)
// Note: Temporarily disabling custom allocators to debug SEGV during free.
// If the SEGV is resolved, the issue might be related to the custom allocators
// or their interaction with zlib's internal state management.
/*
voidpf custom_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque; // Unused parameter
    // Use calloc to zero-initialize allocated memory, which can help detect bugs
    // Check for potential overflow before allocation
    if (__builtin_mul_overflow(items, size, (size_t*)NULL)) {
        return Z_NULL; // Indicate allocation failure
    }
    return calloc(items, size);
}

void custom_free(voidpf opaque, voidpf address) {
    (void)opaque; // Unused parameter
    free(address);
}
*/

// Entry point for the fuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimum size to extract initial parameters for zlib functions
    size_t param_size = 6;
    if (Size < param_size) {
        // If input is too small for parameters, still call functions that don't
        // require significant input or can handle NULL/zero size gracefully
        crc32_z(0L, Z_NULL, 0);
        zlibCompileFlags();
        return 0;
    }

    // Use the first few bytes of the input to control fuzzer behavior and parameters
    int level = Data[0] % 10; // Compression level (0-9)
    // windowBits: Restricting to 8-15 for standard zlib format to potentially avoid issues
    int windowBits = 8 + (Data[1] % 8); // Generate values between 8 and 15

    int memLevel = 1 + (Data[2] % 9); // Memory level (1-9)
    int strategy = Data[3] % 5; // Compression strategy (Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED)
    // Data[4] and Data[5] will be used to vary flush modes within loops

    // Calculate the size of the data available for function inputs after parameters
    size_t data_offset = param_size;
    size_t data_len = Size - data_offset;

    // Distribute the remaining input data among different purposes:
    // deflate input, dictionary for deflate/inflate, and data for crc32_z
    size_t deflate_input_len = data_len / 3;
    size_t dict_len = (data_len - deflate_input_len) / 2;
    size_t crc_data_len = data_len - deflate_input_len - dict_len;

    // Pointers for allocated buffers
    uint8_t *deflate_input_buf = NULL;
    uint8_t *dict_buf = NULL;
    uint8_t *crc_data_buf = NULL;
    uint8_t *deflate_output_buf = NULL;
    uint8_t *inflate_output_buf = NULL;

    // Allocate buffer for deflate input data
    if (deflate_input_len > 0) {
        deflate_input_buf = (uint8_t *)malloc(deflate_input_len);
        if (!deflate_input_buf) goto cleanup; // Handle allocation failure
        // memcpy source is guaranteed to be within Data based on data_len calculation
        memcpy(deflate_input_buf, Data + data_offset, deflate_input_len);
    }

    // Allocate buffer for dictionary data
    if (dict_len > 0) {
        dict_buf = (uint8_t *)malloc(dict_len);
        if (!dict_buf) goto cleanup; // Handle allocation failure
        // memcpy source is guaranteed to be within Data based on data_len calculation
        memcpy(dict_buf, Data + data_offset + deflate_input_len, dict_len);
    }

    // Allocate buffer for crc32_z input data
    if (crc_data_len > 0) {
        crc_data_buf = (uint8_t *)malloc(crc_data_len);
        if (!crc_data_buf) goto cleanup; // Handle allocation failure
        // memcpy source is guaranteed to be within Data based on data_len calculation
        memcpy(crc_data_buf, Data + data_offset + deflate_input_len + dict_len, crc_data_len);
    }

    // Allocate output buffers with heuristic sizes.
    // Deflate output size is typically slightly larger than input for small inputs,
    // and can be smaller for compressible data.
    size_t deflate_output_len = deflate_input_len + deflate_input_len / 10 + 50; // Estimate
    if (deflate_output_len < 100) deflate_output_len = 100; // Ensure a minimum size
    if (deflate_output_len > 1024 * 1024) deflate_output_len = 1024 * 1024; // Cap size to prevent excessive memory usage

    if (deflate_output_len > 0) {
        deflate_output_buf = (uint8_t *)malloc(deflate_output_len);
        if (!deflate_output_buf) goto cleanup; // Handle allocation failure
    }

    // Inflate output size can be significantly larger than compressed input.
    // Estimate based on original input size.
    size_t inflate_output_len = deflate_input_len * 3 + 50; // Estimate for decompressed size
    if (inflate_output_len < 100) inflate_output_len = 100; // Ensure a minimum size
     if (inflate_output_len > 1024 * 1024 * 3) inflate_output_len = 1024 * 1024 * 3; // Cap size

    if (inflate_output_len > 0) {
        inflate_output_buf = (uint8_t *)malloc(inflate_output_len);
        if (!inflate_output_buf) goto cleanup; // Handle allocation failure
    }


    // --- Test deflate and deflateSetDictionary ---
    z_stream c_stream;
    // Use default allocators by setting zalloc and zfree to Z_NULL
    c_stream.zalloc = Z_NULL;
    c_stream.zfree = Z_NULL;
    c_stream.opaque = Z_NULL;

    int ret = Z_OK; // Initialize return code

    // Initialize the deflate stream
    // Use ZLIB_VERSION and sizeof(z_stream) for version checking
    ret = deflateInit2_(&c_stream, level, Z_DEFLATED, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));
    if (ret == Z_OK) {
        // Test deflateSetDictionary if dictionary data is available
        if (dict_buf && dict_len > 0) {
            deflateSetDictionary(&c_stream, dict_buf, dict_len);
        }

        // Set initial input and output buffers for deflate
        c_stream.next_in = deflate_input_buf;
        c_stream.avail_in = deflate_input_len;
        c_stream.next_out = deflate_output_buf;
        c_stream.avail_out = deflate_output_len;

        size_t deflate_call_count = 0;
        int flush = Z_NO_FLUSH;

        // Loop while there is input or the stream is not finished
        while (c_stream.avail_in > 0 || flush == Z_FINISH) {
             // Use Z_NO_FLUSH for most calls, Z_FINISH when input is exhausted
             flush = (c_stream.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;

             ret = deflate(&c_stream, flush);

             // Break loop on stream end or non-recoverable errors
             if (ret == Z_STREAM_END) break;
             if (ret != Z_OK && ret != Z_BUF_ERROR) {
                 // Handle potential errors like Z_STREAM_ERROR, Z_DATA_ERROR, etc.
                 break;
             }
             // If output buffer is full (ret == Z_BUF_ERROR), we cannot proceed without reallocating.
             // Break to prevent potential OOB writes.
             if (ret == Z_BUF_ERROR) {
                 break;
             }

             deflate_call_count++;
             // Add a safeguard to prevent excessive loops
             if (deflate_call_count > 100000) break;
        }
        // Clean up the deflate stream
        deflateEnd(&c_stream);
    }

    // --- Test inflate and inflateSyncPoint ---
    z_stream d_stream;
    // Use default allocators by setting zalloc and zfree to Z_NULL
    d_stream.zalloc = Z_NULL;
    d_stream.zfree = Z_NULL;
    d_stream.opaque = Z_NULL;

    // Determine the actual size of compressed data produced by deflate
    // This is the original output buffer size minus the remaining available space
    size_t compressed_len = deflate_output_len - c_stream.avail_out;

    // If there is compressed data and output buffer for inflate is available
    if (compressed_len > 0 && deflate_output_buf && inflate_output_buf && inflate_output_len > 0) {
         // Initialize the inflate stream
         // Use ZLIB_VERSION and sizeof(z_stream) for version checking
         ret = inflateInit2_(&d_stream, windowBits, ZLIB_VERSION, sizeof(z_stream));
         if (ret == Z_OK) {
             // Set initial input and output buffers for inflate
             d_stream.next_in = deflate_output_buf; // Use the output of deflate as input for inflate
             d_stream.avail_in = compressed_len;
             d_stream.next_out = inflate_output_buf;
             d_stream.avail_out = inflate_output_len;

             size_t inflate_call_count = 0;
             ret = Z_OK; // Initialize ret for the inflate loop

             // Loop while there is input or dictionary is needed
             while (d_stream.avail_in > 0 || ret == Z_NEED_DICT) {
                 // Use Z_NO_FLUSH for inflate calls
                 int current_flush = Z_NO_FLUSH;

                 ret = inflate(&d_stream, current_flush);

                 // Test inflateSyncPoint periodically or after inflate calls
                 inflateSyncPoint(&d_stream);

                 // Break loop on stream end or non-recoverable errors
                 if (ret == Z_STREAM_END) break;
                 if (ret != Z_OK && ret != Z_BUF_ERROR && ret != Z_NEED_DICT) {
                     // Handle potential errors like Z_STREAM_ERROR, Z_DATA_ERROR, etc.
                     break;
                 }
                 // If dictionary is needed, try setting the same dictionary used for deflate
                 if (ret == Z_NEED_DICT) {
                     // Note: This assumes the dictionary is still available and correct for inflate
                     if (dict_buf && dict_len > 0) {
                         inflateSetDictionary(&d_stream, dict_buf, dict_len);
                         // After setting dictionary, inflate should be called again with Z_NO_FLUSH
                         // to continue decompression. The loop will handle this as ret is now Z_OK or similar.
                     } else {
                         // Cannot proceed without dictionary, break
                         break;
                     }
                 }
                 // If output buffer is full (ret == Z_BUF_ERROR), we cannot proceed without reallocating.
                 // Break to prevent potential OOB writes.
                 if (ret == Z_BUF_ERROR) {
                     break;
                 }

                 inflate_call_count++;
                 // Add a safeguard to prevent excessive loops
                 if (inflate_call_count > 100000) break;
             }
             // Clean up the inflate stream
             inflateEnd(&d_stream);
         }
    }


    // --- Test crc32_z ---
    // Use the first byte of the data section for the initial CRC value
    // Ensure data_offset is within bounds before accessing Data
    uLong initial_crc = (data_len > 0 && data_offset < Size) ? (uLong)(Data[data_offset] << 24 | Data[data_offset] << 16 | Data[data_offset] << 8 | Data[data_offset]) : 0L;
    // Call crc32_z with the allocated crc_data_buf or NULL if not allocated
    if (crc_data_buf && crc_data_len > 0) {
         crc32_z(initial_crc, (const Bytef *)crc_data_buf, crc_data_len);
    } else {
         crc32_z(initial_crc, Z_NULL, 0); // Test with NULL buffer and initial crc
    }


    // --- Test zlibCompileFlags ---
    // This function doesn't take input, just call it to cover its code
    zlibCompileFlags();


cleanup:
    // Clean up all allocated memory to prevent leaks
    free(deflate_input_buf);
    free(dict_buf);
    free(crc_data_buf);
    free(deflate_output_buf);
    free(inflate_output_buf);

    return 0;
}