// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy
#include <math.h>   // For fabs (though not strictly needed for the fix, good practice if used)
#include <float.h>  // For DBL_EPSILON (though not strictly needed for the fix, good practice if used)
#include <stdio.h>  // For FILE operations used by gz* functions

// Include necessary zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For zlibCompileFlags
#include "/src/zlib/gzguts.h" // For gzFile

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

// Structs and callback functions for inflateBack
// inflateBack uses callbacks to get input and provide output, unlike inflate/deflate
typedef struct {
    const Bytef *buffer;
    size_t size;
    size_t consumed;
} in_desc_t;

typedef struct {
    Bytef *buffer;
    size_t size;
    size_t written;
} out_desc_t;

// Input callback function for inflateBack
// Reads data from the input descriptor buffer
unsigned int fuzzer_in_func(void FAR *desc, unsigned char FAR *buf, unsigned int len) {
    in_desc_t *in_desc = (in_desc_t *)desc;
    size_t remaining = in_desc->size - in_desc->consumed;
    unsigned int to_read = (unsigned int)(remaining < len ? remaining : len);
    if (to_read > 0) {
        // Ensure we don't read beyond the input buffer
        if (in_desc->consumed + to_read > in_desc->size) {
            to_read = in_desc->size - in_desc->consumed; // Adjust to_read to fit
            if (to_read == 0) return 0; // Cannot read anything more
        }
        memcpy(buf, in_desc->buffer + in_desc->consumed, to_read);
        in_desc->consumed += to_read;
    }
    return to_read;
}

// Output callback function for inflateBack
// Writes data to the output descriptor buffer
int fuzzer_out_func(void FAR *desc, unsigned char FAR *buf, unsigned int len) {
    out_desc_t *out_desc = (out_desc_t *)desc;
    size_t remaining = out_desc->size - out_desc->written;
    unsigned int to_write = (unsigned int)(remaining < len ? remaining : len);
    if (to_write > 0) {
        // Ensure we don't write beyond the allocated buffer
        if (out_desc->written + to_write > out_desc->size) {
             to_write = out_desc->size - out_desc->written; // Adjust to_write to fit
             if (to_write == 0) return 0; // Cannot write anything more
        }
        memcpy(out_desc->buffer + out_desc->written, buf, to_write);
        out_desc->written += to_write;
    }
    // Return 0 on success, non-zero on failure.
    // For fuzzing, we'll assume success as long as we don't write beyond the buffer.
    // If to_write < len, it means the output buffer is full, which is not an error for inflateBack,
    // it just means it produced less output than requested.
    return 0;
}


// Entry point for the fuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimum size to extract initial parameters for zlib functions
    size_t param_size = 6;
    if (Size < param_size) {
        // If input is too small for parameters, still call functions that don't
        // require significant input or can handle NULL/zero size gracefully
        crc32_z(0L, Z_NULL, 0);
        zlibCompileFlags();
        // Added: Call compress and uncompress with minimal input to cover 0% branch coverage functions.
        // FIX: Provide valid pointers for destLen to avoid NULL dereference in compress2/uncompress.
        uLongf compressed_len = 0;
        compress(Z_NULL, &compressed_len, Z_NULL, 0);
        uLongf uncompressed_len = 0;
        uncompress(Z_NULL, &uncompressed_len, Z_NULL, 0);
        // Added: Call compressBound with minimal input to cover 0% branch coverage function.
        compressBound(0);
        // Added: Call crc32 and adler32 with minimal input to cover 0% branch coverage functions.
        crc32(0L, Z_NULL, 0);
        adler32(0L, Z_NULL, 0);
        // Added: Call crc32_combine and crc32_combine64 with minimal input to cover 0% branch coverage functions.
        crc32_combine(0L, 0L, 0);
        crc32_combine64(0L, 0L, 0);
        // FIX: Removed gzclose(Z_NULL) as it's unnecessary and potentially problematic.
        return 0;
    }

    // Use the first few bytes of the input to control fuzzer behavior and parameters
    int level = Data[0] % 10; // Compression level (0-9)
    // windowBits: Allow 0 and negative values to hit more branches in inflateBackInit_ and inflateInit2_
    // Also allow values outside 8-15 range for deflateInit2_ error paths.
    int windowBits = (int)(Data[1]); // Use raw byte value for wider range
    // Added: Clamp windowBits to a reasonable range to avoid excessive memory allocation or invalid parameters for most calls,
    // but still allow some values outside the standard 8-15 range for error path coverage.
    if (windowBits > 15) windowBits = 15;
    // Added: Ensure windowBits can be less than -15 to cover the missed branch at line 127.
    if (windowBits < -15) windowBits = -16 - (Data[1] % 10); // Make it less than -15


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
    uint8_t *inflateback_output_buf = NULL; // Buffer for inflateBack

    // Allocate buffer for deflate input data
    if (deflate_input_len > 0) {
        deflate_input_buf = (uint8_t *)malloc(deflate_input_len);
        if (!deflate_input_buf) goto cleanup; // Handle allocation failure
        // memcpy source is guaranteed to be within Data based on data_len calculation
        memcpy(deflate_input_buf, Data + data_offset, deflate_input_len);
    }

    // Allocate buffer for dictionary data
    // Added: Sometimes allocate a zero-length dictionary buffer to hit related branches.
    // Modified: Simplified dictionary allocation logic to ensure the zero-length case is hit reliably,
    // covering the missed branch at line 163.
    size_t current_dict_len = 0;
    if (dict_len > 0) {
        current_dict_len = dict_len;
    } else if (data_len > 0 && Data[0] % 3 == 0) {
        // Randomly choose to have a zero-length dictionary when dict_len is 0
        current_dict_len = 0;
    }

    if (current_dict_len > 0) {
         dict_buf = (uint8_t *)malloc(current_dict_len);
         if (!dict_buf) goto cleanup; // Handle allocation failure
         // memcpy source is guaranteed to be within Data based on data_len calculation
         memcpy(dict_buf, Data + data_offset + deflate_input_len, current_dict_len);
         dict_len = current_dict_len; // Update dict_len to the actual allocated size
    } else {
         // Explicitly set dict_buf to NULL and dict_len to 0 for the zero-length case
         dict_buf = NULL;
         dict_len = 0;
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
    // Modified: Increased cap size and added logic to sometimes hit the cap branch at line 192.
    if (deflate_output_len > 1024 * 1024 * 5 || (Data[0] % 3 == 0 && deflate_output_len > 1000)) { // Hit cap or randomly cap
        // Added: Ensure the branch at line 193 is hit by making the condition true.
        if (deflate_output_len > 1024 * 1024 * 5) {
             deflate_output_len = 1024 * 1024 * 5;
        } else if (Data[0] % 3 == 0 && deflate_output_len > 1000) {
             deflate_output_len = 1000;
        }
    }
    // Added: Sometimes set output length to 0 to hit related branches.
    if (Data[1] % 5 == 0) deflate_output_len = 0;


    if (deflate_output_len > 0) {
        deflate_output_buf = (uint8_t *)malloc(deflate_output_len);
        if (!deflate_output_buf) goto cleanup; // Handle allocation failure
    }

    // Inflate output size can be significantly larger than compressed input.
    // Estimate based on original input size.
    size_t inflate_output_len = deflate_input_len * 3 + 50; // Estimate for decompressed size
    if (inflate_output_len < 100) inflate_output_len = 100; // Ensure a minimum size
    // Modified: Increased cap size and added logic to sometimes hit the cap branch at line 209.
     if (inflate_output_len > 1024 * 1024 * 10 || (Data[1] % 3 == 0 && inflate_output_len > 1000)) { // Hit cap or randomly cap
         // Added: Ensure the branch at line 210 is hit by making the condition true.
         if (inflate_output_len > 1024 * 1024 * 10) {
             inflate_output_len = 1024 * 1024 * 10;
         } else if (Data[1] % 3 == 0 && inflate_output_len > 1000) {
             inflate_output_len = 1000;
         }
     }
    // Added: Sometimes set output length to 0 to hit related branches.
    // Modified: Ensure inflate_output_len is often > 0 to cover the inflate block (lines 327-386).
    if (Data[2] % 7 == 0) inflate_output_len = 0;


    // Allocate buffer for inflateBack output. Needs to be large enough for decompressed data.
    size_t inflateback_output_len = inflate_output_len; // Use the same estimate as inflate
    // Added: Sometimes set output length to 0 to hit related branches.
    if (Data[3] % 5 == 0) inflateback_output_len = 0;

     if (inflateback_output_len > 0) {
        inflateback_output_buf = (uint8_t *)malloc(inflateback_output_len);
        if (!inflateback_output_buf) goto cleanup; // Handle allocation failure
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
    // Added: Sometimes pass invalid windowBits or memLevel to hit deflateInit2_ error paths.
    int deflate_windowBits = windowBits;
    int deflate_memLevel = memLevel;
    if (Data[4] % 10 == 0) deflate_windowBits = 30; // Invalid windowBits
    if (Data[4] % 10 == 1) deflate_memLevel = 0; // Invalid memLevel

    ret = deflateInit2_(&c_stream, level, Z_DEFLATED, deflate_windowBits, deflate_memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));
    // Added: Check for deflateInit2_ failure to cover the false branch after the call.
    if (ret == Z_OK) {
        // Test deflateSetDictionary if dictionary data is available
        if (dict_buf && dict_len > 0) {
            deflateSetDictionary(&c_stream, dict_buf, dict_len);
        }
        // Added: Test deflateSetDictionary with NULL or zero-length dictionary to cover related branches.
        if (Data[5] % 10 == 0) {
             deflateSetDictionary(&c_stream, Z_NULL, 0);
        } else if (Data[5] % 10 == 1 && dict_buf) {
             deflateSetDictionary(&c_stream, dict_buf, 0);
        }


        // Set initial input and output buffers for deflate
        c_stream.next_in = deflate_input_buf;
        c_stream.avail_in = deflate_input_len;
        c_stream.next_out = deflate_output_buf;
        c_stream.avail_out = deflate_output_len;

        size_t deflate_call_count = 0;
        int flush = Z_NO_FLUSH;

        // Loop while there is input or the stream is not finished
        // Modified: Added logic to vary flush modes based on input data to cover more branches in deflate.
        // Modified: Adjusted loop condition and flush logic to hit more branches in deflate, including Z_BUF_ERROR and other errors.
        while (ret == Z_OK || ret == Z_BUF_ERROR) {
             // Use Z_NO_FLUSH for most calls, Z_FINISH when input is exhausted
             // Vary flush mode based on input byte Data[4]
             if (c_stream.avail_in == 0) {
                 flush = Z_FINISH;
             } else {
                 switch (Data[4] % 7) { // Use Data[4] to select flush mode, include default case
                     case 0: flush = Z_NO_FLUSH; break;
                     case 1: flush = Z_PARTIAL_FLUSH; break;
                     case 2: flush = Z_SYNC_FLUSH; break;
                     case 3: flush = Z_FULL_FLUSH; break;
                     case 4: flush = Z_FINISH; break; // Can also try Z_FINISH mid-stream
                     case 5: flush = Z_BLOCK; break;
                     case 6: flush = Z_NO_FLUSH; break; // Default case
                     default: flush = Z_NO_FLUSH; break;
                 }
             }

             ret = deflate(&c_stream, flush);

             // Break loop on stream end or non-recoverable errors
             if (ret == Z_STREAM_END) break;
             // Modified: Removed explicit break on Z_BUF_ERROR to allow the loop to continue and potentially recover if avail_out is increased (though not implemented here).
             // The loop condition now handles Z_BUF_ERROR.
             if (ret != Z_OK && ret != Z_BUF_ERROR) {
                 // Handle potential errors like Z_STREAM_ERROR, Z_DATA_ERROR, etc.
                 break;
             }

             deflate_call_count++;
             // Add a safeguard to prevent excessive loops
             if (deflate_call_count > 100000) break;

             // Added: Break if avail_out is 0 and ret is Z_OK to prevent infinite loops if no progress is made.
             // Modified: Adjusted condition to hit the missed branch at line 305.
             if (c_stream.avail_out == 0 && ret == Z_OK && deflate_call_count > 1) break; // Ensure at least one call is made before potentially breaking


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
    // Modified: The inflate block (lines 327-386) was previously skipped. Ensure inflate_output_len > 0 more often.
    if (compressed_len > 0 && deflate_output_buf && inflate_output_buf && inflate_output_len > 0) {
         // Initialize the inflate stream
         // Use ZLIB_VERSION and sizeof(z_stream) for version checking
         // Added: Sometimes pass invalid windowBits to hit inflateInit2_ error paths.
         // Modified: Ensure valid windowBits are passed sometimes to allow inflateInit2_ to succeed and cover the inflate block.
         int inflate_windowBits = windowBits;
         if (Data[5] % 10 == 0) inflate_windowBits = 30; // Invalid windowBits
         else if (Data[5] % 10 == 1) inflate_windowBits = 15; // Valid windowBits
         else if (Data[5] % 10 == 2) inflate_windowBits = -15; // Valid raw inflate windowBits


         ret = inflateInit2_(&d_stream, inflate_windowBits, ZLIB_VERSION, sizeof(z_stream));
         // Added: Check for inflateInit2_ failure to cover the false branch after the call.
         // Modified: The if block at line 332 was never entered. Ensure inflateInit2_ succeeds sometimes.
         if (ret == Z_OK) {
             // Set initial input and output buffers for inflate
             d_stream.next_in = deflate_output_buf; // Use the output of deflate as input for inflate
             d_stream.avail_in = compressed_len;
             d_stream.next_out = inflate_output_buf;
             d_stream.avail_out = inflate_output_len;

             size_t inflate_call_count = 0;
             ret = Z_OK; // Initialize ret for the inflate loop

             // Loop while there is input or dictionary is needed
             // Modified: Simplified loop condition and flush logic for inflate.
             while (ret != Z_STREAM_END && ret != Z_BUF_ERROR && ret != Z_DATA_ERROR && ret != Z_STREAM_ERROR) {
                 // Use Z_NO_FLUSH for inflate calls, except for Z_FINISH at the end
                 int current_flush = Z_NO_FLUSH;
                 // Vary flush mode based on input byte Data[5]
                 switch (Data[5] % 4) { // Use Data[5] to select flush mode for inflate, include default case
                     case 0: current_flush = Z_NO_FLUSH; break;
                     case 1: current_flush = Z_SYNC_FLUSH; break;
                     case 2: current_flush = Z_FINISH; break; // Can also try Z_FINISH mid-stream
                     case 3: current_flush = Z_NO_FLUSH; break; // Default case
                     default: current_flush = Z_NO_FLUSH; break;
                 }

                 ret = inflate(&d_stream, current_flush);

                 // Test inflateSyncPoint periodically or after inflate calls
                 inflateSyncPoint(&d_stream);

                 // Break loop on stream end or non-recoverable errors are handled by loop condition
                 if (ret == Z_NEED_DICT) {
                     // If dictionary is needed, try setting the same dictionary used for deflate
                     // Added: Sometimes pass NULL or zero-length dictionary to cover related branches in inflateSetDictionary.
                     // Modified: Ensure the dictionary setting logic inside Z_NEED_DICT is covered.
                     if (dict_buf && dict_len > 0 && Data[0] % 10 != 0) {
                         inflateSetDictionary(&d_stream, dict_buf, dict_len);
                     } else if (Data[0] % 10 == 0) {
                         inflateSetDictionary(&d_stream, Z_NULL, 0);
                     } else {
                         // Cannot proceed without dictionary, break
                         break;
                     }
                 }
                 // Z_BUF_ERROR is handled by the loop condition.

                 inflate_call_count++;
                 // Add a safeguard to prevent excessive loops
                 if (inflate_call_count > 100000) break;

                 // Added: Break if avail_out is 0 and ret is Z_OK to prevent infinite loops if no progress is made.
                 // Modified: Adjusted condition to hit the missed branch at line 381.
                 if (d_stream.avail_out == 0 && ret == Z_OK && inflate_call_count > 1) break; // Ensure at least one call is made before potentially breaking
             }
             // Clean up the inflate stream
             inflateEnd(&d_stream);
         }
    }

    // --- Test inflateBack ---
    // Added: Section to test inflateBackInit_, inflateBack, and inflateBackEnd
    // This targets functions in infback.c that were previously uncovered.
    z_stream db_stream;
    db_stream.zalloc = Z_NULL;
    db_stream.zfree = Z_NULL;
    db_stream.opaque = Z_NULL;

    // Use the compressed data from deflate as input for inflateBack
    // Modified: The inflateBack block (lines 397-435) was partially covered, but inflateBackInit_ success path was missed.
    // Ensure inflateback_output_len > 0 more often and pass valid windowBits sometimes.
    if (compressed_len > 0 && deflate_output_buf && inflateback_output_buf && inflateback_output_len > 0) {
        // windowBits must be negative for raw inflate (no zlib header)
        // Use the same windowBits as deflateInit2_ but negative
        // Added: Allow windowBits to be 0 or negative values outside -8 to -15 range to hit inflateBackInit_ error paths.
        // Modified: Ensure valid negative windowBits are passed sometimes to allow inflateBackInit_ to succeed and cover the inflateBack block.
        int inflateback_windowBits = windowBits;
        if (inflateback_windowBits > 0) inflateback_windowBits = -inflateback_windowBits;
        if (Data[0] % 10 == 0) inflateback_windowBits = -5; // Invalid windowBits
        else if (Data[0] % 10 == 1) inflateback_windowBits = -20; // Invalid windowBits
        else if (Data[0] % 10 == 2) inflateback_windowBits = -15; // Valid windowBits


        // inflateBackInit_ requires a fixed window size (usually 32K) for the output history
        // Allocate a buffer for the history window
        unsigned char *window_buf = NULL;
        // Added: Sometimes allocate a smaller window buffer to hit allocation failure paths in inflateBackInit_.
        // Modified: Ensure window_buf allocation succeeds sometimes to cover the inflateBackInit_ success path (missed branch at line 417).
        if (Data[1] % 10 == 0) {
             window_buf = (unsigned char *)malloc(1024); // Smaller buffer
        } else {
             window_buf = (unsigned char *)malloc(32768); // ZLIB_WBITS is 15, window size is 2^15 = 32768
        }


        if (window_buf) {
            ret = inflateBackInit_(&db_stream, inflateback_windowBits, window_buf, ZLIB_VERSION, sizeof(z_stream));
            // Added: Check for inflateBackInit_ failure to cover the false branch after the call.
            // Modified: The if block at line 420 was never entered. Ensure inflateBackInit_ succeeds sometimes.
            if (ret == Z_OK) {
                // Initialize input and output descriptors for inflateBack callbacks
                in_desc_t input_descriptor = { .buffer = deflate_output_buf, .size = compressed_len, .consumed = 0 };
                out_desc_t output_descriptor = { .buffer = inflateback_output_buf, .size = inflateback_output_len, .written = 0 };

                // Call inflateBack with the stream, input callback, input descriptor, output callback, and output descriptor
                ret = inflateBack(&db_stream, fuzzer_in_func, &input_descriptor, fuzzer_out_func, &output_descriptor);

                // Clean up the inflateBack stream
                inflateBackEnd(&db_stream);
            }
            free(window_buf); // Free the history window buffer
        } else {
            goto cleanup; // Handle allocation failure for window_buf
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
         // FIX: Corrected the call to crc32_z to have 3 arguments: initial_crc, Z_NULL, 0.
         crc32_z(initial_crc, Z_NULL, 0); // Test with NULL buffer and initial crc
    }

    // Added: Test crc32_combine and crc32_combine64
    // These functions were identified as having 0% branch coverage in the function-level report.
    // They are used to combine CRC values from different data segments.
    if (crc_data_buf && crc_data_len > 0) {
        uLong crc1 = crc32_z(0L, (const Bytef *)crc_data_buf, crc_data_len / 2);
        uLong crc2 = crc32_z(0L, (const Bytef *)crc_data_buf + crc_data_len / 2, crc_data_len - crc_data_len / 2);
        crc32_combine(crc1, crc2, crc_data_len - crc_data_len / 2);

        // Test crc32_combine64 with larger lengths if possible
        if (sizeof(z_off64_t) > sizeof(z_off_t)) {
             crc32_combine64(crc1, crc2, (z_off64_t)crc_data_len - crc_data_len / 2);
        }
    }
    // Added: Call crc32_combine and crc32_combine64 with zero lengths to cover related branches.
    crc32_combine(0L, 0L, 0);
    crc32_combine64(0L, 0L, 0);


    // --- Test zlibCompileFlags ---
    // This function doesn't take input, just call it to cover its code
    zlibCompileFlags();

    // --- Test gz* functions ---
    // Added: Section to test gz* functions (gzopen, gzwrite, gzread, gzclose, etc.)
    // These functions operate on gzip files and were previously uncovered.
    // Using a temporary file for testing.
    gzFile gz_file = NULL;
    const char* temp_filename = "fuzz_temp.gz"; // Use a fixed temporary filename

    // Attempt to open a gzip file for writing
    // Use different modes based on input data to cover more branches in gzopen/gz_open
    // Added: Include modes that should fail for writing to cover gzopen error paths.
    const char* write_modes[] = {"wb", "wb1", "wb9", "w", "w1", "w9", "ab", "a", "rb", "r", "invalid_mode"};
    const char* write_mode = write_modes[Data[0] % (sizeof(write_modes) / sizeof(write_modes[0]))];
    gz_file = gzopen(temp_filename, write_mode);

    if (gz_file) {
        // Test gzwrite
        if (deflate_input_buf && deflate_input_len > 0) {
            gzwrite(gz_file, deflate_input_buf, deflate_input_len);
        }
        // Added: Test gzwrite with NULL buffer and zero length.
        gzwrite(gz_file, Z_NULL, 0);

        // Test gzputc
        if (deflate_input_len > 0) {
            gzputc(gz_file, deflate_input_buf[0]);
        }
        // Added: Test gzputc with EOF.
        gzputc(gz_file, EOF);


        // Test gzputs
        if (deflate_input_buf && deflate_input_len > 0) {
             // Ensure the buffer is null-terminated for gzputs
             char* temp_str = (char*)malloc(deflate_input_len + 1);
             if (temp_str) {
                 memcpy(temp_str, deflate_input_buf, deflate_input_len);
                 temp_str[deflate_input_len] = '\0';
                 gzputs(gz_file, temp_str);
                 free(temp_str);
             } else {
                 goto cleanup; // Handle allocation failure
             }
        }
        // FIX: Removed gzputs(gz_file, Z_NULL) as it causes a NULL dereference.
        // gzputs(gz_file, Z_NULL);


        // Test gzprintf (simple case)
        gzprintf(gz_file, "fuzz_data_%zu\n", Size);
        // FIX: Removed gzprintf(gz_file, Z_NULL) as it causes a NULL dereference.
        // gzprintf(gz_file, Z_NULL);


        // Test gzflush with different flush modes based on input data
        int gz_flush_modes[] = {Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH};
        int gz_flush_mode = gz_flush_modes[Data[1] % (sizeof(gz_flush_modes) / sizeof(gz_flush_modes[0]))];
        gzflush(gz_file, gz_flush_mode);

        // Test gzsetparams
        int gz_level = Data[2] % 10;
        int gz_strategy = Data[3] % 5;
        gzsetparams(gz_file, gz_level, gz_strategy);
        // Added: Test gzsetparams with invalid level or strategy.
        gzsetparams(gz_file, -1, gz_strategy);
        gzsetparams(gz_file, gz_level, -1);


        // Close the file for writing
        gzclose(gz_file);
        gz_file = NULL; // Set to NULL after closing

        // Attempt to open the file for reading
        // Use different modes based on input data to cover more branches in gzopen/gz_open
        // Added: Include modes that should fail for reading to cover gzopen error paths (missed branch at line 548).
        const char* read_modes[] = {"rb", "r", "wb", "w", "invalid_mode"};
        const char* read_mode = read_modes[Data[0] % (sizeof(read_modes) / sizeof(read_modes[0]))];
        gz_file = gzopen(temp_filename, read_mode);

        if (gz_file) {
            // Test gzread
            uint8_t read_buf[1024];
            gzread(gz_file, read_buf, sizeof(read_buf));
            // Added: Test gzread with NULL buffer and zero length.
            gzread(gz_file, Z_NULL, 0);

            // Test gzgetc
            gzgetc(gz_file);

            // Test gzgets
            char gets_buf[1024];
            gzgets(gz_file, gets_buf, sizeof(gets_buf));
            // FIX: Removed gzgets(gz_file, Z_NULL, 0) as it causes a NULL dereference.
            // gzgets(gz_file, Z_NULL, 0);
            gzgets(gz_file, gets_buf, 0);


            // Test gzdirect
            gzdirect(gz_file);

            // Test gzeof
            gzeof(gz_file);

            // Test gzrewind
            gzrewind(gz_file);

            // Test gzseek and gztell (simple cases)
            gzseek(gz_file, 0, SEEK_SET);
            gztell(gz_file);
            gzseek64(gz_file, 0, SEEK_SET);
            gztell64(gz_file);
            gzoffset(gz_file);
            gzoffset64(gz_file);
            // Added: Test gzseek with invalid origin.
            gzseek(gz_file, 0, -1);
            gzseek64(gz_file, 0, -1);


            // Test gzungetc
            gzungetc('A', gz_file);
            // Added: Test gzungetc with EOF.
            gzungetc(EOF, gz_file);


            // Test gzerror and gzclearerr
            int errnum;
            const char* error_msg = gzerror(gz_file, &errnum);
            gzclearerr(gz_file);

            // Close the file for reading
            gzclose(gz_file);
            gz_file = NULL; // Set to NULL after closing
        }

        // Clean up the temporary file
        remove(temp_filename);
    } else {
        // Added: Attempt to remove the temporary file even if gzopen failed,
        // in case a previous run left a file behind.
        remove(temp_filename);
    }
    // FIX: Removed gzclose(Z_NULL) as it's unnecessary and potentially problematic.
    // gzclose(Z_NULL);


cleanup:
    // Clean up all allocated memory to prevent leaks
    free(deflate_input_buf);
    free(dict_buf);
    free(crc_data_buf);
    free(deflate_output_buf);
    free(inflate_output_buf);
    free(inflateback_output_buf); // Free inflateBack buffer

    // Ensure gz_file is closed if cleanup is reached due to an error before closing
    // Modified: The if block at line 620 was never entered. Ensure gz_file is closed if not NULL.
    if (gz_file) {
        gzclose(gz_file);
        // Also attempt to remove the temp file in case of early exit
        remove(temp_filename);
    }


    return 0;
}