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
    uint8_t *inflateback_output_buf = NULL; // Buffer for inflateBack

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
    // Modified: Increased cap size to potentially hit the cap branch in the fuzzer code.
    if (deflate_output_len > 1024 * 1024 * 5) deflate_output_len = 1024 * 1024 * 5; // Cap size to prevent excessive memory usage

    if (deflate_output_len > 0) {
        deflate_output_buf = (uint8_t *)malloc(deflate_output_len);
        if (!deflate_output_buf) goto cleanup; // Handle allocation failure
    }

    // Inflate output size can be significantly larger than compressed input.
    // Estimate based on original input size.
    size_t inflate_output_len = deflate_input_len * 3 + 50; // Estimate for decompressed size
    if (inflate_output_len < 100) inflate_output_len = 100; // Ensure a minimum size
    // Modified: Increased cap size to potentially hit the cap branch in the fuzzer code.
     if (inflate_output_len > 1024 * 1024 * 10) inflate_output_len = 1024 * 1024 * 10; // Cap size

    if (inflate_output_len > 0) {
        inflate_output_buf = (uint8_t *)malloc(inflate_output_len);
        if (!inflate_output_buf) goto cleanup; // Handle allocation failure
    }

    // Allocate buffer for inflateBack output. Needs to be large enough for decompressed data.
    size_t inflateback_output_len = inflate_output_len; // Use the same estimate as inflate
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
        // Modified: Added logic to vary flush modes based on input data to cover more branches in deflate.
        while (c_stream.avail_in > 0 || flush == Z_FINISH) {
             // Use Z_NO_FLUSH for most calls, Z_FINISH when input is exhausted
             // Vary flush mode based on input byte Data[4]
             if (c_stream.avail_in == 0) {
                 flush = Z_FINISH;
             } else {
                 switch (Data[4] % 6) { // Use Data[4] to select flush mode
                     case 0: flush = Z_NO_FLUSH; break;
                     case 1: flush = Z_PARTIAL_FLUSH; break;
                     case 2: flush = Z_SYNC_FLUSH; break;
                     case 3: flush = Z_FULL_FLUSH; break;
                     case 4: flush = Z_FINISH; break; // Can also try Z_FINISH mid-stream
                     case 5: flush = Z_BLOCK; break;
                     default: flush = Z_NO_FLUSH; break;
                 }
             }

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
             // Modified: Added logic to vary flush modes based on input data to cover more branches in inflate.
             while (d_stream.avail_in > 0 || ret == Z_NEED_DICT) {
                 // Use Z_NO_FLUSH for inflate calls, except for Z_FINISH at the end
                 int current_flush = Z_NO_FLUSH;
                 // Vary flush mode based on input byte Data[5]
                 if (d_stream.avail_in == 0 && ret != Z_NEED_DICT) {
                     current_flush = Z_FINISH;
                 } else {
                     switch (Data[5] % 3) { // Use Data[5] to select flush mode for inflate
                         case 0: current_flush = Z_NO_FLUSH; break;
                         case 1: current_flush = Z_SYNC_FLUSH; break;
                         case 2: current_flush = Z_FINISH; break; // Can also try Z_FINISH mid-stream
                         default: current_flush = Z_NO_FLUSH; break;
                     }
                 }


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

    // --- Test inflateBack ---
    // Added: Section to test inflateBackInit_, inflateBack, and inflateBackEnd
    // This targets functions in infback.c that were previously uncovered.
    z_stream db_stream;
    db_stream.zalloc = Z_NULL;
    db_stream.zfree = Z_NULL;
    db_stream.opaque = Z_NULL;

    // Use the compressed data from deflate as input for inflateBack
    if (compressed_len > 0 && deflate_output_buf && inflateback_output_buf && inflateback_output_len > 0) {
        // windowBits must be negative for raw inflate (no zlib header)
        // Use the same windowBits as deflateInit2_ but negative
        int inflateback_windowBits = (windowBits > 0) ? -windowBits : windowBits;
        if (inflateback_windowBits == 0) inflateback_windowBits = -15; // Ensure a non-zero negative value if windowBits was 0

        // inflateBackInit_ requires a fixed window size (usually 32K) for the output history
        // Allocate a buffer for the history window
        unsigned char *window_buf = (unsigned char *)malloc(32768); // ZLIB_WBITS is 15, window size is 2^15 = 32768
        if (window_buf) {
            ret = inflateBackInit_(&db_stream, inflateback_windowBits, window_buf, ZLIB_VERSION, sizeof(z_stream));
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
    const char* modes[] = {"wb", "wb1", "wb9", "w", "w1", "w9", "ab", "a"};
    const char* write_mode = modes[Data[0] % (sizeof(modes) / sizeof(modes[0]))];
    gz_file = gzopen(temp_filename, write_mode);

    if (gz_file) {
        // Test gzwrite
        if (deflate_input_buf && deflate_input_len > 0) {
            gzwrite(gz_file, deflate_input_buf, deflate_input_len);
        }

        // Test gzputc
        if (deflate_input_len > 0) {
            gzputc(gz_file, deflate_input_buf[0]);
        }

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

        // Test gzprintf (simple case)
        gzprintf(gz_file, "fuzz_data_%zu\n", Size);

        // Test gzflush with different flush modes based on input data
        int gz_flush_modes[] = {Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH};
        int gz_flush_mode = gz_flush_modes[Data[1] % (sizeof(gz_flush_modes) / sizeof(gz_flush_modes[0]))];
        gzflush(gz_file, gz_flush_mode);

        // Test gzsetparams
        int gz_level = Data[2] % 10;
        int gz_strategy = Data[3] % 5;
        gzsetparams(gz_file, gz_level, gz_strategy);

        // Close the file for writing
        gzclose(gz_file);
        gz_file = NULL; // Set to NULL after closing

        // Attempt to open the file for reading
        // Use different modes based on input data to cover more branches in gzopen/gz_open
        const char* read_modes[] = {"rb", "r"};
        const char* read_mode = read_modes[Data[0] % (sizeof(read_modes) / sizeof(read_modes[0]))];
        gz_file = gzopen(temp_filename, read_mode);

        if (gz_file) {
            // Test gzread
            uint8_t read_buf[1024];
            gzread(gz_file, read_buf, sizeof(read_buf));

            // Test gzgetc
            gzgetc(gz_file);

            // Test gzgets
            char gets_buf[1024];
            gzgets(gz_file, gets_buf, sizeof(gets_buf));

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

            // Test gzungetc
            gzungetc('A', gz_file);

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
    }


cleanup:
    // Clean up all allocated memory to prevent leaks
    free(deflate_input_buf);
    free(dict_buf);
    free(crc_data_buf);
    free(deflate_output_buf);
    free(inflate_output_buf);
    free(inflateback_output_buf); // Free inflateBack buffer

    // Ensure gz_file is closed if cleanup is reached due to an error before closing
    if (gz_file) {
        gzclose(gz_file);
        // Also attempt to remove the temp file in case of early exit
        remove(temp_filename);
    }


    return 0;
}