// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy
#include <math.h>   // For fabs, needed by crc32_combine_op which is called by crc32_combine
#include <stdio.h>  // For FILE operations for gz* functions

// Include necessary zlib headers with project-relative paths
// zlib.h includes zconf.h
#include "/src/zlib/zlib.h" // Includes zconf.h
#include "/src/zlib/zutil.h" // Contains utility functions and definitions
#include "/src/zlib/inftrees.h" // Defines 'code' and related structures
#include "/src/zlib/inffixed.h" // Contains fixed inflate tables and constants like ENOUGH
#include "/src/zlib/deflate.h"   // For deflateInit2, deflate, deflateEnd
#include "/src/zlib/inflate.h"   // For inflateInit2, inflate, inflateEnd
#include "/src/zlib/crc32.h"     // For crc32_combine
#include "/src/zlib/gzguts.h"    // For gzFile, internal structures
// Removed includes for gzread.h, gzwrite.h, gzlib.h as they caused build errors and
// the necessary public gz* functions are declared in zlib.h and gzguts.h.


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Handle empty input to cover the false branch of Size > 0 checks.
    if (Size == 0) {
        return 0;
    }

    // Use a small portion of the input for parameters to avoid large shifts/values
    // that might cause timeouts or excessive memory allocation attempts.
    size_t param_size = Size > 15 ? 15 : Size; // Increased param_size limit

    // Fuzz level, strategy, windowBits, and memLevel for deflateInit2
    int level = (param_size > 0) ? (Data[0] % (Z_BEST_COMPRESSION + 1)) : Z_DEFAULT_COMPRESSION; // 0-9
    int strategy = (param_size > 1) ? (Data[1] % (Z_FIXED + 1)) : Z_DEFAULT_STRATEGY;
    // Fuzz windowBits: 8-15 for deflate, -8 to -15 for raw, 25-31 for gzip
    // Add values outside the valid range to trigger error paths in deflateInit2
    int d_windowBits = (param_size > 2) ? (Data[2] % 40) - 20 : MAX_WBITS; // Range approx [-20, 19]
    // Ensure common valid ranges are hit
    if (param_size > 3 && Data[3] % 4 == 0) d_windowBits = 15; // Zlib
    if (param_size > 3 && Data[3] % 4 == 1) d_windowBits = -15; // Raw
    if (param_size > 3 && Data[3] % 4 == 2) d_windowBits = 31; // Gzip
    if (param_size > 3 && Data[3] % 4 == 3) d_windowBits = 12; // Common value

    // Fuzz memLevel: 1-9
    // Add values outside the valid range to trigger error paths
    int d_memLevel = (param_size > 4) ? (Data[4] % 15) : DEF_MEM_LEVEL; // Range approx [0, 14]
    if (d_memLevel == 0) d_memLevel = 1; // Ensure minimum is 1

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

    // Call deflateInit2 with fuzzed parameters to hit error branches
    // Added fuzzed windowBits and memLevel to trigger deflateInit2 failures.
    if (deflateInit2(&strm_def, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        // Perform a deflate operation
        strm_def.avail_in = Size;
        strm_def.next_in = (Bytef *)Data;
        strm_def.avail_out = output_buffer_size;
        strm_def.next_out = output_buffer;

        // Added calls with different flush modes to cover deflate internal logic (e.g., _tr_align, _tr_tally)
        // Need to manage input/output pointers and sizes for these calls.
        // A simpler approach for fuzzing is to call deflate multiple times with Z_NO_FLUSH
        // before the final Z_FINISH, or use separate streams as done below.

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

            // Fuzz windowBits for inflateInit2
            // Add values outside the valid range to trigger error paths in inflateInit2
            int i_windowBits = (param_size > 5) ? (Data[5] % 60) - 30 : MAX_WBITS; // Range approx [-30, 29]
            // Ensure common valid ranges are hit
            if (param_size > 6 && Data[6] % 4 == 0) i_windowBits = 15; // Zlib
            if (param_size > 6 && Data[6] % 4 == 1) i_windowBits = -15; // Raw
            if (param_size > 6 && Data[6] % 4 == 2) i_windowBits = 47; // Gzip/Zlib headers
            if (param_size > 6 && Data[6] % 4 == 3) i_windowBits = 12; // Common value

            // Initialize inflate stream with fuzzed windowBits to hit error branches
            // Added fuzzed windowBits to trigger inflateInit2 failures.
            if (inflateInit2(&strm_inf, i_windowBits) == Z_OK) {
                 // Perform inflate operation
                 inflate(&strm_inf, Z_FINISH);

                 // Exercise inflateSync - Added to cover inflateSync and syncsearch.
                 // Call inflateSync after some inflation has occurred.
                 inflateSync(&strm_inf);

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
    // This calls crc32_combine_op internally, but coverage reports suggest it's
    // conditional on build flags. Keeping the call but not expecting crc32_combine_op coverage.
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
    z_stream strm_dict_def;
    strm_dict_def.zalloc = Z_NULL;
    strm_dict_def.zfree = Z_NULL;
    strm_dict_def.opaque = Z_NULL;

    // Fuzz deflateInit2 parameters to hit error branches (based on coverage report)
    if (deflateInit2(&strm_dict_def, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        if (Size > 10) { // Need at least 10 bytes for a dictionary
            // Use part of the input data as the dictionary
            const Bytef *dictionary = Data;
            uInt dict_size = Size / 2; // Use half the input size as dictionary size

            deflateSetDictionary(&strm_dict_def, dictionary, dict_size);
        }
        // Clean up
        deflateEnd(&strm_dict_def);
    }


    // --- Exercise inflateSetDictionary ---
    // Added to cover inflateSetDictionary.
    z_stream strm_dict_inf;
    strm_dict_inf.zalloc = Z_NULL;
    strm_dict_inf.zfree = Z_NULL;
    strm_dict_inf.opaque = Z_NULL;

    // Fuzz inflateInit2 parameters to hit error branches (based on coverage report)
    int i_windowBits_set_dict = (param_size > 5) ? (Data[5] % 60) - 30 : MAX_WBITS;
    if (inflateInit2(&strm_dict_inf, i_windowBits_set_dict) == Z_OK) {
        if (Size > 10) { // Need at least 10 bytes for a dictionary
            // Use part of the input data as the dictionary
            const Bytef *dictionary = Data;
            uInt dict_size = Size / 2; // Use half the input size as dictionary size

            inflateSetDictionary(&strm_dict_inf, dictionary, dict_size);
        }
        // Clean up
        inflateEnd(&strm_dict_inf);
    }

    // --- Exercise gz* functions ---
    // Added to cover gz* API surface, including gzgetc_, gz_skip, gzrewind, gzseek, etc.
    if (Size > 0) {
        // Create a dummy file for gzopen/gzdopen
        FILE* dummy_file = fopen("fuzz_dummy_file.gz", "wb+");
        if (dummy_file) {
            // Exercise gzdopen
            gzFile gz_file = gzdopen(fileno(dummy_file), "wb");
            if (gz_file) {
                // Exercise gzwrite, gzputs, gzputc
                gzwrite(gz_file, Data, Size);

                // gzputs expects a null-terminated string. Create a temporary buffer.
                char* temp_string = (char*)malloc(Size + 1);
                if (temp_string) {
                    memcpy(temp_string, Data, Size);
                    temp_string[Size] = '\0'; // Null-terminate the string
                    gzputs(gz_file, temp_string);
                    free(temp_string); // Free the temporary buffer
                }

                if (Size > 0) gzputc(gz_file, Data[0]);

                // Exercise gzflush
                gzflush(gz_file, Z_FINISH);

                // Exercise gzsetparams
                gzsetparams(gz_file, level, strategy);

                // Exercise gzrewind and gzseek to trigger gz_skip
                gzrewind(gz_file);
                // Seek forward by a small amount to trigger gz_skip if possible
                if (Size > 1) gzseek(gz_file, Size / 2, SEEK_SET);

                // Added more gzseek calls with different modes/offsets to cover gz_skip branches (based on coverage report)
                if (Size > 14) {
                    long offset = (long)Data[14]; // Use a fuzzed offset
                    gzseek(gz_file, offset, SEEK_CUR);
                }
                gzseek(gz_file, 0, SEEK_END);


                // Exercise gzread, gzgets, gzgetc, gzungetc
                // Need to rewind or seek to the beginning to read
                gzrewind(gz_file);
                char read_buffer[1024];
                gzread(gz_file, read_buffer, sizeof(read_buffer));
                gzgets(gz_file, read_buffer, sizeof(read_buffer));
                gzgetc(gz_file);
                // Added loop to call gzgetc multiple times to cover gzgetc_ (based on coverage report)
                // Need to rewind again before reading character by character
                gzrewind(gz_file);
                while (gzgetc(gz_file) != EOF);

                // Need to rewind again before ungetc
                gzrewind(gz_file);
                if (Size > 0) gzungetc(Data[0], gz_file);

                // Exercise gzdirect, gzeof, gzerror, gzclearerr
                gzdirect(gz_file);
                gzeof(gz_file);
                int err;
                const char* err_str = gzerror(gz_file, &err);
                gzclearerr(gz_file);

                // Exercise gzbuffer
                gzbuffer(gz_file, 2048); // Set buffer size

                // Exercise gztell, gzoffset
                gztell(gz_file);
                gzoffset(gz_file);
                gztell64(gz_file); // Exercise 64-bit variants
                gzoffset64(gz_file);

                // Exercise gzclose_w (used by gzclose for write mode)
                gzclose(gz_file);
            }
            fclose(dummy_file);
            // Clean up the dummy file
            remove("fuzz_dummy_file.gz");
        }
    }

    // --- Exercise deflateParams ---
    // Added to cover deflateParams, which had low coverage.
    z_stream strm_params;
    strm_params.zalloc = Z_NULL;
    strm_params.zfree = Z_NULL;
    strm_params.opaque = Z_NULL;
    // Fuzz deflateInit2 parameters to hit error branches (based on coverage report)
    if (deflateInit2(&strm_params, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        // Fuzz new level and strategy for deflateParams
        int new_level = (param_size > 7) ? (Data[7] % (Z_BEST_COMPRESSION + 1)) : Z_DEFAULT_COMPRESSION;
        int new_strategy = (param_size > 8) ? (Data[8] % (Z_FIXED + 1)) : Z_DEFAULT_STRATEGY;
        deflateParams(&strm_params, new_level, new_strategy);
        deflateEnd(&strm_params);
    }

    // --- Exercise deflateTune ---
    // Added to cover deflateTune, which had low coverage.
    z_stream strm_tune;
    strm_tune.zalloc = Z_NULL;
    strm_tune.zfree = Z_NULL;
    strm_tune.opaque = Z_NULL;
    // Fuzz deflateInit2 parameters to hit error branches (based on coverage report)
    if (deflateInit2(&strm_tune, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        // Fuzz parameters for deflateTune
        int good_length = (param_size > 9) ? Data[9] : 0;
        int max_lazy = (param_size > 10) ? Data[10] : 0;
        int nice_length = (param_size > 11) ? Data[11] : 0;
        int max_chain = (param_size > 12) ? Data[12] : 0;
        deflateTune(&strm_tune, good_length, max_lazy, nice_length, max_chain);
        deflateEnd(&strm_tune);
    }

    // Added blocks to exercise deflate with different flush modes (Z_SYNC_FLUSH, Z_FULL_FLUSH)
    // to cover related internal functions like _tr_align and _tr_tally (based on coverage report).
    // Each block uses a separate stream for simplicity.

    // --- Exercise deflate with Z_SYNC_FLUSH ---
    z_stream strm_sync_flush;
    strm_sync_flush.zalloc = Z_NULL;
    strm_sync_flush.zfree = Z_NULL;
    strm_sync_flush.opaque = Z_NULL;
    // Fuzz deflateInit2 parameters
    if (deflateInit2(&strm_sync_flush, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        strm_sync_flush.avail_in = Size;
        strm_sync_flush.next_in = (Bytef *)Data;
        size_t sync_output_buffer_size = Size * 2 + 1024;
        Bytef *sync_output_buffer = (Bytef *)malloc(sync_output_buffer_size);
        if (sync_output_buffer) {
            strm_sync_flush.avail_out = sync_output_buffer_size;
            strm_sync_flush.next_out = sync_output_buffer;
            deflate(&strm_sync_flush, Z_SYNC_FLUSH); // Call with Z_SYNC_FLUSH
            deflateEnd(&strm_sync_flush);
            free(sync_output_buffer);
        } else {
             deflateEnd(&strm_sync_flush); // Clean up stream even if buffer allocation fails
        }
    }

    // --- Exercise deflate with Z_FULL_FLUSH ---
    z_stream strm_full_flush;
    strm_full_flush.zalloc = Z_NULL;
    strm_full_flush.zfree = Z_NULL;
    strm_full_flush.opaque = Z_NULL;
    // Fuzz deflateInit2 parameters
    if (deflateInit2(&strm_full_flush, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        strm_full_flush.avail_in = Size;
        strm_full_flush.next_in = (Bytef *)Data;
        size_t full_output_buffer_size = Size * 2 + 1024;
        Bytef *full_output_buffer = (Bytef *)malloc(full_output_buffer_size);
        if (full_output_buffer) {
            strm_full_flush.avail_out = full_output_buffer_size;
            strm_full_flush.next_out = full_output_buffer;
            deflate(&strm_full_flush, Z_FULL_FLUSH); // Call with Z_FULL_FLUSH
            deflateEnd(&strm_full_flush);
            free(full_output_buffer);
        } else {
            deflateEnd(&strm_full_flush); // Clean up stream even if buffer allocation fails
        }
    }


    // --- Exercise deflateCopy and inflateCopy ---
    // Added to cover deflateCopy and inflateCopy.
    z_stream strm_copy_def_orig;
    strm_copy_def_orig.zalloc = Z_NULL;
    strm_copy_def_orig.zfree = Z_NULL;
    strm_copy_def_orig.opaque = Z_NULL;

    // Added call to deflateCopy before initialization to cover failure paths (based on coverage report)
    z_stream strm_copy_def_uninit_copy;
    strm_copy_def_uninit_copy.zalloc = Z_NULL;
    strm_copy_def_uninit_copy.zfree = Z_NULL;
    strm_copy_def_uninit_copy.opaque = Z_NULL;
    // Call deflateCopy. Even if it fails, it might allocate state.
    deflateCopy(&strm_copy_def_uninit_copy, &strm_copy_def_orig);
    // Clean up the destination stream after the copy attempt.
    // deflateEnd should be called after deflateCopy, regardless of success/failure of deflateCopy itself,
    // as long as the destination stream structure was valid.
    deflateEnd(&strm_copy_def_uninit_copy);


    // Fuzz deflateInit2 parameters to hit error branches (based on coverage report)
    if (deflateInit2(&strm_copy_def_orig, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        z_stream strm_copy_def_copy;
        strm_copy_def_copy.zalloc = Z_NULL; // deflateCopy allocates state, but zalloc/zfree should be set
        strm_copy_def_copy.zfree = Z_NULL;
        strm_copy_def_copy.opaque = Z_NULL;
        // Call deflateCopy.
        if (deflateCopy(&strm_copy_def_copy, &strm_copy_def_orig) == Z_OK) {
             // Perform a small deflate operation on the copy
             strm_copy_def_copy.avail_in = Size > 10 ? 10 : Size;
             strm_copy_def_copy.next_in = (Bytef *)Data;
             Bytef copy_output[100];
             strm_copy_def_copy.avail_out = sizeof(copy_output);
             strm_copy_def_copy.next_out = copy_output;
             deflate(&strm_copy_def_copy, Z_NO_FLUSH);
             // Clean up the copy stream after successful copy and use.
             deflateEnd(&strm_copy_def_copy);
        } else {
            // If deflateCopy failed, the destination stream might still have allocated state.
            // Call deflateEnd to clean it up.
            deflateEnd(&strm_copy_def_copy);
        }
        // Clean up the original stream.
        deflateEnd(&strm_copy_def_orig);
    }

    z_stream strm_copy_inf_orig;
    strm_copy_inf_orig.zalloc = Z_NULL;
    strm_copy_inf_orig.zfree = Z_NULL;
    strm_copy_inf_orig.opaque = Z_NULL;

    // Added call to inflateCopy before initialization to cover failure paths (based on coverage report)
    z_stream strm_copy_inf_uninit_copy;
    strm_copy_inf_uninit_copy.zalloc = Z_NULL;
    strm_copy_inf_uninit_copy.zfree = Z_NULL;
    strm_copy_inf_uninit_copy.opaque = Z_NULL;
    // Call inflateCopy. Even if it fails, it might allocate state.
    inflateCopy(&strm_copy_inf_uninit_copy, &strm_copy_inf_orig);
    // Clean up the destination stream after the copy attempt.
    // inflateEnd should be called after inflateCopy, regardless of success/failure of inflateCopy itself.
    inflateEnd(&strm_copy_inf_uninit_copy);

    // Fuzz inflateInit2 parameters to hit error branches (based on coverage report)
    int i_windowBits = (param_size > 5) ? (Data[5] % 60) - 30 : MAX_WBITS;
    if (inflateInit2(&strm_copy_inf_orig, i_windowBits) == Z_OK) {
        z_stream strm_copy_inf_copy;
        strm_copy_inf_copy.zalloc = Z_NULL; // inflateCopy allocates state, but zalloc/zfree should be set
        strm_copy_inf_copy.zfree = Z_NULL;
        strm_copy_inf_copy.opaque = Z_NULL;
        // Call inflateCopy.
        if (inflateCopy(&strm_copy_inf_copy, &strm_copy_inf_orig) == Z_OK) {
            // No inflate operation needed on copy for coverage, just init/end
            // Clean up the copy stream after successful copy.
            inflateEnd(&strm_copy_inf_copy);
        } else {
            // If inflateCopy failed, the destination stream might still have allocated state.
            // Call inflateEnd to clean it up.
            inflateEnd(&strm_copy_inf_copy);
        }
        // Clean up the original stream.
        inflateEnd(&strm_copy_inf_orig);
    }

    // --- Exercise deflateGetDictionary and inflateGetDictionary ---
    // Added to cover deflateGetDictionary and inflateGetDictionary.
    z_stream strm_get_dict_def;
    strm_get_dict_def.zalloc = Z_NULL;
    strm_get_dict_def.zfree = Z_NULL;
    strm_get_dict_def.opaque = Z_NULL;
    // Fuzz deflateInit2 parameters to hit error branches (based on coverage report)
    if (deflateInit2(&strm_get_dict_def, level, Z_DEFLATED, d_windowBits, d_memLevel, strategy) == Z_OK) {
        if (Size > 10) {
            const Bytef *dictionary = Data;
            uInt dict_size = Size / 2;
            deflateSetDictionary(&strm_get_dict_def, dictionary, dict_size);
        }
        Bytef retrieved_dict[1024];
        uInt dict_len = 0;
        deflateGetDictionary(&strm_get_dict_def, retrieved_dict, &dict_len);
        deflateEnd(&strm_get_dict_def);
    }

    z_stream strm_get_dict_inf;
    strm_get_dict_inf.zalloc = Z_NULL;
    strm_get_dict_inf.zfree = Z_NULL;
    strm_get_dict_inf.opaque = Z_NULL;
    // Fuzz inflateInit2 parameters to hit error branches (based on coverage report)
    int i_windowBits_get_dict = (param_size > 5) ? (Data[5] % 60) - 30 : MAX_WBITS;
    if (inflateInit2(&strm_get_dict_inf, i_windowBits_get_dict) == Z_OK) {
         // Note: inflateGetDictionary typically works after inflateSetDictionary
         // or after processing a dictionary in the compressed stream.
         // Calling it here without a dictionary might hit different paths.
         Bytef retrieved_dict[1024];
         uInt dict_len = 0;
         inflateGetDictionary(&strm_get_dict_inf, retrieved_dict, &dict_len);
         inflateEnd(&strm_get_dict_inf);
    }


    // --- Exercise inflateGetHeader ---
    // Added to cover inflateGetHeader and the branches related to optional header fields (based on coverage report).
    // Craft a small input buffer that starts with a gzip header including FEXTRA, FNAME, FCOMMENT flags.
    z_stream strm_crafted_header;
    strm_crafted_header.zalloc = Z_NULL;
    strm_crafted_header.zfree = Z_NULL;
    strm_crafted_header.opaque = Z_NULL;

    // Crafted gzip header with FEXTRA, FNAME, FCOMMENT flags
    // 1f 8b 08 1c 00 00 00 00 00 03 (base header)
    // 04 00 (XLEN = 4) 01 02 03 04 (Extra data)
    // 'a' 00 (File name)
    // 'b' 00 (Comment)
    unsigned char crafted_header_bytes[] = {
        0x1f, 0x8b, 0x08, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x04, 0x00, 0x01, 0x02, 0x03, 0x04,
        'a', 0x00,
        'b', 0x00
    };
    size_t crafted_header_size = sizeof(crafted_header_bytes);

    // Create a combined buffer: crafted header + fuzzer input
    size_t combined_size = crafted_header_size + Size;
    Bytef *combined_input = (Bytef *)malloc(combined_size);
    if (combined_input) {
        memcpy(combined_input, crafted_header_bytes, crafted_header_size);
        memcpy(combined_input + crafted_header_size, Data, Size);

        // Fuzz inflateInit2 parameters to hit error branches (based on coverage report)
        int i_windowBits_header = (param_size > 5) ? (Data[5] % 60) - 30 : (MAX_WBITS | 32); // Use | 32 to enable gzip header processing
        if (inflateInit2(&strm_crafted_header, i_windowBits_header) == Z_OK) {
            strm_crafted_header.avail_in = combined_size;
            strm_crafted_header.next_in = combined_input;

            gz_header header;
            // Initialize header fields to Z_NULL to allow inflateGetHeader to allocate
            header.extra = Z_NULL;
            header.name = Z_NULL;
            header.comment = Z_NULL;
            header.hcrc = 0;
            header.os = 0;
            header.text = 0;
            header.time = 0;

            // Call inflateGetHeader *before* inflate to process the header
            inflateGetHeader(&strm_crafted_header, &header);

            // Need to free allocated memory if header fields were populated by inflateGetHeader
            if (header.extra != Z_NULL) free(header.extra);
            if (header.name != Z_NULL) free(header.name);
            if (header.comment != Z_NULL) free(header.comment);

            // Optionally, continue inflation with the rest of the data
            // inflate(&strm_crafted_header, Z_FINISH);

            inflateEnd(&strm_crafted_header);
        }
        free(combined_input); // Clean up the combined input buffer
    }


    // --- Exercise inflateUndermine and inflateValidate ---
    // Added to cover inflateUndermine and inflateValidate.
    z_stream strm_und_val;
    strm_und_val.zalloc = Z_NULL;
    strm_und_val.zfree = Z_NULL;
    strm_und_val.opaque = Z_NULL;
    // Fuzz inflateInit2 parameters to hit error branches (based on coverage report)
    int i_windowBits_und_val = (param_size > 5) ? (Data[5] % 60) - 30 : MAX_WBITS;
     if (inflateInit2(&strm_und_val, i_windowBits_und_val) == Z_OK) {
        inflateUndermine(&strm_und_val, (param_size > 13) ? Data[13] % 2 : 0); // Fuzz undermine parameter (0 or 1)
        inflateValidate(&strm_und_val, (param_size > 14) ? Data[14] % 2 : 0); // Fuzz validate parameter (0 or 1)
        inflateEnd(&strm_und_val);
     }

    // --- Exercise inflateMark and inflateCodesUsed ---
    // Added to cover inflateMark and inflateCodesUsed.
    z_stream strm_mark_codes;
    strm_mark_codes.zalloc = Z_NULL;
    strm_mark_codes.zfree = Z_NULL;
    strm_mark_codes.opaque = Z_NULL;
    // Fuzz inflateInit2 parameters to hit error branches (based on coverage report)
    int i_windowBits_mark_codes = (param_size > 5) ? (Data[5] % 60) - 30 : MAX_WBITS;
     if (inflateInit2(&strm_mark_codes, i_windowBits_mark_codes) == Z_OK) {
        long mark = inflateMark(&strm_mark_codes);
        int codes_used = inflateCodesUsed(&strm_mark_codes);
        inflateEnd(&strm_mark_codes);
     }

    // --- Exercise zlibCompileFlags ---
    // Added to cover zlibCompileFlags, which had low coverage.
    zlibCompileFlags();

    return 0;
}