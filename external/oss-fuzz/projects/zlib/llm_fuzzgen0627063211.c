// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h> // For INT_MAX

// Include necessary zlib headers with project-relative paths
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/deflate.h" // For deflate_state
#include "/src/zlib/crc32.h" // For z_word_t
#include "/src/zlib/gzguts.h" // For gzFile_s

// Define a dummy deflate_state structure for _tr_tally calls
// This is a simplified structure based on zlib's internal deflate_state
// It may need adjustments based on the actual definition in deflate.h
// To avoid depending on the full internal structure, we will only define
// the fields that _tr_tally is expected to access based on its likely logic
// (which involves accessing fields like strm, d_buf, l_buf, etc.).
// However, since _tr_tally is an internal function and its state
// is complex, directly calling it without a properly initialized
// deflate_state is difficult and likely to cause crashes.
// A more robust approach is to call the public API functions that
// internally call _tr_tally, such as deflate().
// Based on the coverage report, deflate() itself has low coverage (56.03% lines, 56.63% branches),
// and calling deflate() with varied inputs is the intended way to exercise
// the internal deflate logic, including _tr_tally.

// Similarly, byte_swap and crc_word_big are internal CRC32 helpers.
// The public API crc32_z (59.53% lines, 72.73% branches) is the correct
// entry point to exercise the CRC32 logic, which should internally
// call these helpers under specific conditions (e.g., endianness).

// zlibCompileFlags is a utility function that doesn't require complex state.
// gzvprintf is a gzip formatted print function, requiring a gzFile.
// deflate is the core compression function, requiring a z_stream.

// Let's focus on fuzzing the following public/semi-public APIs that
// have low coverage and are entry points to exercise the internal logic:
// 1. deflate (exercises _tr_tally and other deflate internals)
// 2. crc32_z (exercises byte_swap, crc_word_big, and other crc32 internals)
// 3. zlibCompileFlags (utility function)
// 4. gzvprintf (gzip formatted write)
// 5. inflateGetDictionary (inflate utility with low coverage)

// Helper function to create a temporary file for gz* functions
char* create_temp_file() {
    // Use a simple approach to create a unique temporary filename
    // In a real fuzzer, mkstemp or similar secure functions should be used.
    // For this example, we'll use a predictable name for simplicity.
    static int counter = 0;
    char* filename = (char*)malloc(20); // Sufficient space for "temp_file_XXXX.gz"
    if (!filename) return NULL;
    sprintf(filename, "temp_file_%d.gz", counter++);
    return filename;
}


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // zlib does not use FuzzedDataProvider in C fuzz targets.
    // We will use the raw Data and Size to drive the zlib APIs.

    // Ensure we have at least some data to work with
    if (Size < 1) {
        return 0;
    }

    // --- Fuzzing zlibCompileFlags ---
    // This function takes no arguments and returns a long.
    // It's safe to call directly.
    (void)zlibCompileFlags();

    // --- Fuzzing crc32_z ---
    // crc32_z(crc, buf, len)
    // crc: initial CRC value (can be 0L)
    // buf: input data buffer
    // len: length of the input data
    // We can use the input Data and Size directly.
    (void)crc32_z(0L, Data, Size);

    // --- Fuzzing deflate ---
    // deflate(strm, flush)
    // Requires an initialized z_stream.
    z_stream strm_deflate;
    strm_deflate.zalloc = Z_NULL;
    strm_deflate.zfree = Z_NULL;
    strm_deflate.opaque = Z_NULL;

    // Initialize the stream for compression
    // deflateInit2_(strm, level, method, windowBits, memLevel, strategy, version, stream_size)
    // Use Z_DEFAULT_COMPRESSION, Z_DEFLATED, default windowBits, memLevel, strategy.
    // windowBits can be negative for raw deflate. Let's try varying it.
    // memLevel can be 1-9. Let's try varying it.
    // strategy can be Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED. Let's try varying it.

    // Use a small portion of the input data to determine parameters
    int level = Z_DEFAULT_COMPRESSION;
    int windowBits = 15; // Default
    int memLevel = 8; // Default
    int strategy = Z_DEFAULT_STRATEGY;
    int method = Z_DEFLATED;

    if (Size > 0) {
        level = (Data[0] % (Z_BEST_COMPRESSION - Z_NO_COMPRESSION + 1)) + Z_NO_COMPRESSION;
    }
    if (Size > 1) {
        // Vary windowBits: 9 to 15 for zlib, -9 to -15 for raw, +16 for gzip
        windowBits = (Data[1] % 23) + (-15); // Range from -15 to 7. Need to adjust for valid zlib/gzip/raw values.
        // Let's simplify and choose from a set of valid values
        int valid_windowBits[] = {15, -15, 15 + 16, -15 - 16}; // zlib, raw, gzip, raw gzip
        windowBits = valid_windowBits[Data[1] % (sizeof(valid_windowBits) / sizeof(valid_windowBits[0]))];
    }
     if (Size > 2) {
        memLevel = (Data[2] % 9) + 1; // 1 to 9
    }
    if (Size > 3) {
        strategy = Data[3] % 5; // Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED
    }
     if (Size > 4) {
        method = Z_DEFLATED; // Currently only Z_DEFLATED is supported for deflateInit2_
    }


    int ret_init = deflateInit2_(&strm_deflate, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

    if (ret_init == Z_OK) {
        // Allocate output buffer
        size_t out_buffer_size = Size * 2 + 100; // A reasonable guess for output size
        Bytef* out_buffer = (Bytef*)malloc(out_buffer_size);
        if (out_buffer) {
            strm_deflate.avail_in = Size;
            strm_deflate.next_in = (Bytef*)Data;
            strm_deflate.avail_out = out_buffer_size;
            strm_deflate.next_out = out_buffer;

            // Perform deflation
            // Vary the flush parameter
            int flush = Z_NO_FLUSH;
            if (Size > 5) {
                 flush = Data[5] % 4; // Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH
                 // Z_FINISH should be the last flush
                 if (flush == Z_FINISH && Size > 6) {
                     // Only call Z_FINISH if there's no more input data
                     if (strm_deflate.avail_in > 0) flush = Z_NO_FLUSH;
                 } else if (flush == Z_FINISH && Size <= 6) {
                      flush = Z_NO_FLUSH; // Avoid Z_FINISH if not enough data to decide
                 }
            }


            // Call deflate in a loop until input is consumed or output is full
            do {
                 // Ensure avail_in and avail_out are set before each call
                 strm_deflate.avail_in = Size - (strm_deflate.next_in - (Bytef*)Data);
                 strm_deflate.avail_out = out_buffer_size - (strm_deflate.next_out - out_buffer);

                 // If avail_in is 0, we should use Z_FINISH to complete the stream
                 if (strm_deflate.avail_in == 0) flush = Z_FINISH;
                 // If avail_out is 0, we need to stop or resize the output buffer (not doing resize here)
                 if (strm_deflate.avail_out == 0) break;


                int ret_deflate = deflate(&strm_deflate, flush);

                if (ret_deflate != Z_OK && ret_deflate != Z_STREAM_END) {
                    // Handle potential errors during deflation
                    break;
                }
                // If Z_STREAM_END is reached, stop
                if (ret_deflate == Z_STREAM_END) break;

            } while (strm_deflate.avail_in > 0 || flush == Z_FINISH);


            // Clean up deflate stream
            deflateEnd(&strm_deflate);
            free(out_buffer);
        } else {
             // If malloc failed, clean up deflate stream
             deflateEnd(&strm_deflate);
        }
    }


    // --- Fuzzing gzvprintf ---
    // gzvprintf(file, format, va_list)
    // This requires a gzFile and a format string.
    // Creating a valid gzFile requires file system operations, which are generally
    // avoided in fuzzers for determinism and speed.
    // However, to exercise gzvprintf, we need a gzFile. We can create a temporary
    // file and open it with gzopen.

    char* temp_filename = create_temp_file();
    if (temp_filename) {
        gzFile gz_file = gzopen(temp_filename, "wb"); // Open for writing in binary mode
        if (gz_file) {
            // We need a format string and arguments for vprintf.
            // This is tricky with raw fuzzer input.
            // A simple approach is to use a fixed format string and
            // try to use parts of the input data as arguments.
            // This is not ideal for hitting diverse paths in gzvprintf's
            // parsing logic, but it allows calling the function.

            // Example format string: "%d %s %c"
            // We need to provide corresponding arguments.
            // This requires interpreting the fuzzer input as different types,
            // which is what FuzzedDataProvider excels at.
            // Since we are in C, we have to manually interpret the bytes.

            // Let's try a simpler approach: use a fixed format string
            // that takes a string argument, and pass a portion of the input data.
            const char* format = "Input data: %s\n";
            // Ensure the input data is null-terminated for %s
            char* input_string = NULL;
            if (Size > 0) {
                input_string = (char*)malloc(Size + 1);
                if (input_string) {
                    memcpy(input_string, Data, Size);
                    input_string[Size] = '\0'; // Null terminate
                }
            }

            if (input_string) {
                 // gzvprintf requires a va_list. We need to use vprintf's mechanism.
                 // This is complex to do directly with fuzzer input without FuzzedDataProvider.
                 // A common fuzzer pattern is to have a wrapper function that takes
                 // fuzzer data and constructs the va_list.
                 // For simplicity in this example, we will call gzprintf instead,
                 // which is a variadic function and easier to call with fuzzer data.
                 // gzprintf has 100% line coverage but 0% branch coverage in the report,
                 // which seems contradictory or indicates trivial branches.
                 // Let's call gzprintf as a proxy to exercise similar logic to gzvprintf.

                 // gzprintf(file, format, ...)
                 // Use a simple format string and pass the input data as a string.
                 // This might not hit all branches of gzprintf/gzvprintf, but it calls the function.
                 gzprintf(gz_file, "Data: %s\n", input_string);

                 free(input_string);
            } else {
                // If malloc failed or Size is 0, call with just the format string
                 gzprintf(gz_file, "No data\n");
            }


            // Close the gzFile
            gzclose(gz_file);
        }
        // Clean up the temporary file
        remove(temp_filename);
        free(temp_filename);
    }


    // --- Fuzzing inflateGetDictionary ---
    // inflateGetDictionary(strm, dictionary, dictLength)
    // Requires an initialized inflate z_stream.
    // We need to first inflate some data that potentially uses a dictionary.
    // This is complex as it requires a valid compressed stream with a dictionary.
    // A simpler approach for fuzzing inflateGetDictionary specifically is to
    // initialize an inflate stream and then call inflateGetDictionary,
    // even if no dictionary has been set or used yet. This will at least
    // exercise the function's initial state handling.

    z_stream strm_inflate;
    strm_inflate.zalloc = Z_NULL;
    strm_inflate.zfree = Z_NULL;
    strm_inflate.opaque = Z_NULL;

    // Initialize the stream for inflation
    // inflateInit2_(strm, windowBits, version, stream_size)
    // Use default windowBits (15), which handles zlib and gzip.
    // Use a small portion of the input data to vary windowBits for inflateInit2_
    int inflate_windowBits = 15;
    if (Size > 6) {
         // Vary windowBits: 8 to 15 for zlib, -8 to -15 for raw, +16 for gzip
         inflate_windowBits = (Data[6] % 16) + 8; // Range 8 to 23.
         // Adjust for raw and gzip
         if (Data[6] % 3 == 0) inflate_windowBits = -(inflate_windowBits); // Raw
         if (Data[6] % 3 == 1) inflate_windowBits = inflate_windowBits + 16; // Gzip
    }


    int ret_inflate_init = inflateInit2_(&strm_inflate, inflate_windowBits, ZLIB_VERSION, sizeof(z_stream));

    if (ret_inflate_init == Z_OK) {
        // Allocate a buffer for the dictionary
        size_t dict_buffer_size = 1024; // Arbitrary size
        Bytef* dict_buffer = (Bytef*)malloc(dict_buffer_size);
        unsigned int dict_length = 0;

        if (dict_buffer) {
            // Call inflateGetDictionary
            // Pass the allocated buffer and its size.
            // The function will fill the buffer with the dictionary if available
            // and update dict_length.
            int ret_get_dict = inflateGetDictionary(&strm_inflate, dict_buffer, &dict_length);

            // ret_get_dict can be Z_OK (dictionary returned), Z_DATA_ERROR (no dictionary expected),
            // Z_STREAM_ERROR (stream not initialized), Z_BUF_ERROR (buffer too small).
            // We expect Z_DATA_ERROR or Z_OK depending on whether a dictionary was used
            // in the (non-existent) inflation process before this call.
            // The fuzzer will explore these cases.

            free(dict_buffer);
        }

        // Clean up inflate stream
        inflateEnd(&strm_inflate);
    }


    // Note: Fuzzing internal functions like _tr_tally, byte_swap, crc_word_big
    // by calling them directly is highly discouraged and complex due to their
    // reliance on intricate internal state structures (like deflate_state).
    // The standard and safer approach is to fuzz the public API functions
    // (like deflate, crc32_z) that internally call these helpers.
    // By providing diverse inputs to the public APIs, we aim to trigger
    // the conditions under which these internal functions are called and
    // explore their code paths indirectly.

    return 0;
}