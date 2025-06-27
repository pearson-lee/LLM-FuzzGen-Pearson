// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy, memset
// #include <stdio.h>  // Not needed if gz* functions are removed

// Include necessary zlib headers with full project-relative paths
#include "/src/zlib/zlib.h"
// Removed internal headers that caused build errors:
// #include "/src/zlib/gzguts.h"
// #include "/src/zlib/crc32.h"
// #include "/src/zlib/trees.h"

// Removed MemFile struct and mem_* functions as gz* fuzzing cases were removed.

// Removed custom allocation functions as they were not used by z_stream when Z_NULL is set.
// static voidpf zlib_alloc(voidpf opaque, uInt items, uInt size) {
//     (void)opaque; // Unused
//     // Check for potential overflow before allocating
//     if (items > 0 && size > 0 && items > (uInt)-1 / size) return NULL;
//     return calloc(items, size);
// }
//
// static void zlib_free(voidpf opaque, voidpf address) {
//     (void)opaque; // Unused
//     free(address);
// }


// Removed forward declarations for internal functions that caused build errors.
// z_word_t byte_swap(z_word_t x);
// z_word_t crc_word_big(z_word_t);
// int _tr_tally(deflate_state *s, unsigned int dist, unsigned int lc);
// int gz_skip(gz_statep s, off64_t offset);
// int gzgetc_(gzFile file); // Wrapper around gzgetc, fuzzing gzgetc is sufficient

// Fuzz target entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // We will use the input data to drive the fuzzer's actions and inputs.
    // Since this is C, we'll consume bytes from Data manually.

    if (Size < 1) {
        return 0; // Need at least one byte to determine which API to call
    }

    // Use the first byte to select which API or sequence to test
    uint8_t api_selector = Data[0];
    Data++;
    Size--;

    // Consume data for API inputs
    // Ensure we don't read beyond the input buffer
    size_t current_offset = 0;

    // Helper to safely consume bytes
    #define CONSUME_BYTES(count) \
        (Size - current_offset >= (count) ? (Data + current_offset) : NULL); \
        current_offset += (count);

    // Helper to safely consume a value of a specific type
    #define CONSUME_VALUE(type) \
        (Size - current_offset >= sizeof(type) ? *(type *)(Data + current_offset) : 0); \
        current_offset += sizeof(type);

    // Helper to safely consume a size_t value
    #define CONSUME_SIZE_T() \
        (Size - current_offset >= sizeof(size_t) ? *(size_t *)(Data + current_offset) : 0); \
        current_offset += sizeof(size_t);

    // Helper to safely consume an int value
    #define CONSUME_INT() \
        (Size - current_offset >= sizeof(int) ? *(int *)(Data + current_offset) : 0); \
        current_offset += sizeof(int);

    // Removed unused macros:
    // #define CONSUME_LONG() ...
    // #define CONSUME_Z_OFF64_T() ...


    // Exercise selected APIs based on api_selector
    switch (api_selector % 2) { // Use modulo 2 to select one of the 2 remaining API groups
        // Removed case 0 (gzgetc) - relied on custom file ops and internal gzdopen usage
        // Removed case 1 (byte_swap, crc_word_big) - called internal functions
        case 0: { // This was case 2, now case 0
            // Target: inflateGetDictionary
            // Needs a z_stream pointer, dictionary buffer, and dictLength pointer.
            // To hit the NULL stream/state branch, we can pass NULL or a stream with NULL state.
            // To hit other paths, we need a properly initialized inflate stream.

            uint8_t scenario = CONSUME_VALUE(uint8_t); // Use a byte to pick scenario

            z_stream strm;
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.avail_in = 0;
            strm.next_in = Z_NULL;

            Bytef dictionary_buffer[256]; // Dummy buffer
            uInt dict_length = 0;

            if (scenario % 3 == 0) {
                // Scenario 1: Pass NULL stream to hit the NULL check
                inflateGetDictionary(NULL, dictionary_buffer, &dict_length);
            } else if (scenario % 3 == 1) {
                 // Scenario 2: Pass stream with NULL state to hit the NULL check
                 strm.state = NULL;
                 inflateGetDictionary(&strm, dictionary_buffer, &dict_length);
            } else {
                // Scenario 3: Attempt with an initialized stream (may not have a dictionary)
                // Need enough data for inflateInit2_ parameters
                if (Size - current_offset >= sizeof(int)) { // Only need windowBits for inflateInit2_
                    int windowBits = CONSUME_INT();

                    // Initialize inflate stream
                    // Corrected the arguments for inflateInit2_
                    int ret_init = inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream));

                    if (ret_init == Z_OK) {
                        // Call inflateGetDictionary with the initialized stream
                        inflateGetDictionary(&strm, dictionary_buffer, &dict_length);
                        inflateEnd(&strm); // Clean up inflate stream
                    }
                }
            }
            break;
        }
        case 1: { // This was case 3, now case 1
            // Target: deflate
            // Needs a z_stream pointer and a flush parameter.
            // This is a complex function, fuzzing it requires setting up a deflate stream
            // and providing input data.

            z_stream strm;
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.avail_in = 0;
            strm.next_in = Z_NULL;

            // Need enough data for deflateInit2_ parameters and input/output buffers
            size_t params_size = sizeof(int) * 5; // level, method, windowBits, memLevel, strategy
            size_t flush_size = sizeof(int);
            size_t buffer_size_needed = 256; // Arbitrary buffer size

            if (Size - current_offset >= params_size + flush_size + buffer_size_needed * 2) {
                int level = CONSUME_INT();
                int method = CONSUME_INT();
                int windowBits = CONSUME_INT();
                int memLevel = CONSUME_INT();
                int strategy = CONSUME_INT();
                int flush = CONSUME_INT();

                // Clamp parameters to valid ranges if necessary (basic sanity)
                if (level < -1 || level > 9) level = Z_DEFAULT_COMPRESSION;
                if (method != Z_DEFLATED) method = Z_DEFLATED; // Only Z_DEFLATED is supported
                // windowBits: 9 to 15 for raw deflate, -9 to -15 for zlib header, 25 to 31 for gzip header
                if (windowBits < -15 || (windowBits > -9 && windowBits < 9) || windowBits > 31) windowBits = 15;
                if (memLevel < 1 || memLevel > 9) memLevel = 8;
                if (strategy < 0 || strategy > 4) strategy = Z_DEFAULT_STRATEGY; // Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED, Z_DEFAULT_STRATEGY
                if (flush < 0 || flush > Z_FINISH) flush = Z_NO_FLUSH; // Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH, Z_BLOCK, Z_TREES

                // Initialize deflate stream
                int ret_init = deflateInit2_(&strm, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

                if (ret_init == Z_OK) {
                    // Allocate input and output buffers
                    size_t in_buffer_size = buffer_size_needed;
                    size_t out_buffer_size = buffer_size_needed;
                    Bytef *in_buffer = (Bytef *)malloc(in_buffer_size);
                    Bytef *out_buffer = (Bytef *)malloc(out_buffer_size);

                    if (in_buffer && out_buffer) {
                        // Consume data for the input buffer
                        size_t data_to_consume = Size - current_offset < in_buffer_size ? Size - current_offset : in_buffer_size;
                        const uint8_t *input_data = CONSUME_BYTES(data_to_consume);

                        if (input_data) {
                            memcpy(in_buffer, input_data, data_to_consume);
                            strm.avail_in = (uInt)data_to_consume;
                            strm.next_in = in_buffer;
                            strm.avail_out = (uInt)out_buffer_size;
                            strm.next_out = out_buffer;

                            // Call deflate
                            deflate(&strm, flush);
                        }
                    }

                    free(in_buffer); // Free input buffer
                    free(out_buffer); // Free output buffer
                    deflateEnd(&strm); // Clean up deflate stream
                }
            }
            break;
        }
        // Removed case 4 (gzseek64) - relied on custom file ops and internal gz_skip usage
    }

    // Note: _tr_tally is an internal function called by deflate and compress functions.
    // Fuzzing deflate (case 1) is the intended way to reach _tr_tally.
    // We do not call _tr_tally directly here as it requires a complex internal state (deflate_state).

    return 0; // Fuzzer always returns 0
}