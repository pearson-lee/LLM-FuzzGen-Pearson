// Comprehensive fuzz target for zlib, focusing on low-coverage APIs.
// Prioritizes memory safety and aims to maximize code coverage.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // For SIZE_MAX
#include <math.h>   // For fabs in compare_double (if needed, though not used in this fuzzer)
#include <float.h>  // For DBL_EPSILON (if needed)

// Include necessary zlib headers with project-relative paths.
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/crc32.h"

// Custom allocation functions to exercise zcalloc and zcfree.
// These functions wrap standard malloc and free, providing a way
// to hook into zlib's memory management.
voidpf custom_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque; // Unused
    // Prevent potential multiplication overflow before allocation.
    if (items > 0 && size > 0 && items > SIZE_MAX / size) return Z_NULL;
    size_t total_size = (size_t)items * size;
    return malloc(total_size);
}

void custom_free(voidpf opaque, voidpf address) {
    (void)opaque; // Unused
    free(address);
}

// Entry point for the fuzzer.
// Data: Pointer to the fuzzer-generated input data.
// Size: Size of the input data.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Need at least one byte to select the API.
    if (Size < 1) {
        return 0;
    }

    // Consume the first byte to select which API to test.
    size_t consumed_bytes = 0;
    uint8_t api_selector = Data[consumed_bytes++];

    // Remaining data is used as input for the selected API.
    const uint8_t *api_data = Data + consumed_bytes;
    size_t api_size = Size - consumed_bytes;

    // Track consumption within the API data.
    size_t current_api_data_offset = 0;

    // Helper macro to safely consume data for parameters.
    // Declares the variable 'var' of type 'type', reads data into it,
    // and returns 0 if not enough data is available.
    #define CONSUME_DATA_OR_RETURN(type, var) \
        type var; /* Declare the variable */ \
        if (current_api_data_offset + sizeof(type) > api_size) { \
            return 0; /* Not enough data for this API call */ \
        } \
        memcpy(&var, api_data + current_api_data_offset, sizeof(type)); \
        current_api_data_offset += sizeof(type);

    // Helper macro to consume the rest of the available data as a buffer.
    #define CONSUME_REMAINING_BUFFER(buffer_ptr, buffer_size_var) \
        buffer_size_var = api_size - current_api_data_offset; \
        buffer_ptr = (uint8_t *)(api_data + current_api_data_offset); \
        current_api_data_offset = api_size;

    // Select one of the target APIs based on the first byte of input.
    switch (api_selector % 5) {
        case 0: { // Test deflate (covers _tr_tally indirectly)
            // Ensure enough data for deflateInit2_ parameters.
            if (api_size - current_api_data_offset < sizeof(int) * 5) return 0;

            z_stream strm;
            // Set custom allocators to exercise zcalloc and zcfree.
            strm.zalloc = custom_alloc;
            strm.zfree = custom_free;
            strm.opaque = Z_NULL;

            // Consume parameters for deflateInit2_.
            CONSUME_DATA_OR_RETURN(int, level);
            CONSUME_DATA_OR_RETURN(int, method);
            CONSUME_DATA_OR_RETURN(int, windowBits);
            CONSUME_DATA_OR_RETURN(int, memLevel);
            CONSUME_DATA_OR_RETURN(int, strategy);

            // Sanitize parameters to be within valid ranges for zlib.
            level = (level % 10) - 1; // Z_DEFAULT_COMPRESSION (-1) to 9
            method = Z_DEFLATED; // Only Z_DEFLATED is supported for now
            windowBits = (windowBits % 15) + 1; // 1 to 15
            memLevel = (memLevel % 9) + 1; // 1 to 9
            strategy = strategy % (Z_FIXED + 1); // Z_FILTERED (0) to Z_FIXED (4)

            // Initialize the deflation stream.
            int ret = deflateInit2_(&strm, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

            if (ret == Z_OK) {
                // Consume the rest of the input data as the input buffer for deflate.
                uint8_t *in_buf = NULL;
                size_t in_len = 0;
                CONSUME_REMAINING_BUFFER(in_buf, in_len);

                // Allocate an output buffer. A simple heuristic is used for size estimation.
                size_t out_len = in_len + in_len / 10 + 128; // Estimate output size
                // Prevent potential overflow in out_len calculation
                if (out_len < in_len) out_len = SIZE_MAX; // Indicate potential overflow, maybe handle differently

                uint8_t *out_buf = NULL;
                if (out_len > 0 && out_len != SIZE_MAX) {
                    out_buf = (uint8_t *)malloc(out_len);
                }


                if (out_buf) {
                    strm.avail_in = in_len;
                    strm.next_in = in_buf;
                    strm.avail_out = out_len;
                    strm.next_out = out_buf;

                    // Perform deflation. Z_FINISH attempts to compress all input.
                    deflate(&strm, Z_FINISH);

                    // Free the allocated output buffer.
                    free(out_buf);
                }
                // Clean up the deflation stream. This also calls zfree for internal state.
                deflateEnd(&strm);
            }
            break;
        }
        case 1: { // Test inflate (covers inflateSyncPoint indirectly)
            // Ensure enough data for inflateInit2_ parameters.
            if (api_size - current_api_data_offset < sizeof(int)) return 0;

            z_stream strm;
            // Set custom allocators to exercise zcalloc and zcfree.
            strm.zalloc = custom_alloc;
            strm.zfree = custom_free;
            strm.opaque = Z_NULL;

            // Consume parameters for inflateInit2_.
            CONSUME_DATA_OR_RETURN(int, windowBits);
            windowBits = (windowBits % 15) + 1; // 1 to 15

            // Initialize the inflation stream.
            int ret = inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream));

            if (ret == Z_OK) {
                // Consume the rest of the input data as the input buffer for inflate.
                uint8_t *in_buf = NULL;
                size_t in_len = 0;
                CONSUME_REMAINING_BUFFER(in_buf, in_len);

                // Allocate an output buffer. A simple heuristic is used for size estimation.
                size_t out_len = in_len * 5; // Estimate output size (assuming expansion)
                 // Prevent potential overflow in out_len calculation
                if (in_len > 0 && out_len / in_len != 5) out_len = SIZE_MAX; // Indicate potential overflow

                uint8_t *out_buf = NULL;
                 if (out_len > 0 && out_len != SIZE_MAX) {
                    out_buf = (uint8_t *)malloc(out_len);
                }

                if (out_buf) {
                    strm.avail_in = in_len;
                    strm.next_in = in_buf;
                    strm.avail_out = out_len;
                    strm.next_out = out_buf;

                    // Perform inflation. Z_FINISH attempts to decompress all input.
                    inflate(&strm, Z_FINISH);

                    // Free the allocated output buffer.
                    free(out_buf);
                }
                // Clean up the inflation stream. This also calls zfree for internal state.
                inflateEnd(&strm);
            }
            break;
        }
        case 2: { // Test deflateBound
            // Ensure enough data for the valid stream flag and sourceLen.
            if (api_size - current_api_data_offset < sizeof(uint8_t) + sizeof(uLong)) return 0;

            z_stream strm;
            CONSUME_DATA_OR_RETURN(uint8_t, is_valid_stream);

            // Test deflateBound with both valid and invalid stream states.
            if (is_valid_stream % 2 == 0) {
                 // Initialize a valid stream to test paths that access strm->state.
                // Ensure enough data for deflateInit2_ parameters if initializing.
                if (api_size - current_api_data_offset < sizeof(int) * 5) return 0;
                strm.zalloc = Z_NULL; // Use default allocators for this test case
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;

                // Consume parameters for deflateInit2_.
                CONSUME_DATA_OR_RETURN(int, level);
                CONSUME_DATA_OR_RETURN(int, method);
                CONSUME_DATA_OR_RETURN(int, windowBits);
                CONSUME_DATA_OR_RETURN(int, memLevel);
                CONSUME_DATA_OR_RETURN(int, strategy);

                // Sanitize parameters.
                level = (level % 10) - 1;
                method = Z_DEFLATED;
                windowBits = (windowBits % 15) + 1;
                memLevel = (memLevel % 9) + 1;
                strategy = strategy % (Z_FIXED + 1);

                // Initialize the stream.
                int init_ret = deflateInit2_(&strm, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

                if (init_ret != Z_OK) {
                    // If initialization failed, treat as an invalid stream for deflateBound.
                    memset(&strm, 0, sizeof(strm));
                }
                // No need to consume wrap_param or set strm.state->wrap directly.
                // deflateBound uses the parameters set during deflateInit2_.

            } else {
                // Use an invalid stream state (zero-initialized).
                memset(&strm, 0, sizeof(strm));
            }

            // Consume the source length parameter.
            CONSUME_DATA_OR_RETURN(uLong, sourceLen);

            // Call deflateBound.
            deflateBound(&strm, sourceLen);

            // Clean up the stream if it was successfully initialized.
            // Check strm.state to see if it was initialized by deflateInit2_.
            if (is_valid_stream % 2 == 0 && strm.state != NULL) {
                 deflateEnd(&strm);
            }
            break;
        }
        case 3: { // Test crc32_z (covers byte_swap and crc_word_big conditionally)
            // Ensure enough data for the initial CRC value.
            if (api_size - current_api_data_offset < sizeof(uLong)) return 0;

            CONSUME_DATA_OR_RETURN(uLong, crc);

            // Consume the rest of the input data as the buffer for crc32_z.
            uint8_t *buf = NULL;
            size_t len = 0;
            CONSUME_REMAINING_BUFFER(buf, len);

            // Call crc32_z.
            crc32_z(crc, buf, len);
            break;
        }
        case 4: { // Test zcalloc/zcfree explicitly via inflateInit2_ with custom allocators
             // Ensure enough data for inflateInit2_ parameters.
             if (api_size - current_api_data_offset < sizeof(int)) return 0;

             z_stream strm;
            // Set custom allocators to exercise zcalloc and zcfree.
            strm.zalloc = custom_alloc;
            strm.zfree = custom_free;
            strm.opaque = Z_NULL;

            // Consume parameters for inflateInit2_.
            CONSUME_DATA_OR_RETURN(int, windowBits);
            windowBits = (windowBits % 15) + 1; // 1 to 15

            // Initialize the inflation stream. This should trigger zcalloc.
            int ret = inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream));

            if (ret == Z_OK) {
                // Clean up the stream. This should trigger zcfree for internal state.
                inflateEnd(&strm);
            }
            break;
        }
    }

    return 0;
}