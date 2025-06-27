#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> // Required for fabs in crc32_combine_op case, although not directly called in the fuzzer code, it might be used internally by zlib functions called. Including defensively.

// Include zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/gzguts.h"

// The original code included definitions for zcalloc and zcfree.
// However, the build error indicated that these are already defined
// in the zlib library itself (libz.a(zutil.o)).
// When z_stream::zalloc and z_stream::zfree are set to Z_NULL,
// zlib uses its own default allocation functions.
// Therefore, the definitions in the fuzzer code are redundant and cause
// multiple definition errors during linking.
// We remove the definitions here to resolve the build error.
// The forward declarations are also not needed if the definitions are removed.

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Keep track of the current position and remaining size
    const uint8_t *current_data = Data;
    size_t remaining_size = Size;

    // Helper to consume bytes safely and update pointers/size
    // Copies bytes from the input buffer to a local variable to avoid unaligned access.
#define CONSUME_SAFE(type, var) \
    type var; \
    if (remaining_size < sizeof(type)) return 0; \
    memcpy(&var, current_data, sizeof(type)); \
    current_data += sizeof(type); \
    remaining_size -= sizeof(type);

    // Helper to consume a buffer and update pointers/size
    // Note: This macro just updates pointers and size, it does NOT copy data.
    // The caller must ensure the consumed data is valid for the duration it's used.
    // This macro is not used in the corrected code for case 4, but kept for other cases.
#define CONSUME_BUF(len, buf_ptr) \
    if (remaining_size < len) return 0; \
    buf_ptr = (const char*)current_data; \
    current_data += len; \
    remaining_size -= len;

    // Consume one byte to determine which API to call
    if (remaining_size == 0) {
        return 0;
    }
    CONSUME_SAFE(uint8_t, api_selector);

    // Use a switch statement to call different APIs based on the selector
    switch (api_selector % 5) { // Use modulo 5 for the 5 selected APIs
        case 0: {
            // Fuzz crc32_combine_op(uLong crc1, uLong crc2, uLong op)
            // This function had 0.0% coverage.
            // The timeout was observed in this case, likely due to large 'op' values
            // causing excessive computation in multmodp, or op being 0 leading to an infinite loop.
            // Constrain 'op' using a bitmask and check for zero to prevent timeouts.
            if (remaining_size < sizeof(uLong) * 3) return 0;
            CONSUME_SAFE(uLong, crc1);
            CONSUME_SAFE(uLong, crc2);
            CONSUME_SAFE(uLong, op);
            // Apply a bitmask to 'op' to keep it within a reasonable range for multmodp
            op &= 0xFFF; // Masking with 0xFFF (4095)
            // Check if op is zero, which causes an infinite loop in multmodp
            if (op == 0) return 0;
            crc32_combine_op(crc1, crc2, op);
            break;
        }
        case 1: {
            // Fuzz zlibCompileFlags()
            // This function had 50.00% branch coverage, but the missed branches
            // are based on compile-time sizeof checks, not fuzzer input.
            // Calling it exercises the available code paths.
            zlibCompileFlags();
            break;
        }
        case 2: {
            // Fuzz deflateInit2_(z_streamp strm, int level, int method, int windowBits, int memLevel, int strategy, const char *version, int stream_size)
            // This function had 90.41% line and 72.22% branch coverage.
            // Fuzzing parameters helps explore different initialization paths.
            if (remaining_size < sizeof(int) * 5) return 0; // Need space for 5 ints

            z_stream strm;
            strm.zalloc = Z_NULL; // Use default alloc/free provided by zlib
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            CONSUME_SAFE(int, level);
            CONSUME_SAFE(int, method);
            CONSUME_SAFE(int, windowBits);
            CONSUME_SAFE(int, memLevel);
            CONSUME_SAFE(int, strategy);

            // Use remaining data as version string (null-terminated)
            const char* version = (const char*)current_data;
            // Ensure null termination by temporarily modifying the buffer if needed
            char* version_copy = NULL;
            if (remaining_size > 0 && current_data[remaining_size - 1] != '\0') {
                version_copy = (char*)malloc(remaining_size + 1);
                if (version_copy == NULL) return 0; // Allocation failed
                memcpy(version_copy, current_data, remaining_size);
                version_copy[remaining_size] = '\0';
                version = version_copy;
            } else if (remaining_size == 0) {
                 version = ""; // Empty string if no data left
            }

            int ret = deflateInit2_(&strm, level, method, windowBits, memLevel, strategy, version, sizeof(z_stream));

            // Clean up version_copy if allocated
            if (version_copy != NULL) {
                free(version_copy);
            }

            // Clean up z_stream if initialization was successful
            // deflateEnd frees the internal state allocated by deflateInit2_
            if (ret == Z_OK) {
                deflateEnd(&strm);
            }
            break;
        }
        case 3: {
            // Fuzz deflateParams(z_streamp strm, int level, int strategy)
            // This function had 75.00% line and 62.50% branch coverage.
            // Fuzzing parameters after initialization helps explore state transitions.
            // Requires an initialized z_stream.
            if (remaining_size < sizeof(int) * 2) return 0; // Need space for 2 ints for deflateParams

            z_stream strm;
            strm.zalloc = Z_NULL; // Use default alloc/free
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Initialize with some default parameters first
            int init_ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);

            if (init_ret == Z_OK) {
                CONSUME_SAFE(int, level);
                CONSUME_SAFE(int, strategy);
                deflateParams(&strm, level, strategy);
                deflateEnd(&strm); // Clean up the initialized stream
            }
            break;
        }
        case 4: {
            // Fuzz gzopen(const char *path, const char *mode)
            // This function (and its internal implementation gz_open) had missed coverage.
            // Fuzzing path and mode strings explores file handling paths.
            // The previous version could cause heap-buffer-overflow if the input data
            // for path or mode was not null-terminated, leading gzopen to read out of bounds.
            // We fix this by copying the consumed data into explicitly null-terminated buffers.

            // Determine the length of the path string in the input data.
            // It's the number of bytes until the first null terminator or the end of the buffer.
            size_t path_data_len = 0;
            while (path_data_len < remaining_size && current_data[path_data_len] != '\0') {
                path_data_len++;
            }

            // If no data left after path (including potential null terminator), return.
            // Need at least 1 byte for mode (even an empty string with null terminator).
            if (remaining_size <= path_data_len) return 0;

            // The actual bytes for the path string are from current_data up to path_data_len.
            const uint8_t* path_bytes = current_data;

            // Move current_data past the path data and its null terminator (if found)
            size_t path_consumed_len = path_data_len;
            if (path_data_len < remaining_size) { // Found null terminator
                path_consumed_len++; // Consume the null terminator
            }
            current_data += path_consumed_len;
            remaining_size -= path_consumed_len;

            // Determine the length of the mode string in the remaining data.
            size_t mode_data_len = 0;
            while (mode_data_len < remaining_size && current_data[mode_data_len] != '\0') {
                mode_data_len++;
            }

            // The actual bytes for the mode string are from current_data up to mode_data_len.
            const uint8_t* mode_bytes = current_data;

            // Move current_data past the mode data and its null terminator (if found)
            size_t mode_consumed_len = mode_data_len;
            if (mode_data_len < remaining_size) { // Found null terminator
                mode_consumed_len++; // Consume the null terminator
            }
            current_data += mode_consumed_len;
            remaining_size -= mode_consumed_len;


            // Allocate buffers for null-terminated strings
            char* path_str = (char*)malloc(path_data_len + 1);
            char* mode_str = (char*)malloc(mode_data_len + 1);

            if (!path_str || !mode_str) {
                // Free allocated memory before returning
                free(path_str);
                free(mode_str);
                return 0; // Allocation failed
            }

            // Copy data and null-terminate
            memcpy(path_str, path_bytes, path_data_len);
            path_str[path_data_len] = '\0';

            memcpy(mode_str, mode_bytes, mode_data_len);
            mode_str[mode_data_len] = '\0';

            // Call gzopen with the null-terminated strings
            gzFile file = gzopen(path_str, mode_str);

            // Free the allocated strings
            free(path_str);
            free(mode_str);

            // If gzopen succeeds, it returns a non-NULL gzFile pointer.
            // We must close the file to prevent memory leaks.
            if (file != Z_NULL) {
                gzclose(file);
            }
            break;
        }
    }

    return 0;
}