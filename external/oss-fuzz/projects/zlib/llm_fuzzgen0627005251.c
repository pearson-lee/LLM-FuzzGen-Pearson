// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
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
    // Increased modulo to 8 for the two new cases (deflate and gzflush)
    switch (api_selector % 8) {
        case 0: {
            // Fuzz crc32_combine_op(uLong crc1, uLong crc2, uLong op)
            // This function had 0.0% coverage initially.
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
            // This function had 91.09% region and 81.48% branch coverage.
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
            // This function had 68.00% region and 71.88% branch coverage.
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
            if (mode_data_len < remaining_size) { // Consume null terminator if present
                mode_consumed_len++;
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
        case 5: {
            // Fuzz uncompress2(Bytef *dest, uLongf *destLen, const Bytef *source, uLong *sourceLen)
            // This function had missed coverage (78.72% regions, 86.96% lines, 67.86% branches).
            // Adding a case to call it directly with fuzzer input.
            // Need at least space for sourceLen and some source data.
            if (remaining_size < sizeof(uLong) + 1) return 0;

            CONSUME_SAFE(uLong, sourceLen_val);
            const Bytef* source = current_data;
            size_t current_source_size = remaining_size;

            // Ensure sourceLen_val does not exceed available data
            uLong sourceLen = (uLong)current_source_size;
            if (sourceLen_val < sourceLen) {
                sourceLen = sourceLen_val;
            }

            // Allocate a destination buffer. A reasonable size based on sourceLen.
            // A common uncompression ratio is around 3-5x, but can be much larger.
            // Allocate a fixed size or a size based on sourceLen with a multiplier,
            // ensuring it's not excessively large to avoid OOM.
            // Let's use a simple multiplier for now, capped at a reasonable size.
            uLongf destLen = sourceLen * 4; // Assume 4x expansion, adjust as needed
            const uLongf MAX_DEST_LEN = 1024 * 1024; // Cap destination size at 1MB
            if (destLen > MAX_DEST_LEN || destLen < sourceLen + 1) { // Ensure minimum size and cap
                 destLen = sourceLen + 1 > MAX_DEST_LEN ? MAX_DEST_LEN : sourceLen + 1;
            }


            Bytef* dest = (Bytef*)malloc(destLen);
            if (dest == NULL) {
                return 0; // Allocation failed
            }

            // Call uncompress2
            uncompress2(dest, &destLen, source, &sourceLen);

            // Free the allocated destination buffer
            free(dest);

            // Consume the source data used by uncompress2
            // Note: sourceLen is updated by uncompress2 to the actual consumed size.
            current_data += sourceLen;
            remaining_size -= sourceLen;

            break;
        }
        case 6: {
            // Fuzz deflate()
            // Added based on coverage report showing low coverage in deflate.c,
            // including 0% coverage for _tr_tally which is called by deflate_slow/fast.
            // This case performs a full deflate operation.
            if (remaining_size < sizeof(uLong) + 1) return 0; // Need at least size for inputLen and 1 byte of data

            CONSUME_SAFE(uLong, inputLen_val);
            const Bytef* input_data = current_data;
            size_t current_input_size = remaining_size;

            // Ensure inputLen_val does not exceed available data
            uLong inputLen = (uLong)current_input_size;
            if (inputLen_val < inputLen) {
                inputLen = inputLen_val;
            }

            // Consume the input data
            current_data += inputLen;
            remaining_size -= inputLen;

            // Allocate output buffer. A reasonable size based on inputLen, capped.
            uLongf outputLen = inputLen * 2; // Assume 2x expansion in worst case (uncompressed)
            const uLongf MAX_OUTPUT_LEN = 1024 * 1024; // Cap output size at 1MB
            // Fix: Changed MAX_DEST_LEN to MAX_OUTPUT_LEN
            if (outputLen > MAX_OUTPUT_LEN || outputLen < inputLen + 1) { // Ensure minimum size and cap
                 outputLen = inputLen + 1 > MAX_OUTPUT_LEN ? MAX_OUTPUT_LEN : inputLen + 1;
            }

            Bytef* output_buffer = (Bytef*)malloc(outputLen);
            if (output_buffer == NULL) {
                return 0; // Allocation failed
            }

            z_stream strm;
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            int ret_init = deflateInit(&strm, Z_DEFAULT_COMPRESSION);

            if (ret_init == Z_OK) {
                strm.avail_in = inputLen;
                strm.next_in = (Bytef*)input_data;
                strm.avail_out = outputLen;
                strm.next_out = output_buffer;

                // Perform compression
                // Call deflate until input is consumed or an error occurs
                while (strm.avail_in > 0 && ret_init == Z_OK) {
                     ret_init = deflate(&strm, Z_NO_FLUSH); // Use Z_NO_FLUSH for intermediate calls
                }

                // Finish the compression
                if (ret_init == Z_OK) {
                    ret_init = deflate(&strm, Z_FINISH);
                }

                deflateEnd(&strm); // Clean up the initialized stream
            }

            // Free the allocated output buffer
            free(output_buffer);

            break;
        }
        case 7: {
            // Fuzz gzflush()
            // Added based on coverage report showing low branch coverage in gzflush.
            // This case opens a gzFile and calls gzflush with a fuzzed flush mode.

            // Determine the length of the path string in the input data.
            size_t path_data_len = 0;
            while (path_data_len < remaining_size && current_data[path_data_len] != '\0') {
                path_data_len++;
            }

            if (remaining_size <= path_data_len) return 0; // Need space for path string and at least 1 byte for mode

            const uint8_t* path_bytes = current_data;

            size_t path_consumed_len = path_data_len;
            if (path_data_len < remaining_size) { // Consume null terminator if present
                path_consumed_len++;
            }
            current_data += path_consumed_len;
            remaining_size -= path_consumed_len;

            // Determine the length of the mode string in the remaining data.
            size_t mode_data_len = 0;
            while (mode_data_len < remaining_size && current_data[mode_data_len] != '\0') {
                mode_data_len++;
            }

            if (remaining_size <= mode_data_len + sizeof(int)) return 0; // Need space for mode string, null terminator, and flush mode

            const uint8_t* mode_bytes = current_data;

            size_t mode_consumed_len = mode_data_len;
            if (mode_data_len < remaining_size) { // Consume null terminator if present
                mode_consumed_len++;
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

            memcpy(path_str, path_bytes, path_data_len);
            path_str[path_data_len] = '\0';

            memcpy(mode_str, mode_bytes, mode_data_len);
            mode_str[mode_data_len] = '\0';

            gzFile file = gzopen(path_str, mode_str);

            // Free the allocated strings immediately after use
            free(path_str);
            free(mode_str);

            if (file != Z_NULL) {
                // Consume flush mode
                CONSUME_SAFE(int, flush_mode);

                gzflush(file, flush_mode);

                gzclose(file); // Close the file to prevent memory leaks
            }

            break;
        }
    }

    return 0;
}