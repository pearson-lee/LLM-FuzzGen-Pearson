// Comprehensive memory-safe fuzz target for zlib, targeting low-coverage APIs.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For close, unlink (on POSIX systems)

// Include zlib headers with project-relative paths
#include "/src/zlib/zlib.h"
// #include "/src/zlib/gzguts.h" // Not strictly needed for public API calls used here

// Define callback contexts for inflateBack
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} in_desc_t;

typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t offset;
} out_desc_t;

// Callback function for inflateBack input
// Reads data from the fuzzer's input buffer
unsigned int fuzzer_in_func(void *desc, unsigned char **buf) {
    in_desc_t *in = (in_desc_t *)desc;
    if (in->offset >= in->size) {
        *buf = NULL;
        return 0; // Indicate no more data
    }
    *buf = (unsigned char *)(in->data + in->offset);
    size_t available = in->size - in->offset;
    // Provide a chunk of data, or all remaining data
    size_t chunk_size = available; // Simple: provide all available
    in->offset += chunk_size;
    return chunk_size; // Return number of bytes provided
}

// Callback function for inflateBack output
// Writes decompressed data to an output buffer
int fuzzer_out_func(void *desc, unsigned char *buf, unsigned int len) {
    out_desc_t *out = (out_desc_t *)desc;
    if (out->offset + len > out->size) {
        // Not enough space in output buffer
        return -1; // Indicate error
    }
    memcpy(out->buffer + out->offset, buf, len);
    out->offset += len;
    return len; // Return number of bytes written
}


// Entry point for the fuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte to select the API group to test
    uint8_t api_selector = Data[0];
    const uint8_t *fuzz_data = Data + 1;
    size_t fuzz_size = Size - 1;

    // Ensure we have enough data for basic operations if needed
    if (fuzz_size < 4) { // Minimum size for some parameters
        return 0;
    }

    // Keep track of data consumed from fuzz_data
    size_t data_offset = 0;

    // Select one of the 5 API groups based on the first byte
    switch (api_selector % 5) {
        case 0: { // Test gzfwrite and gzclose
            // Need enough data for writing
            if (fuzz_size - data_offset < 10) return 0;

            // Create a temporary file
            char tmp_filename[] = "/tmp/fuzz_gzwrite_XXXXXX";
            int fd = mkstemp(tmp_filename);
            if (fd == -1) return 0;
            close(fd); // Close the descriptor, gzopen will open the file

            // Open the temporary file for writing
            gzFile file = gzopen(tmp_filename, "wb");
            if (file) {
                // Use part of fuzz_data for the write buffer
                size_t write_buffer_size = fuzz_size - data_offset;
                size_t size_param = (write_buffer_size / 2) + 1; // Vary size parameter
                size_t nitems_param = 1; // Simple case: 1 item of varying size

                if (write_buffer_size > 0 && size_param > 0) {
                     // Call gzfwrite
                     gzfwrite(fuzz_data + data_offset, size_param, nitems_param, file);
                }

                // Close the gzFile
                gzclose(file);
            }

            // Clean up the temporary file
            unlink(tmp_filename);
            break;
        }
        case 1: { // Test gzfread and gzclose
            // Need enough data for writing and reading
            if (fuzz_size - data_offset < 10) return 0;

            // Create a temporary file
            char tmp_filename[] = "/tmp/fuzz_gzread_XXXXXX";
            int fd = mkstemp(tmp_filename);
            if (fd == -1) return 0;
            close(fd); // Close the descriptor, gzopen will open the file

            // First, write some fuzzed data to the file using gzwrite
            gzFile write_file = gzopen(tmp_filename, "wb");
            if (write_file) {
                gzwrite(write_file, fuzz_data + data_offset, fuzz_size - data_offset);
                gzclose(write_file);
            } else {
                 // If writing failed, clean up and exit
                 unlink(tmp_filename);
                 return 0;
            }

            // Now, open the temporary file for reading
            gzFile read_file = gzopen(tmp_filename, "rb");
            if (read_file) {
                // Allocate a buffer for reading the decompressed data
                size_t read_buffer_size = 4096; // Example buffer size
                uint8_t *read_buffer = (uint8_t *)malloc(read_buffer_size);
                if (read_buffer) {
                    // Use fuzzed data to determine size and nitems for gzfread
                    size_t size_param = (fuzz_size - data_offset) % (read_buffer_size / 2) + 1; // Vary size
                    size_t nitems_param = (fuzz_size - data_offset) % 5 + 1; // Vary nitems

                    // Call gzfread
                    gzfread(read_buffer, size_param, nitems_param, read_file);

                    // Free the read buffer
                    free(read_buffer);
                }

                // Close the gzFile
                gzclose(read_file);
            }

            // Clean up the temporary file
            unlink(tmp_filename);
            break;
        }
        case 2: { // Test inflateBack and inflateBackEnd
            // Need enough data for potential input
            if (fuzz_size - data_offset < 10) return 0;

            z_stream strm;
            // Initialize z_stream struct (on stack, no malloc/free for the struct itself)
            strm.zalloc = Z_NULL; // Use default alloc/free
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = Z_NULL; // Will be managed by the input callback
            strm.avail_in = 0;

            // Allocate window buffer for inflateBack
            size_t window_size = 1 << 15; // Max window size (32768)
            uint8_t *window = (uint8_t *)malloc(window_size);
            if (!window) return 0; // Allocation failed

            // Initialize inflateBack stream
            // windowBits = 15 for max window size
            // FIX: Added missing 'window' argument
            int ret_init = inflateBackInit_(&strm, 15, window, ZLIB_VERSION, sizeof(z_stream));

            if (ret_init == Z_OK) {
                // Setup input and output descriptors for callbacks
                in_desc_t in = {fuzz_data + data_offset, fuzz_size - data_offset, 0};
                // Allocate output buffer (example size, can be larger than input)
                size_t out_buffer_size = window_size * 2;
                uint8_t *out_buffer = (uint8_t *)malloc(out_buffer_size);

                if (out_buffer) {
                    out_desc_t out = {out_buffer, out_buffer_size, 0};

                    // Call inflateBack
                    inflateBack(&strm, fuzzer_in_func, &in, fuzzer_out_func, &out);

                    // Free the output buffer
                    free(out_buffer);
                }

                // Clean up inflateBack stream
                inflateBackEnd(&strm);
            }

            // Free the window buffer
            free(window);
            break;
        }
        case 3: { // Test deflateCopy
            // Need enough data for deflateInit2_ parameters
            if (fuzz_size - data_offset < 4) return 0;

            z_stream source_strm;
            z_stream dest_strm;

            // Initialize source stream (on stack)
            source_strm.zalloc = Z_NULL; // Use default alloc/free
            source_strm.zfree = Z_NULL;
            source_strm.opaque = Z_NULL;
            source_strm.next_in = Z_NULL;
            source_strm.avail_in = 0;

            // Use fuzzed data for deflateInit2_ parameters
            int level = (fuzz_data[data_offset] % 10) -1; // Z_DEFAULT_COMPRESSION (-1) to 9
            int method = Z_DEFLATED; // Only Z_DEFLATED is supported
            int windowBits = (fuzz_data[data_offset+1] % 8) + 8; // 8 to 15
            int memLevel = (fuzz_data[data_offset+2] % 9) + 1; // 1 to 9
            int strategy = fuzz_data[data_offset+3] % 5; // Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED

            data_offset += 4;

            // Initialize the source deflate stream
            // FIX: Added missing 'version' and 'stream_size' arguments
            int ret_init = deflateInit2_(&source_strm, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

            if (ret_init == Z_OK) {
                // Initialize destination stream (on stack). Its state will be allocated by deflateCopy.
                dest_strm.zalloc = Z_NULL; // Use default alloc/free
                dest_strm.zfree = Z_NULL;
                dest_strm.opaque = Z_NULL;
                dest_strm.next_in = Z_NULL;
                dest_strm.avail_in = 0;
                dest_strm.state = Z_NULL; // Ensure state is NULL before copy

                // Call deflateCopy
                deflateCopy(&dest_strm, &source_strm);

                // Clean up both streams. deflateEnd frees the internal state.
                deflateEnd(&source_strm);
                // deflateCopy allocates state for dest_strm, so it also needs deflateEnd
                deflateEnd(&dest_strm);

            } else {
                 // If deflateInit2_ failed, ensure source stream state is freed if allocated
                 if (source_strm.state != Z_NULL) {
                     deflateEnd(&source_strm);
                 }
            }
            break;
        }
        case 4: { // Test crc32_combine_gen
            // Need enough data for z_off_t
            if (fuzz_size - data_offset < sizeof(z_off_t)) return 0;

            z_off_t len2;
            // Copy fuzzed data into len2
            memcpy(&len2, fuzz_data + data_offset, sizeof(z_off_t));
            data_offset += sizeof(z_off_t);

            // Limit len2 to prevent excessive computation in crc32_combine_gen
            // A mask of 0xFFFFF limits the value to less than 2^20
            len2 &= 0xFFFFF;

            // Call crc32_combine_gen
            crc32_combine_gen(len2);
            // This function does not allocate memory, so no cleanup is needed.
            break;
        }
    }

    return 0;
}