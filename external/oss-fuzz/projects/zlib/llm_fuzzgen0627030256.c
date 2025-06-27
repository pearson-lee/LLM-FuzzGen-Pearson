// Comprehensive fuzz target for zlib, focusing on low-coverage functions.
// This fuzzer aims to increase coverage in _tr_tally, byte_swap,
// zlibCompileFlags, inflateSyncPoint, and gzfread by providing diverse inputs
// and exercising different API call sequences.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Include necessary zlib headers with project-relative paths
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For byte_swap and crc_word_big declarations (though we won't call them directly)
#include "/src/zlib/gzguts.h" // For gzFile definition and internal structures
#include "/src/zlib/deflate.h" // For Z_BLOCK definition

// Define a structure to hold fuzzer data and state
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzerData;

// Helper function to consume bytes from the fuzzer data
size_t ConsumeData(FuzzerData *fd, uint8_t *buffer, size_t num_bytes) {
    size_t bytes_to_consume = num_bytes;
    if (fd->offset + bytes_to_consume > fd->size) {
        bytes_to_consume = fd->size - fd->offset;
    }
    memcpy(buffer, fd->data + fd->offset, bytes_to_consume);
    fd->offset += bytes_to_consume;
    return bytes_to_consume;
}

// Helper function to consume a size_t from the fuzzer data
size_t ConsumeSizeT(FuzzerData *fd) {
    size_t value = 0;
    size_t bytes_consumed = ConsumeData(fd, (uint8_t *)&value, sizeof(size_t));
    // If not enough data for a full size_t, return a small value
    if (bytes_consumed < sizeof(size_t)) {
        // Use partial data if available, scaled down
        size_t partial_value = 0;
        memcpy(&partial_value, &value, bytes_consumed);
        return partial_value % 256;
    }
    return value;
}

// Helper function to consume an int from the fuzzer data
int ConsumeInt(FuzzerData *fd) {
    int value = 0;
    size_t bytes_consumed = ConsumeData(fd, (uint8_t *)&value, sizeof(int));
    // If not enough data for a full int, return a small value
    if (bytes_consumed < sizeof(int)) {
        // Use partial data if available, scaled down
        int partial_value = 0;
        memcpy(&partial_value, &value, bytes_consumed);
        return partial_value % 256;
    }
    return value;
}

// Helper function to consume a uint32_t from the fuzzer data
uint32_t ConsumeUint32(FuzzerData *fd) {
    uint32_t value = 0;
    size_t bytes_consumed = ConsumeData(fd, (uint8_t *)&value, sizeof(uint32_t));
    // If not enough data for a full uint32_t, return a small value
    if (bytes_consumed < sizeof(uint32_t)) {
        // Use partial data if available, scaled down
        uint32_t partial_value = 0;
        memcpy(&partial_value, &value, bytes_consumed);
        return partial_value % 256;
    }
    return value;
}

// Helper function to consume a uint8_t from the fuzzer data
uint8_t ConsumeUint8(FuzzerData *fd) {
    uint8_t value = 0;
    if (fd->offset < fd->size) {
        value = fd->data[fd->offset];
        fd->offset++;
    }
    return value;
}


// Fuzz target entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzerData fd = {Data, Size, 0};

    // To reach _tr_tally, we need to exercise the deflate compression path.
    // This requires initializing a deflate stream and providing input data.
    z_stream strm_deflate;
    strm_deflate.zalloc = Z_NULL;
    strm_deflate.zfree = Z_NULL;
    strm_deflate.opaque = Z_NULL;

    // Use fuzzer data for compression level and strategy
    int level = ConsumeInt(&fd) % 12; // Z_NO_COMPRESSION..Z_BEST_COMPRESSION (0-9), or default (-1). Mod 12 covers -1 to 10, plus some overlap.
    if (level > 9) level = Z_DEFAULT_COMPRESSION; // Map values > 9 to default
    if (level < -1) level = Z_DEFAULT_COMPRESSION; // Map values < -1 to default

    // Map fuzzed value (0-5) to valid strategies (0-4)
    int strategy_fuzzed = ConsumeInt(&fd) % 6;
    int strategy;
    if (strategy_fuzzed >= 0 && strategy_fuzzed <= 4) {
        strategy = strategy_fuzzed; // Map 0-4 to the standard strategies
    } else {
        strategy = Z_DEFAULT_STRATEGY; // Map 5 to default
    }


    // Initialize the deflate stream
    if (deflateInit2(&strm_deflate, level, Z_DEFLATED, 15, 8, strategy) == Z_OK) {
        // Provide input data to the deflate stream
        strm_deflate.avail_in = fd.size - fd.offset;
        strm_deflate.next_in = (Bytef *)(fd.data + fd.offset);

        // Allocate output buffer (size can be fuzzed or fixed reasonably)
        // A common heuristic is input size * 2 + 100, but limit it.
        size_t out_buffer_size = (fd.size - fd.offset) * 2 + 100;
        if (out_buffer_size > 1024 * 1024) out_buffer_size = 1024 * 1024; // Limit output buffer size
        if (out_buffer_size < 256) out_buffer_size = 256; // Ensure minimum size

        Bytef *out_buffer = (Bytef *)malloc(out_buffer_size);

        if (out_buffer) {
            strm_deflate.avail_out = out_buffer_size;
            strm_deflate.next_out = out_buffer;

            // Perform deflation
            // Use fuzzer data to control flush mode
            int flush_mode = ConsumeInt(&fd) % 6; // Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH, Z_BLOCK
            if (flush_mode > Z_BLOCK) flush_mode = Z_NO_FLUSH; // Map values > Z_BLOCK

            deflate(&strm_deflate, flush_mode);

            // Clean up deflate stream and output buffer
            deflateEnd(&strm_deflate);
            free(out_buffer);
        } else {
             deflateEnd(&strm_deflate); // Clean up even if malloc fails
        }
    }

    // Call crc32 to indirectly exercise byte_swap and crc_word_big
    // These internal functions are used by crc32 depending on architecture and data.
    if (fd.offset < fd.size) {
        uint32_t initial_crc = ConsumeUint32(&fd);
        size_t crc_data_size = fd.size - fd.offset;
        const Bytef* crc_data = (Bytef*)(fd.data + fd.offset);
        uint32_t final_crc = crc32(initial_crc, crc_data, crc_data_size);
        (void)final_crc; // Avoid unused variable warning
        fd.offset = fd.size; // Consume all remaining data
    }


    // Call zlibCompileFlags directly
    // This function's coverage depends on compile-time flags, but calling it
    // ensures the compiled path is executed.
    unsigned long flags = zlibCompileFlags();
    (void)flags; // Avoid unused variable warning

    // To reach inflateSyncPoint, we need an initialized inflate stream.
    z_stream strm_inflate;
    strm_inflate.zalloc = Z_NULL;
    strm_inflate.zfree = Z_NULL;
    strm_inflate.opaque = Z_NULL;

    // Initialize inflate stream
    if (inflateInit(&strm_inflate) == Z_OK) {
        // Call inflateSyncPoint with the stream
        // The coverage depends on the stream's internal state, which is
        // influenced by previous inflate operations (not done here for simplicity)
        // and the input data if inflate() were called first.
        // Calling it directly exercises the function's entry points and basic checks.
        inflateSyncPoint(&strm_inflate);

        // Clean up inflate stream
        inflateEnd(&strm_inflate);
    }

    // To reach gzfread, we need a gzFile handle.
    // Creating a temporary file or using fmemopen is needed.
    // Using fmemopen is generally better for fuzzing as it avoids disk I/O.
    // Need to include <stdio.h> for fmemopen.

    // Use fuzzer data to create an in-memory file
    // The data itself will be the content of the "file"
    // Note: fmemopen requires a null terminator if writing, but we are reading "rb".
    // The size passed to fmemopen is the buffer size, not necessarily the data size.
    // We pass the full fuzzer data and size.
    FILE *mem_file = fmemopen((void *)Data, Size, "rb");
    if (mem_file) {
        // Wrap the FILE* in a gzFile
        gzFile gz_file = gzdopen(fileno(mem_file), "rb");
        if (gz_file) {
            // Use fuzzer data for size and number of elements for gzfread
            size_t size_param = ConsumeSizeT(&fd);
            size_t nitems_param = ConsumeSizeT(&fd);

            // Ensure size_param and nitems_param are not excessively large
            // to prevent huge allocations or timeouts.
            if (size_param > 4096) size_param = 4096;
            if (nitems_param > 4096) nitems_param = 4096;

            // Allocate a buffer for gzfread
            size_t read_buffer_size = 0;
            // Check for potential overflow before multiplication
            if (size_param > 0 && nitems_param > 0 && (size_t)-1 / size_param < nitems_param) {
                 read_buffer_size = (size_t)-1; // Indicate overflow, handle below
            } else {
                 read_buffer_size = size_param * nitems_param;
            }


            if (read_buffer_size > 0 && read_buffer_size < 1024 * 1024) { // Limit buffer size
                void *read_buffer = malloc(read_buffer_size);
                if (read_buffer) {
                    // Call gzfread
                    gzfread(read_buffer, size_param, nitems_param, gz_file);
                    free(read_buffer); // Free the allocated buffer
                }
            } else if (read_buffer_size == 0) {
                 // Still call gzfread with size 0 to test edge cases
                 gzfread(NULL, size_param, nitems_param, gz_file);
            }


            // Clean up gzFile
            gzclose(gz_file);
        }
        // Clean up FILE* (fmemopen allocated the buffer, fclose frees it)
        fclose(mem_file);
    }

    // No memory leaks:
    // - deflate stream is ended with deflateEnd
    // - inflate stream is ended with inflateEnd
    // - output buffer for deflate is freed
    // - read buffer for gzfread is freed
    // - gzFile is closed with gzclose
    // - FILE* from fmemopen is closed with fclose (which frees the buffer)

    return 0;
}