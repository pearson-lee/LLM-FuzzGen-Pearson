#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Required for mkstemp, write, close, remove on POSIX systems
#include <unistd.h>

// Include the public zlib header for standard API access.
#include "/src/zlib/zlib.h"
// Include internal headers to access functions and data structures not exposed
// in the public API. This is necessary for targeting specific low-coverage
// internal functions like _tr_tally.
#include "/src/zlib/deflate.h"
#include "/src/zlib/gzguts.h"

// Forward-declare internal zlib functions to make them accessible for fuzzing.
// These functions are not part of the public API and thus not in zlib.h.
// Their coverage is 0%, making them high-priority targets.
int _tr_tally(deflate_state *s, unsigned dist, unsigned lc);

// The main fuzzing entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require a minimum amount of data to perform meaningful operations.
    if (size < 32) {
        return 0;
    }

    // --- Part 1: Fuzz zlibCompileFlags and deflateBound ---
    // Target zlibCompileFlags, a function with low coverage.
    (void)zlibCompileFlags();

    z_stream strm_bound;
    strm_bound.zalloc = Z_NULL;
    strm_bound.zfree = Z_NULL;
    strm_bound.opaque = Z_NULL;
    // Target deflateBound, which also has low coverage. It can be called
    // even before stream initialization.
    uLong source_len_bound = *(const uint32_t*)data % (size + 1);
    (void)deflateBound(&strm_bound, source_len_bound);


    // --- Part 2: Fuzz _tr_tally (internal deflate function) ---
    z_stream strm_tally;
    strm_tally.zalloc = Z_NULL;
    strm_tally.zfree = Z_NULL;
    strm_tally.opaque = Z_NULL;

    // To test _tr_tally, we need a valid deflate_state. We get this by
    // initializing a z_stream for deflation.
    if (deflateInit(&strm_tally, Z_DEFAULT_COMPRESSION) == Z_OK) {
        if (strm_tally.state != NULL) {
            // Use fuzzer data to generate arguments for _tr_tally.
            // This internal function has 0% code coverage.
            unsigned dist = *(const unsigned int*)(data + 4) % 30000;
            // The `lc` parameter must be <= 255 to avoid an out-of-bounds read
            // on the internal `_length_code` array (size 256).
            unsigned lc = *(const unsigned int*)(data + 8) % 256;
            _tr_tally(strm_tally.state, dist, lc);
        }
        // Ensure proper cleanup of the stream resources.
        deflateEnd(&strm_tally);
    }


    // --- Part 3: Fuzz gzungetc and gzseek (gzipped file I/O) ---
    const size_t data_for_compression_offset = 16;
    if (size > data_for_compression_offset) {
        const uint8_t *compress_data = data + data_for_compression_offset;
        const size_t compress_size = size - data_for_compression_offset;

        // To test gzread functions, we create a temporary compressed file from
        // the fuzzer's input data.
        char tmp_filename[] = "/tmp/zlib_fuzz-XXXXXX";
        int fd = mkstemp(tmp_filename);
        if (fd == -1) {
            return 0;
        }

        // Allocate buffer and compress data.
        uLong compressed_len = compressBound(compress_size);
        uint8_t *compressed_buf = (uint8_t *)malloc(compressed_len);
        if (!compressed_buf) {
            close(fd);
            remove(tmp_filename);
            return 0;
        }

        if (compress(compressed_buf, &compressed_len, compress_data, compress_size) == Z_OK) {
            // Write compressed data to the temp file.
            (void)write(fd, compressed_buf, compressed_len);
        }
        // Memory cleanup.
        free(compressed_buf);
        close(fd);

        // Open the temporary file with gzopen for reading.
        gzFile file = gzopen(tmp_filename, "rb");
        if (file) {
            // Target gzungetc, a function with low coverage.
            int c = gzgetc(file);
            if (c != -1) {
                gzungetc(c, file);
            }

            // Target the underlying gz_skip function (0% coverage) via the public gzseek API.
            z_off_t offset_seek = *(const uint32_t*)(data + 12);
            gzseek(file, offset_seek, SEEK_SET);

            // Resource cleanup for the gzFile handle.
            gzclose(file);
        }

        // File system cleanup.
        remove(tmp_filename);
    }

    return 0;
}