#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        exit(1); \
    } \
}

// Fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0;
    }

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", "fuzz");

    gzFile file;
    z_stream strm;
    int err;

    // Consume data for parameters
    int level = data[0] % 10 - 1; // -1 to 8
    int strategy = data[1] % 5; // 0 to 4
    int flush_type = data[2] % 7; // To get different flush types
    int windowBits = (data[3] % 8) + 8; // 8 to 15
    int memLevel = (data[4] % 9) + 1; // 1 to 9
    const uint8_t *remaining_data = data + 5;
    size_t remaining_size = size - 5;
    
    if (remaining_size == 0) {
        unlink(path);
        return 0;
    }

    // --- Test gzopen, gzsetparams, gzwrite, gzflush, gzclose ---
    
    /*
     * ANALYSIS: The coverage report for gzsetparams shows that the branch at line 583
     *           (if (state->size)) is never taken. This is because no data has been
     *           written to the file yet, so the internal buffer is empty.
     * IMPLEMENTATION: First, open a file and write some data to it. Then, call
     *                 gzsetparams to ensure that state->size is non-zero, allowing
     *                 the fuzzer to enter this previously uncovered block.
     */
    file = gzopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "gzopen error\n");
        unlink(path);
        return 0;
    }

    // Write some data before setting params
    if (gzwrite(file, remaining_data, remaining_size > 10 ? 10 : remaining_size) == 0) {
        // Error or nothing written, still proceed to test other things
    }

    gzsetparams(file, level, strategy);

    gzwrite(file, remaining_data, remaining_size);

    /*
     * ANALYSIS: The coverage report for gzflush shows that invalid flush parameters
     *           are not being tested (lines 541-542).
     * IMPLEMENTATION: The following code block calls gzflush with a value outside
     *                 the valid range [0, 5] to exercise this error path.
     */
    if (size > 1) {
        if (data[1] % 10 == 0) { // Sporadically test invalid flush
             gzflush(file, 99); // Invalid flush parameter
        }
    }

    gzflush(file, flush_type);
    gzclose(file);

    // --- Test gzopen, gzungetc, gzgets, gzclose ---

    file = gzopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "gzopen error for reading\n");
        unlink(path);
        return 0;
    }

    char buffer[256];
    gzgets(file, buffer, sizeof(buffer));

    /*
     * ANALYSIS: The coverage report for gzungetc shows that the error path for
     *           pushing a character when the buffer is full (line 478) is never
     *           taken. Additionally, the check for a negative character input
     *           (line 464) is also uncovered.
     * IMPLEMENTATION: The following loop repeatedly calls gzungetc to fill the
     *                 internal buffer and trigger the "out of room" error. A
     *                 separate call with a negative value is made to cover the
     *                 invalid input check.
     */
    for (int i = 0; i < 1024; i++) { // Try to fill up the ungetc buffer
        if (gzungetc('a', file) == -1) {
            break;
        }
    }
    gzungetc(-1, file); // Test with negative char

    /*
     * ANALYSIS: The function-level coverage report showed that gzrewind and gzclearerr
     *           have low branch coverage. The line-level report for gzclearerr shows
     *           that the `if (state == NULL)` check is not taken. The report for
     *           gzrewind shows that the `if (state->seek)` check is not taken.
     * IMPLEMENTATION: The following code calls gzrewind and gzclearerr to improve their
     *                 coverage. A call to gzrewind is made on a valid file handle to
     *                 exercise its main logic. gzclearerr is called on a closed file
     *                 (which sets its internal state to NULL) to hit the uncovered NULL check.
     */
    gzrewind(file);
    gzgets(file, buffer, sizeof(buffer)); // Read again after rewind
    gzclose(file);
    gzclearerr(NULL); // Test on a closed file to hit the NULL state path

    // --- Test deflateBound and deflate ---
    
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    /*
     * ANALYSIS: The coverage report for deflateInit2_ shows multiple uncovered branches
     *           related to invalid parameters and different wrapping modes (e.g. gzip).
     *           Specifically, the gzip-related branches (e.g. line 421) are not covered.
     * IMPLEMENTATION: The windowBits parameter is sometimes set to a value greater
     *                 than 15, which enables gzip wrapping and exercises these paths.
     *                 Other parameters are also varied based on fuzzer input.
     */
    if (size > 6 && data[6] % 2 == 0) {
        // Enable gzip wrapping
        windowBits += 16;
    }
    
    err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (err != Z_OK) {
        unlink(path);
        return 0;
    }

    unsigned long compressed_size = deflateBound(&strm, remaining_size);
    unsigned char *compressed_buffer = (unsigned char *)malloc(compressed_size);
    if (compressed_buffer == NULL) {
        deflateEnd(&strm);
        unlink(path);
        return 0;
    }

    strm.avail_in = remaining_size;
    strm.next_in = (Bytef *)remaining_data;
    strm.avail_out = compressed_size;
    strm.next_out = compressed_buffer;

    /*
     * ANALYSIS: The line coverage report for deflate shows that the error handling
     *           for a NULL output buffer (strm.next_out == Z_NULL at line 963) and
     *           zero available output space (strm.avail_out == 0 at line 968) are
     *           not being exercised.
     * IMPLEMENTATION: The following code blocks conditionally set `next_out` to NULL
     *                 or `avail_out` to 0 before calling `deflate` to specifically
     *                 trigger and test these un-fuzzed error conditions.
     */
    if (size > 7) {
        if (data[7] % 4 == 1) {
            strm.next_out = Z_NULL;
        } else if (data[7] % 4 == 2) {
            strm.avail_out = 0;
        }
    }

    err = deflate(&strm, Z_FINISH);
    // We expect errors here from the injected faults, so we don't check them.

    deflateEnd(&strm);
    free(compressed_buffer);

    unlink(path);

    return 0;
}