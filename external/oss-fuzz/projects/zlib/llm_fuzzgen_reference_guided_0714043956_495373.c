/* BLOCKER_STRATEGY_CONTRACT
required_state: state->seek must be true (non-zero) when gzgets is called.
state_constructor: Call gzseek(file, offset, SEEK_SET) on the gzFile handle before calling gzgets. The offset is derived from the fuzzer input.
trigger_api: gzgets(file, ...)
preserved_invariants: The initial file creation and writing process is preserved. The overall input consumption model (data[0-4] for parameters, data+5 for content) is maintained. The new gzseek call reuses a byte from the content portion of the input without changing the consumption order.
END_BLOCKER_STRATEGY_CONTRACT */

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
    
    file = gzopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "gzopen error\n");
        unlink(path);
        return 0;
    }

    gzwrite(file, "dummy", 5);
    gzbuffer(file, 1024);


    // Write some data before setting params
    if (gzwrite(file, remaining_data, remaining_size > 10 ? 10 : remaining_size) == 0) {
        // Error or nothing written, still proceed to test other things
    }

    gzsetparams(file, level, strategy);

    gzwrite(file, remaining_data, remaining_size);

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

    /*
     * BLOCKER: The 'if (state->seek)' predicate at gzread.c:517 is not taken.
     * STRATEGY: To set the 'state->seek' flag to true, call gzseek() before
     *           calling gzgets(). This requests a seek operation that gzgets()
     *           will then process, allowing execution to enter the blocked-off branch.
     *           The seek offset is derived from the fuzzer input.
     */
    if (size > 5) {
        gzseek(file, (z_off_t)data[5], SEEK_SET);
    }

    gzgets(file, buffer, sizeof(buffer));

    for (int i = 0; i < 1024; i++) { // Try to fill up the ungetc buffer
        if (gzungetc('a', file) == -1) {
            break;
        }
    }
    gzungetc(-1, file); // Test with negative char

    gzrewind(file);
    gzgets(file, buffer, sizeof(buffer)); // Read again after rewind
    gzclose(file);
    gzclearerr(NULL); // Test on a closed file to hit the NULL state path

    // --- Test deflateBound and deflate ---
    
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (size > 6 && data[6] % 2 == 0) {
        // Enable gzip wrapping
        windowBits += 16;
    }
    
    err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (err != Z_OK) {
        unlink(path);
        return 0;
    }

    if (size > 8) {
        if (data[8] % 3 == 1) {
            deflateParams(&strm, level, Z_HUFFMAN_ONLY);
        } else if (data[8] % 3 == 2) {
            deflateParams(&strm, level, Z_RLE);
        }
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