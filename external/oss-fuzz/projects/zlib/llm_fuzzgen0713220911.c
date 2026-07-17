#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        exit(1); \
    } \
}

// Fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 20) { // Increased minimum size for dictionary and data
        return 0;
    }

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", "llm_fuzzgen0713220244");

    gzFile file;
    z_stream strm;
    int err;

    // Consume data for parameters
    int level = data[0] % 10 - 1; // -1 to 8
    int strategy = data[1] % 5; // 0 to 4
    int flush_type = data[2] % 7; // To get different flush types
    int windowBits = (data[3] % 8) + 8; // 8 to 15
    int memLevel = (data[4] % 9) + 1; // 1 to 9
    const uint8_t *dict_data = data + 5;
    size_t dict_size = size > 15 ? 10 : 0;
    const uint8_t *remaining_data = data + 15;
    size_t remaining_size = size - 15;
    
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

    // --- Test gzopen, gzungetc, gzgets, gzseek, gzdirect, gzclose ---

    file = gzopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "gzopen error for reading\n");
        unlink(path);
        return 0;
    }

    char buffer[256];
    gzgets(file, buffer, sizeof(buffer));

    for (int i = 0; i < 1024; i++) { // Try to fill up the ungetc buffer
        if (gzungetc('a', file) == -1) {
            break;
        }
    }
    gzungetc(-1, file); // Test with negative char

    /*
     * ANALYSIS: The coverage report for `gzseek64` shows that the backward seeking
     *           logic (offset < 0) and seeking from the end of the file (whence = SEEK_END)
     *           are not covered.
     * IMPLEMENTATION: The following code calls `gzseek64` with `SEEK_END` and a
     *                 negative offset to exercise these uncovered paths.
     */
    gzseek64(file, -10, SEEK_CUR); // Negative offset
    gzseek64(file, 0, SEEK_END);   // whence = SEEK_END

    /*
     * ANALYSIS: The function `gzgetc_` is completely uncovered. It is called by `gzgetc`
     *           only when the `direct` flag is set on the file state.
     * IMPLEMENTATION: Call `gzdirect` to exercise the function, then call `gzgetc`.
     *                 Note: gzdirect() only returns the direct flag, it does not set it.
     */
    gzdirect(file);
    gzgetc(file);

    gzrewind(file);
    gzgets(file, buffer, sizeof(buffer)); // Read again after rewind
    gzclose(file);
    
    /*
     * ANALYSIS: The coverage reports for `gzseek64`, `gztell64`, `gzoffset64`, and
     *           `gzeof` show that the initial `if (file == NULL)` checks are not covered.
     * IMPLEMENTATION: The following code calls these functions with a NULL file
     *                 pointer to exercise these simple error-handling paths.
     */
    gzseek64(NULL, 0, SEEK_SET);
    gztell64(NULL);
    gzoffset64(NULL);
    gzeof(NULL);
    gzclearerr(NULL);

    // --- Test deflateBound and deflate ---
    
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (size > 6 && data[6] % 2 == 0) {
        windowBits += 16;
    }
    
    err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (err != Z_OK) {
        unlink(path);
        return 0;
    }

    /*
     * ANALYSIS: The function `_tr_tally` is completely uncovered. It is called
     *           internally by `deflate` during compression, often when a dictionary
     *           is being used or for certain input patterns.
     * IMPLEMENTATION: Call `deflateSetDictionary` before `deflate` to provide a
     *                 compression dictionary. This alters the internal compression
     *                 state and increases the likelihood of exercising more complex
     *                 paths within `deflate`, including those that call `_tr_tally`.
     */
    if (dict_size > 0) {
        deflateSetDictionary(&strm, dict_data, dict_size);
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