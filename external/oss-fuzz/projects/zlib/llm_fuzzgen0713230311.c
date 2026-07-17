#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"

#define _FUZZ_TARGET_NAME "fuzz_target"

// This fuzzer targets several functions with low coverage:
// - gzrewind
// - gzerror
// - crc32_z (to cover byte_swap and crc_word_big)
// - deflate (to cover _tr_tally)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    // Write some data to a file
    gzFile file = gzopen(path, "wb");
    if (file) {
        gzwrite(file, data, size);
        gzclose(file);
    }

    // Re-open for reading
    file = gzopen(path, "rb");
    if (file) {
        /*
         * ANALYSIS: The function-level coverage report showed gzrewind had low branch coverage.
         *           The line-level report showed that the `state->mode != GZ_READ` branch was not taken.
         * IMPLEMENTATION: Call gzrewind on a file opened in read mode.
         */
        gzrewind(file);

        int errnum;
        /*
         * ANALYSIS: The function-level coverage report showed gzerror had low branch coverage.
         *           The line-level report showed that the `state->mode != GZ_READ && state->mode != GZ_WRITE`
         *           branch was not taken.
         * IMPLEMENTATION: Call gzerror on a file opened in read mode.
         */
        gzerror(file, &errnum);
        gzclose(file);
    }

    /*
     * ANALYSIS: The function-level coverage report showed gzrewind had low branch coverage.
     *           The line-level report showed that the `file == NULL` branch was not taken.
     * IMPLEMENTATION: Call gzrewind with a NULL file pointer.
     */
    gzrewind(NULL);

    int errnum_null;
    /*
     * ANALYSIS: The function-level coverage report showed gzerror had low branch coverage.
     *           The line-level report showed that the `file == NULL` branch was not taken.
     * IMPLEMENTATION: Call gzerror with a NULL file pointer.
     */
    gzerror(NULL, &errnum_null);

    // Open in write mode to test other branches
    file = gzopen(path, "wb");
    if (file) {
        /*
         * ANALYSIS: The function-level coverage report showed gzrewind had low branch coverage.
         *           The line-level report showed that the `state->mode != GZ_READ` branch was not taken.
         * IMPLEMENTATION: Call gzrewind on a file opened in write mode to trigger the error.
         */
        gzrewind(file);

        int errnum_write;
        /*
         * ANALYSIS: The function-level coverage report showed gzerror had low branch coverage.
         *           The line-level report showed that the `state->mode != GZ_READ && state->mode != GZ_WRITE`
         *           branch was not taken.
         * IMPLEMENTATION: Call gzerror on a file opened in write mode.
         */
        gzerror(file, &errnum_write);
        gzclose(file);
    }


    /*
     * ANALYSIS: The function-level coverage report showed crc32_z, byte_swap and
     *           crc_word_big had 0% coverage.
     * IMPLEMENTATION: Call crc32_z to exercise these functions.
     */
    crc32_z(0, data, size);


    /*
     * ANALYSIS: The function-level coverage report showed _tr_tally had 0% coverage.
     *           _tr_tally is called by deflate.
     * IMPLEMENTATION: The following code block calls deflate to exercise _tr_tally.
     */
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
        strm.avail_in = size;
        strm.next_in = (Bytef *)data;
        unsigned char out[256];
        strm.avail_out = sizeof(out);
        strm.next_out = out;
        deflate(&strm, Z_FINISH);
        deflateEnd(&strm);
    }

    unlink(path);

    return 0;
}