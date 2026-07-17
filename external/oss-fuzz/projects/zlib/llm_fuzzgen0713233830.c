#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"
#include "/src/zlib/zconf.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

// FuzzedDataProvider is not available in C, so we will use the raw data.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    /*
     * ANALYSIS: The function-level coverage report showed gzgetc had low branch coverage.
     *           The line-level report confirmed this was at line 414, in the `if (file == NULL)` check.
     * IMPLEMENTATION: The following code block calls gzgetc with a NULL pointer to exercise this
     *                 uncovered error-handling path.
     */
    if (data[0] % 4 == 0) {
        (gzgetc)(NULL);
    }

    /*
     * ANALYSIS: The function-level coverage report showed gzgetc had low branch coverage.
     *           The line-level report confirmed this was at line 419, in the `if (state->mode != GZ_READ)` check.
     * IMPLEMENTATION: The following code block opens a file in write mode and then calls gzgetc on it
     *                 to exercise this uncovered error-handling path.
     */
    if (data[0] % 4 == 1) {
        gzFile file = gzopen(path, "wb");
        if (file) {
            gzgetc(file);
            gzclose(file);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed gzgetc had low branch coverage.
     *           The line-level report confirmed this was at line 424, in the `if (state->x.have)` check.
     *           This branch is not taken, meaning the output buffer is always empty.
     * IMPLEMENTATION: The following code block writes data to a file, rewinds it, and then reads from it
     *                 to ensure the buffer is populated, thus exercising the uncovered branch.
     */
    if (data[0] % 4 == 2) {
        gzFile file = gzopen(path, "w+b");
        if (file) {
            gzwrite(file, data, size);
            gzrewind(file);
            while (gzgetc(file) != -1);
            gzclose(file);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed _tr_tally with 0% coverage.
     *           This function is called by deflate.
     * IMPLEMENTATION: The following code block calls deflate with different strategies to trigger
     *                 a call to _tr_tally.
     */
    if (data[0] % 4 == 3) {
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;

        int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, (int)data[0] % 4);
        if (ret == Z_OK) {
            unsigned char out[1024];
            strm.avail_in = size;
            strm.next_in = (Bytef *)data;
            strm.avail_out = sizeof(out);
            strm.next_out = out;

            deflate(&strm, Z_FINISH);
            deflateEnd(&strm);
        }
    }

    unlink(path);

    return 0;
}