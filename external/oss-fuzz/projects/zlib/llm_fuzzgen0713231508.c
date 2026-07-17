#include <zlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// Fuzzer function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    /*
     * ANALYSIS: The function-level coverage report showed gzfread had low branch
     *           coverage. The line-level report confirmed this was due to several
     *           uncovered error-handling paths, including a NULL file pointer check,
     *           a check for the correct file mode, and an integer overflow check.
     * IMPLEMENTATION: The following code block targets these specific paths.
     *                 - It calls gzfread with a NULL file pointer.
     *                 - It opens a file in write mode and then attempts to read from it.
     *                 - It calls gzfread with arguments that are likely to cause an
     *                   integer overflow.
     */
    gzfread(NULL, 1, 1, NULL);
    gzFile file_w = gzopen(path, "w");
    if (file_w) {
        char buf[1];
        gzfread(buf, 1, 1, file_w);
        gzclose(file_w);
    }
    gzFile file_r = gzopen(path, "r");
    if (file_r) {
        char buf[1];
        gzfread(buf, (size_t)-1, (size_t)-1, file_r);
        gzclose(file_r);
    }
    unlink(path);

    z_stream strm_deflate;
    memset(&strm_deflate, 0, sizeof(strm_deflate));
    unsigned char out[256];

    /*
     * ANALYSIS: The function _tr_tally has 0% coverage. This function is called
     *           by deflate_rle, which is used when the strategy is Z_RLE.
     * IMPLEMENTATION: The following code initializes a deflate stream and sets the
     *                 strategy to Z_RLE to exercise _tr_tally.
     */
    if (deflateInit(&strm_deflate, Z_DEFAULT_COMPRESSION) == Z_OK) {
        deflateParams(&strm_deflate, Z_DEFAULT_COMPRESSION, Z_RLE);
        strm_deflate.avail_in = size;
        strm_deflate.next_in = (Bytef *)data;
        strm_deflate.avail_out = sizeof(out);
        strm_deflate.next_out = out;
        deflate(&strm_deflate, Z_FINISH);
        deflateEnd(&strm_deflate);
    }

    z_stream strm_inflate;
    memset(&strm_inflate, 0, sizeof(strm_inflate));

    /*
     * ANALYSIS: inflateSync and inflateSyncPoint have low branch coverage.
     *           The line-level report shows that calls with NULL streams are
     *           not being made.
     * IMPLEMENTATION: The following code calls inflateSync and inflateSyncPoint
     *                 with NULL to cover these branches.
     */
    inflateSync(NULL);
    inflateSyncPoint(NULL);

    if (inflateInit(&strm_inflate) == Z_OK) {
        strm_inflate.avail_in = strm_deflate.total_out;
        strm_inflate.next_in = out;
        strm_inflate.avail_out = size;
        unsigned char *decompressed = (unsigned char *)malloc(size);
        if (decompressed) {
            strm_inflate.next_out = decompressed;
            /*
             * ANALYSIS: The line-level report for inflateSync shows that the
             *           main logic is not exercised.
             * IMPLEMENTATION: Call inflateSync during an inflation operation
             *                 to exercise its core logic for finding a sync point.
             */
            inflate(&strm_inflate, Z_NO_FLUSH);
            inflateSync(&strm_inflate);
            inflate(&strm_inflate, Z_FINISH);
            free(decompressed);
        }
        inflateEnd(&strm_inflate);
    }

    return 0;
}