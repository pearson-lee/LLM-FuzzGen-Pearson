/* BLOCKER_STRATEGY_CONTRACT
required_state: `inflateReset2()` must return a value other than `Z_OK`. This happens when it is called with an invalid `windowBits` parameter.
state_constructor: `inflateInit2()` is called with a `windowBits` value in the range [1, 7]. These values are invalid and cause `inflateReset2()` to return `Z_STREAM_ERROR`.
trigger_api: `inflateInit2()` is called, which then calls `inflateReset2()` with the invalid `windowBits`.
preserved_invariants: The original fuzzer's input consumption contract via the FuzzedDataProvider is maintained. The new data consumption happens at the end of the function. The existing file-based operations are preserved.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "zlib_fuzzer"
#endif

// FuzzedDataProvider equivalent for C
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzedDataProvider;

FuzzedDataProvider FDP_create(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = {data, size, 0};
    return fdp;
}

int FDP_has_remaining(FuzzedDataProvider *fdp) {
    return fdp->offset < fdp->size;
}

size_t FDP_get_remaining(FuzzedDataProvider *fdp) {
    return fdp->size - fdp->offset;
}

int FDP_get_data(FuzzedDataProvider *fdp, size_t count, uint8_t *out) {
    if (fdp->offset + count > fdp->size) {
        return 0;
    }
    memcpy(out, fdp->data + fdp->offset, count);
    fdp->offset += count;
    return 1;
}

uint8_t FDP_get_uint8(FuzzedDataProvider *fdp) {
    uint8_t value = 0;
    FDP_get_data(fdp, sizeof(value), (uint8_t*)&value);
    return value;
}

int FDP_get_bool(FuzzedDataProvider *fdp) {
    return FDP_get_uint8(fdp) % 2;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FDP_create(data, size);

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    /*
     * ANALYSIS: The function-level coverage report showed gzwrite and gzread have low coverage.
     *           The line-level report for gzwrite showed the `file == NULL` check at line 241
     *           and the `(int)len < 0` check at line 251 are never hit.
     *           Similarly for gzread, the `file == NULL` check at line 349, the `state->mode != GZ_READ`
     *           check at line 354 and the `(int)len < 0` check at line 360 are never hit.
     * IMPLEMENTATION: The following code block sometimes calls gzwrite and gzread with a NULL file pointer,
     *                 a large length, and on a file opened for writing to exercise these uncovered paths.
     */
    if (FDP_get_bool(&fdp)) {
        gzwrite(NULL, data, size);
        gzread(NULL, (void*)data, size);
        gzFile file_w = gzopen(path, "wb");
        if(file_w) {
            gzread(file_w, (void*)data, size);
            /*
             * ANALYSIS: The function-level coverage reports for gzrewind and gzseek64 showed
             *           uncovered branches when operating on files opened in write mode.
             * IMPLEMENTATION: The following calls exercise gzrewind and gzseek64 on a file
             *                 opened with "wb" to cover these paths.
             */
            gzrewind(file_w);
            gzseek64(file_w, 1, SEEK_SET);
            gzclose(file_w);
        }
    }

    gzFile file = gzopen(path, "wb");
    if (file) {
        unsigned int len = FDP_get_remaining(&fdp) / 2;
        if (FDP_get_bool(&fdp)) {
            // Make len negative when cast to int
            len = 0x80000000;
        }

        if (len > 0 && FDP_has_remaining(&fdp)) {
            size_t write_len = len;
            uint8_t *write_data = (uint8_t*)malloc(write_len);
            if(write_data) {
                if (FDP_get_data(&fdp, write_len, write_data)) {
                    gzwrite(file, write_data, write_len);
                }
                free(write_data);
            }
        }
        gzclose(file);
    }


    file = gzopen(path, "rb");
    if (file) {
        char buffer[1024];
        gzread(file, buffer, sizeof(buffer));

        /*
         * ANALYSIS: The function-level coverage report for gzseek64 showed several uncovered
         *           branches related to the 'whence' parameter and negative offsets.
         * IMPLEMENTATION: The following calls to gzseek64 use SEEK_CUR, a negative offset,
         *                 and a backwards seek to target these uncovered branches.
         */
        gzseek64(file, 1, SEEK_CUR);
        gzseek64(file, -1, SEEK_SET);
        gzrewind(file);
        gzseek(file, 1, SEEK_SET);
        gzseek(file, 0, SEEK_SET);

        gzclose(file);
    }

    /*
     * ANALYSIS: The function-level coverage report showed crc32_z has low coverage.
     *           The original fuzzer had a logical error where this code block was
     *           unreachable because all fuzzer data was consumed by prior operations.
     * IMPLEMENTATION: The fuzzer logic has been restructured to ensure this block can be
     *                 reached. It calls crc32_z to exercise this functionality.
     */
    if (FDP_get_bool(&fdp) && FDP_has_remaining(&fdp)) {
        uLong crc = crc32(0L, Z_NULL, 0);
        size_t crc_len = FDP_get_remaining(&fdp);
        uint8_t *crc_data = (uint8_t*)malloc(crc_len);
        if(crc_data) {
            if (FDP_get_data(&fdp, crc_len, crc_data)) {
                crc32_z(crc, crc_data, crc_len);
            }
            free(crc_data);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed _tr_tally is never called.
     *           This is an internal function to the deflate algorithm. The original fuzzer
     *           had a logical error making this block unreachable.
     * IMPLEMENTATION: The fuzzer logic has been restructured. The following code block
     *                 calls deflate, which in turn should trigger the _tr_tally function.
     */
    if (FDP_get_bool(&fdp) && FDP_has_remaining(&fdp)) {
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
            size_t deflate_len = FDP_get_remaining(&fdp);
            uint8_t *deflate_data = (uint8_t*)malloc(deflate_len);
            if(deflate_data) {
                if (FDP_get_data(&fdp, deflate_len, deflate_data)) {
                    strm.avail_in = deflate_len;
                    strm.next_in = deflate_data;
                    strm.avail_out = deflate_len;
                    Bytef* out_buf = (Bytef*)malloc(deflate_len);
                    if(out_buf) {
                        strm.next_out = out_buf;
                        deflate(&strm, Z_FINISH);
                        free(out_buf);
                    }
                }
                free(deflate_data);
            }
            deflateEnd(&strm);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report for adler32_combine_ had a branch
     *           with zero hits. The line-level report confirmed this was at line 139,
     *           in the `if (len2 < 0)` check.
     * IMPLEMENTATION: The following code block calls adler32_combine_ with a negative
     *                 len2 to exercise this uncovered error-handling path.
     */
    adler32_combine(0, 0, -1);

    /*
     * ANALYSIS: The function-level coverage reports for gzgetc, gzgets, gzputc, and gzungetc
     *           showed several uncovered branches. The original fuzzer had a logical error
     *           where the file was unlinked before this block, causing gzopen to always fail.
     * IMPLEMENTATION: The unlink call has been moved to the end of the fuzzer. This block
     *                 now successfully opens the file and calls these functions with specific
     *                 arguments to target the uncovered paths.
     */
    (gzgetc)(NULL);
    gzFile file_r = gzopen(path, "rb");
    if (file_r) {
        char buffer[1024];
        gzgets(file_r, NULL, sizeof(buffer));
        gzgets(file_r, buffer, 0);
        gzungetc('a', file_r);
        gzgetc(file_r);
        gzclose(file_r);
    }
    gzgets(NULL, NULL, 0);
    (gzputc)(NULL, 'a');
    gzungetc(0, NULL);


    /*
     * ANALYSIS: The function-level coverage report for uncompress2 showed a branch with
     *           zero hits. The line-level report confirmed this was at line 36, in the
     *           `if (*destLen)` check.
     * IMPLEMENTATION: The following code block calls uncompress2 with *destLen = 0 to
     *                 exercise this uncovered path.
     */
    uLong destLen = 0;
    uLong sourceLen = size;
    char out_buffer[1];
    uncompress2((Bytef*)out_buffer, &destLen, data, &sourceLen);


    zlibCompileFlags();

    /* BLOCKER_TARGET_CODE */
    /*
     * ANALYSIS: The blocker is in `inflateInit2_` at line 211. The condition
     *           `ret != Z_OK` is not met because `inflateReset2` returns `Z_OK`.
     *           `inflateReset2` can return `Z_STREAM_ERROR` if the `windowBits`
     *           parameter is invalid. The existing call path via `gzread` uses a
     *           hardcoded `windowBits` value that is normalized to a valid one.
     * IMPLEMENTATION: To trigger the error, we call `inflateInit2` directly with
     *                 an invalid `windowBits` value. A value between 1 and 7
     *                 will cause `inflateReset2` to return `Z_STREAM_ERROR`. We
     *                 use a value from the fuzzer input to explore different
     *                 invalid values.
     */
    if (FDP_has_remaining(&fdp)) {
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.avail_in = 0;
        strm.next_in = Z_NULL;

        /* A `windowBits` value in [1, 7] will trigger the error. */
        int windowBits = (FDP_get_uint8(&fdp) % 7) + 1;
        if (inflateInit2(&strm, windowBits) == Z_STREAM_ERROR) {
            /* Successfully triggered the error path. */
        }
        /*
         * We must call inflateEnd() to free the memory allocated by
         * inflateInit2(), even if it fails. The blocker is hit before
         * inflateInit2 returns, and it cleans up some memory, but not all.
         * The strm.state is set to Z_NULL, and inflateEnd handles this.
         */
        inflateEnd(&strm);
    }
    /* END_BLOCKER_TARGET_CODE */

    unlink(path);

    return 0;
}
