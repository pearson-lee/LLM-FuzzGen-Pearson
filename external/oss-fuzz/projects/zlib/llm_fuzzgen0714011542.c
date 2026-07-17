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
            gzclose(file_w);
        }
    }

    gzFile file = gzopen(path, "wb");
    if (!file) {
        return 0;
    }

    unsigned int len = FDP_get_remaining(&fdp);
    if (FDP_get_bool(&fdp)) {
        // Make len negative when cast to int
        len = 0x80000000;
    }

    if (FDP_has_remaining(&fdp)) {
        size_t write_len = FDP_get_remaining(&fdp);
        uint8_t *write_data = (uint8_t*)malloc(write_len);
        if(!write_data) {
            gzclose(file);
            unlink(path);
            return 0;
        }
        if (FDP_get_data(&fdp, write_len, write_data)) {
            gzwrite(file, write_data, write_len);
        }
        free(write_data);
    }
    gzclose(file);

    file = gzopen(path, "rb");
    if (!file) {
        unlink(path);
        return 0;
    }

    char buffer[1024];
    gzread(file, buffer, sizeof(buffer));
    gzclose(file);
    unlink(path);

    /*
     * ANALYSIS: The function-level coverage report showed crc32_z has low coverage.
     *           The line-level report for crc32.c showed that byte_swap and crc_word_big are never called.
     * IMPLEMENTATION: The following code block calls crc32_z to exercise this functionality.
     */
    if (FDP_has_remaining(&fdp)) {
        uLong crc = crc32(0L, Z_NULL, 0);
        size_t crc_len = FDP_get_remaining(&fdp);
        uint8_t *crc_data = (uint8_t*)malloc(crc_len);
        if(!crc_data) {
            return 0;
        }
        if (FDP_get_data(&fdp, crc_len, crc_data)) {
            crc32_z(crc, crc_data, crc_len);
        }
        free(crc_data);
    }

    /*
     * ANALYSIS: The function-level coverage report showed _tr_tally is never called.
     *           This is an internal function to the deflate algorithm.
     * IMPLEMENTATION: The following code block calls deflate to attempt to trigger _tr_tally.
     */
    if (FDP_has_remaining(&fdp)) {
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        deflateInit(&strm, Z_DEFAULT_COMPRESSION);

        size_t deflate_len = FDP_get_remaining(&fdp);
        uint8_t *deflate_data = (uint8_t*)malloc(deflate_len);
        if(!deflate_data) {
            deflateEnd(&strm);
            return 0;
        }

        if (FDP_get_data(&fdp, deflate_len, deflate_data)) {
            strm.avail_in = deflate_len;
            strm.next_in = deflate_data;
            strm.avail_out = deflate_len;
            strm.next_out = (Bytef*)malloc(deflate_len);
            if(strm.next_out) {
                deflate(&strm, Z_FINISH);
                free(strm.next_out);
            }
        }
        free(deflate_data);
        deflateEnd(&strm);
    }

    zlibCompileFlags();

    return 0;
}