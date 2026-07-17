#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"

// Helper struct to manage the fuzz data buffer.
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzDataProvider;

// Safely consume a block of data from the buffer.
static bool consume_data(FuzzDataProvider *fdp, void *dest, size_t len) {
    if (fdp->offset + len > fdp->size) {
        if (fdp->size > fdp->offset) {
            len = fdp->size - fdp->offset;
        } else {
            return false;
        }
    }
    memcpy(dest, fdp->data + fdp->offset, len);
    fdp->offset += len;
    return true;
}

// Consume an integral value of a specific type.
#define CONSUME_INTEGRAL(fdp, type) \
    ({ \
        type val = 0; \
        consume_data(fdp, &val, sizeof(type)); \
        val; \
    })

// Consume a boolean value.
static bool consume_bool(FuzzDataProvider *fdp) {
    return CONSUME_INTEGRAL(fdp, uint8_t) & 1;
}

// Consume an integral within a given range.
static int consume_range(FuzzDataProvider *fdp, int min, int max) {
    if (min >= max) {
        return min;
    }
    long range = (long)max - min + 1;
    return min + (CONSUME_INTEGRAL(fdp, uint32_t) % range);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzDataProvider fdp = {data, size, 0};
    z_stream strm;
    gz_header head;
    Bytef *extra_buf = NULL;
    Bytef *name_buf = NULL;
    Bytef *comment_buf = NULL;

    memset(&strm, 0, sizeof(strm));
    memset(&head, 0, sizeof(head));

    (void)zlibCompileFlags();

    if (consume_range(&fdp, 0, 9) == 0) {
        uLong sourceLen = CONSUME_INTEGRAL(&fdp, uLong);
        deflateBound(&strm, sourceLen);
    }

    int level = consume_range(&fdp, -1, 9);
    int windowBits = consume_range(&fdp, -15, 15);
    int memLevel = consume_range(&fdp, 1, 9);
    int strategy = consume_range(&fdp, 0, 4);

    if (deflateInit2_(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream)) != Z_OK) {
        goto cleanup;
    }

    if (consume_bool(&fdp)) {
        if (consume_bool(&fdp)) {
            size_t extra_len = consume_range(&fdp, 0, 512);
            if (extra_len > 0) {
                extra_buf = (Bytef*)malloc(extra_len);
                if (extra_buf && consume_data(&fdp, extra_buf, extra_len)) {
                    head.extra = extra_buf;
                    head.extra_len = extra_len;
                }
            }
        }
        if (consume_bool(&fdp)) {
            size_t name_len = consume_range(&fdp, 0, 255);
            if (name_len > 0) {
                name_buf = (Bytef*)malloc(name_len + 1);
                if (name_buf && consume_data(&fdp, name_buf, name_len)) {
                    name_buf[name_len] = '\0';
                    head.name = name_buf;
                }
            }
        }
        if (consume_bool(&fdp)) {
            size_t comment_len = consume_range(&fdp, 0, 255);
            if (comment_len > 0) {
                comment_buf = (Bytef*)malloc(comment_len + 1);
                if (comment_buf && consume_data(&fdp, comment_buf, comment_len)) {
                    comment_buf[comment_len] = '\0';
                    head.comment = comment_buf;
                }
            }
        }
        head.hcrc = consume_bool(&fdp);
        head.os = CONSUME_INTEGRAL(&fdp, int);
        head.time = CONSUME_INTEGRAL(&fdp, uLong);
        head.text = consume_bool(&fdp);

        deflateSetHeader(&strm, &head);
    }

    uLong sourceLen = CONSUME_INTEGRAL(&fdp, uLong);
    (void)deflateBound(&strm, sourceLen);

cleanup:
    deflateEnd(&strm);
    free(extra_buf);
    free(name_buf);
    free(comment_buf);

    return 0;
}