#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"

// The _FUZZ_TARGET_NAME macro is not a standard C feature, so we define it here for the purpose of this example.
// In a real fuzzing environment (e.g., OSS-Fuzz), this would be provided by the build system.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzzer"
#endif

#define MIN_WINDOW_BITS 8
#define MAX_WINDOW_BITS 15
#define WINDOW_SIZE (1U << MAX_WINDOW_BITS)

struct FuzzData {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

// Input callback for inflateBack
static unsigned int fuzz_in_func(void *in_desc, unsigned char **buf) {
    struct FuzzData *fuzz_data = (struct FuzzData *)in_desc;
    if (fuzz_data->offset < fuzz_data->size) {
        size_t remaining = fuzz_data->size - fuzz_data->offset;
        size_t to_copy = remaining > 4096 ? 4096 : remaining;
        *buf = (unsigned char *)fuzz_data->data + fuzz_data->offset;
        fuzz_data->offset += to_copy;
        return to_copy;
    }
    *buf = NULL;
    return 0;
}

// Output callback for inflateBack
static int fuzz_out_func(void *out_desc, unsigned char *buf, unsigned len) {
    // Discard the output
    (void)out_desc;
    (void)buf;
    (void)len;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Use one byte to decide which API to fuzz
    unsigned char api_selector = data[0];
    data++;
    size--;

    if (api_selector % 2 == 0) {
        /*
         * ANALYSIS: The function-level coverage report showed that inflateBackInit_,
         *           inflateBack, and inflateBackEnd in infback.c have 0% coverage.
         *           These functions provide a raw inflation interface with callbacks.
         * IMPLEMENTATION: This code block exercises the inflateBack* API. It initializes
         *                 a z_stream, allocates a window, and calls inflateBackInit_.
         *                 It then calls inflateBack with input and output callbacks to
         *                 process the fuzzer-provided data. Finally, it cleans up with
         *                 inflateBackEnd.
         */
        z_stream strm;
        memset(&strm, 0, sizeof(strm));

        unsigned char *window = (unsigned char *)malloc(WINDOW_SIZE);
        if (!window) {
            return 0;
        }

        // Use a byte from the input to determine windowBits
        int windowBits = MIN_WINDOW_BITS + (size > 0 ? (data[0] % (MAX_WINDOW_BITS - MIN_WINDOW_BITS + 1)) : 0);

        if (inflateBackInit_(&strm, windowBits, window, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
            struct FuzzData fuzz_data = {data, size, 0};
            inflateBack(&strm, fuzz_in_func, &fuzz_data, fuzz_out_func, NULL);
            inflateBackEnd(&strm);
        }

        free(window);
    } else {
        /*
         * ANALYSIS: The function-level coverage report showed many gz* functions
         *           in gzlib.c, gzread.c, and gzwrite.c have 0% or low coverage.
         *           These include gzopen, gzwrite, gzread, gzseek, and gzclose.
         * IMPLEMENTATION: This code block targets the file-based gz* API. It creates
         *                 a temporary file, opens it with gzopen, writes compressed
         *                 data with gzwrite, and then reopens it to read with gzread.
         *                 It also calls gzseek and gztell to exercise seeking
         *                 functionality. This ensures that the file I/O and
         *                 compression/decompression paths of the gz* functions are tested.
         */
        char path[256];
        snprintf(path, sizeof(path), "/tmp/%s.gz", _FUZZ_TARGET_NAME);

        // Compress the input data first to have valid gzip data to read
        uLongf compressed_size = compressBound(size);
        unsigned char *compressed_data = (unsigned char *)malloc(compressed_size);
        if (!compressed_data) {
            return 0;
        }

        if (compress2(compressed_data, &compressed_size, data, size, Z_DEFAULT_COMPRESSION) == Z_OK) {
            gzFile file = gzopen(path, "wb");
            if (file) {
                gzwrite(file, compressed_data, compressed_size);
                gzclose(file);

                file = gzopen(path, "rb");
                if (file) {
                    unsigned char read_buffer[1024];
                    int bytes_read;
                    while ((bytes_read = gzread(file, read_buffer, sizeof(read_buffer))) > 0) {
                        // Discard data
                    }
                    gzrewind(file);
                    gzseek(file, 0, SEEK_SET);
                    gztell(file);
                    gzclose(file);
                }
            }
        }

        free(compressed_data);
        unlink(path);
    }

    return 0;
}