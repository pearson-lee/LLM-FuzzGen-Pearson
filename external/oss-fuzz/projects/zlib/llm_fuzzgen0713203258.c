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
#define CHUNK_SIZE 1024

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
    if (size < 4) {
        return 0;
    }

    // Use one byte to decide which API to fuzz
    unsigned char api_selector = data[0];
    data++;
    size--;

    if (api_selector % 3 == 0) {
        /*
         * ANALYSIS: The function-level coverage report showed that inflateBackInit_,
         *           inflateBack, and inflateBackEnd in infback.c have low branch coverage.
         *           The fuzzer coverage shows the error path of inflateBackInit_ is never taken.
         * IMPLEMENTATION: This code block exercises the inflateBack* API. It uses a raw byte
         *                 from the fuzzer input for `windowBits` without validation. This allows
         *                 invalid values to be passed to `inflateBackInit_`, exercising its
         *                 error-handling paths and improving branch coverage.
         */
        z_stream strm;
        memset(&strm, 0, sizeof(strm));

        unsigned char *window = (unsigned char *)malloc(WINDOW_SIZE);
        if (!window) {
            return 0;
        }

        // Use a raw byte from the input to allow invalid windowBits values
        int windowBits = data[0];

        if (inflateBackInit_(&strm, windowBits, window, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
            struct FuzzData fuzz_data = {data, size, 0};
            inflateBack(&strm, fuzz_in_func, &fuzz_data, fuzz_out_func, NULL);
            inflateBackEnd(&strm);
        }

        free(window);
    } else if (api_selector % 3 == 1) {
        /*
         * ANALYSIS: The function-level coverage report showed many gz* functions
         *           in gzwrite.c and gzread.c (e.g., gzsetparams, gzputc, gzputs,
         *           gzflush, gzgets, gzungetc, gzeof, gzerror) have 0% coverage.
         * IMPLEMENTATION: This block is enhanced to call these uncovered functions.
         *                 It calls gzsetparams after opening the file, uses gzputc/gzputs
         *                 for writing, calls gzflush, and uses gzgets/gzungetc for reading.
         *                 It also calls gzeof, gzerror, and gzclearerr to hit more error-handling code.
         */
        char path[256];
        snprintf(path, sizeof(path), "/tmp/%s.gz", _FUZZ_TARGET_NAME);

        gzFile file = gzopen(path, "wb");
        if (file) {
            // Target gzsetparams
            gzsetparams(file, data[1], data[2]);

            // Target gzputc and gzputs
            gzputc(file, 'a');
            gzputs(file, "fuzz string\n");

            gzwrite(file, data, size);

            // Target gzflush
            gzflush(file, Z_SYNC_FLUSH);
            gzclose(file);

            file = gzopen(path, "rb");
            if (file) {
                unsigned char read_buffer[1024];
                
                // Target gzgets
                gzgets(file, (char*)read_buffer, sizeof(read_buffer));

                // Target gzungetc
                gzungetc('b', file);

                int bytes_read;
                while ((bytes_read = gzread(file, read_buffer, sizeof(read_buffer))) > 0) {
                    // Discard data
                }

                // Target gzeof, gzerror, gzclearerr
                gzeof(file);
                int err_num = 0;
                gzerror(file, &err_num);
                gzclearerr(file);

                gzclose(file);
            }
        }
        unlink(path);
    } else {
        /*
         * ANALYSIS: The function-level coverage report showed that deflateSetDictionary,
         *           inflateSetDictionary, adler32_combine, and crc32_combine have low or 0% coverage.
         * IMPLEMENTATION: This block is added to specifically target dictionary-based
         *                 compression and decompression. It splits the input to create a
         *                 dictionary and data, then uses the deflate/inflate APIs with
         *                 dictionaries. It also calls adler32_combine and crc32_combine.
         */
        size_t dict_size = size / 4;
        if (dict_size > 0 && size > dict_size) {
            const uint8_t *dict_data = data;
            const uint8_t *plain_data = data + dict_size;
            size_t plain_size = size - dict_size;

            uLongf compressed_size = compressBound(plain_size);
            unsigned char *compressed_data = (unsigned char *)malloc(compressed_size);
            if (!compressed_data) {
                return 0;
            }

            // Deflate with dictionary
            z_stream def_strm;
            memset(&def_strm, 0, sizeof(def_strm));
            if (deflateInit(&def_strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
                deflateSetDictionary(&def_strm, dict_data, dict_size);
                def_strm.avail_in = plain_size;
                def_strm.next_in = plain_data;
                def_strm.avail_out = compressed_size;
                def_strm.next_out = compressed_data;
                deflate(&def_strm, Z_FINISH);
                deflateEnd(&def_strm);

                // Inflate with dictionary
                z_stream inf_strm;
                memset(&inf_strm, 0, sizeof(inf_strm));
                if (inflateInit(&inf_strm) == Z_OK) {
                    unsigned char out_buffer[CHUNK_SIZE];
                    inf_strm.avail_in = def_strm.total_out;
                    inf_strm.next_in = compressed_data;
                    inf_strm.avail_out = CHUNK_SIZE;
                    inf_strm.next_out = out_buffer;
                    int ret = inflate(&inf_strm, Z_NO_FLUSH);
                    if (ret == Z_NEED_DICT) {
                        inflateSetDictionary(&inf_strm, dict_data, dict_size);
                        inflate(&inf_strm, Z_FINISH);
                    }
                    inflateEnd(&inf_strm);
                }
            }
            free(compressed_data);
        }
        
        // Target adler32_combine and crc32_combine
        if (size >= 8) {
            uLong adler1 = adler32(0L, Z_NULL, 0);
            uLong adler2 = adler32(adler1, data, size/2);
            adler32_combine(adler1, adler2, size - (size/2));

            uLong crc1 = crc32(0L, Z_NULL, 0);
            uLong crc2 = crc32(crc1, data, size/2);
            crc32_combine(crc1, crc2, size - (size/2));
        }
    }

    return 0;
}