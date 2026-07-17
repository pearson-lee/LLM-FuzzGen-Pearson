#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"

// Forward declaration for gz_intmax as it's not in a public header
unsigned ZLIB_INTERNAL gz_intmax(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int level = data[0] % 10; // 0-9
    if (size > 1) {
        level = data[1] % 12 - 2; // -2 to 9 (include invalid levels)
    }
    int windowBits = 8 + (data[0] % 8); // 8-15
    if (size > 2) {
        windowBits = data[2] % 20 - 2; // -2 to 17 (include invalid values)
    }
    int memLevel = 1 + (data[0] % 9); // 1-9
    if (size > 3) {
        memLevel = data[3] % 12 - 1; // -1 to 10 (include invalid values)
    }
    int strategy = data[0] % 5; // 0-4

    int ret = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (ret != Z_OK) {
        return 0;
    }

    size_t dictionary_size = 0;
    if (size > 4) {
        dictionary_size = (size - 4) / 2;
    }
    const uint8_t *dictionary_data = data + 4;

    if (dictionary_size > 0) {
        deflateSetDictionary(&strm, dictionary_data, dictionary_size);
    }

    size_t input_offset = 4 + dictionary_size;
    size_t input_size = size - input_offset;
    if (input_size == 0) {
        deflateEnd(&strm);
        return 0;
    }

    size_t comprLen = deflateBound(&strm, input_size);
    uint8_t *compr = (uint8_t *)malloc(comprLen);
    if (!compr) {
        deflateEnd(&strm);
        return 0;
    }

    strm.next_in = (Bytef *)(data + input_offset);
    strm.avail_in = input_size;
    strm.next_out = compr;
    strm.avail_out = comprLen;

    int flush = (data[0] % 4 == 0) ? Z_SYNC_FLUSH : (data[0] % 4 == 1) ? Z_FULL_FLUSH : Z_NO_FLUSH;
    deflate(&strm, flush);

    if (strm.avail_in > 0) {
        deflate(&strm, Z_FINISH);
    }
    
    uInt dict_len_out = 0;
    uint8_t *dict_out = NULL;
    // First, call to get the dictionary length.
    if (deflateGetDictionary(&strm, NULL, &dict_len_out) == Z_OK && dict_len_out > 0) {
        dict_out = (uint8_t *)malloc(dict_len_out);
        if (dict_out) {
            // Second, call to get the actual dictionary.
            deflateGetDictionary(&strm, dict_out, &dict_len_out);
        }
    }

    deflateEnd(&strm);
    
    free(compr);
    if (dict_out) {
        free(dict_out);
    }
    
    (void)gz_intmax();

    return 0;
}