#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc/free
#include <string.h> // For memcpy

// Include zlib headers
// These headers provide the necessary function declarations and types for zlib APIs.
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/crc32.h"

// FuzzerInput structure to manage consumption of fuzzer data.
// This mimics the functionality of FuzzedDataProvider in C++ for C fuzzers.
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzerInput;

// Initializes the FuzzerInput structure with the provided fuzzer data.
void FuzzerInput_Init(FuzzerInput *input, const uint8_t *data, size_t size) {
    input->data = data;
    input->size = size;
    input->offset = 0;
}

// Consumes a single byte from the fuzzer input.
// Returns 0 if no more data is available.
uint8_t FuzzerInput_ConsumeUint8(FuzzerInput *input) {
    if (input->offset < input->size) {
        return input->data[input->offset++];
    }
    return 0;
}

// Consumes a size_t value from the fuzzer input, capped by max_val.
// This helps in generating reasonable sizes for allocations and buffer lengths.
size_t FuzzerInput_ConsumeSizeT(FuzzerInput *input, size_t max_val) {
    size_t val = 0;
    for (int i = 0; i < sizeof(size_t) && input->offset < input->size; ++i) {
        val = (val << 8) | input->data[input->offset++];
    }
    return val % (max_val + 1);
}

// Consumes a block of bytes from the fuzzer input.
// Returns a pointer to the consumed bytes or NULL if not enough data.
const uint8_t* FuzzerInput_ConsumeBytes(FuzzerInput *input, size_t num_bytes) {
    if (input->offset + num_bytes <= input->size) {
        const uint8_t *ptr = input->data + input->offset;
        input->offset += num_bytes;
        return ptr;
    }
    return NULL;
}

// The main fuzzer entry point. LLVMFuzzerTestOneInput is called repeatedly
// with different fuzzer-generated inputs.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzerInput fuzzer_input;
    FuzzerInput_Init(&fuzzer_input, Data, Size);

    // 1. Fuzz zlibCompileFlags
    // This function returns compile-time flags and does not take any input.
    // Calling it directly exercises its internal logic, which depends on
    // the sizes of various zlib types (uInt, uLong, voidpf, z_off_t).
    // The branches within this function are determined at compile time,
    // so simply calling it is sufficient for coverage.
    (void)zlibCompileFlags();

    // 2. Fuzz get_crc_table
    // This function initializes static CRC tables. Calling it will trigger
    // the initialization process, which in turn calls internal functions
    // like 'byte_swap' and 'crc_word_big' (if DYNAMIC_CRC_TABLE and W are
    // defined during compilation). This helps in covering those low-coverage
    // internal functions.
    (void)get_crc_table();

    // 3. Fuzz compress2
    // This function compresses a block of data. We generate input and output
    // buffer sizes, compression level, and strategy from the fuzzer input.
    size_t input_len = FuzzerInput_ConsumeSizeT(&fuzzer_input, 1024 * 10); // Max 10KB input data
    const uint8_t *input_buf = FuzzerInput_ConsumeBytes(&fuzzer_input, input_len);

    if (input_buf != NULL) {
        // Calculate a safe upper bound for the compressed output buffer size.
        // zlib's compressBound provides a good estimate.
        size_t output_len_bound = compressBound((uLong)input_len);
        // Fuzz the actual output buffer size, ensuring it's within a reasonable range.
        size_t output_len = FuzzerInput_ConsumeSizeT(&fuzzer_input, output_len_bound);

        Bytef *compressed_buf = (Bytef *)malloc(output_len);
        // Ensure memory allocation was successful to prevent crashes.
        if (compressed_buf != NULL) {
            uLongf dest_len = (uLongf)output_len;
            // Fuzz compression level (0-9).
            int level = (int)FuzzerInput_ConsumeUint8(&fuzzer_input) % 10;

            // Call compress2 with fuzzed parameters.
            (void)compress2(compressed_buf, &dest_len, (const Bytef *)input_buf, (uLong)input_len, level);

            // 4. Fuzz uncompress2
            // This function decompresses a block of data. We use the output of compress2
            // as input for uncompress2 to test the decompression logic.
            // The uncompressed output buffer size is also fuzzed, with a generous upper bound.
            size_t uncomp_output_len = FuzzerInput_ConsumeSizeT(&fuzzer_input, input_len * 2); // Allow for expansion

            Bytef *uncompressed_buf = (Bytef *)malloc(uncomp_output_len);
            // Ensure memory allocation was successful.
            if (uncompressed_buf != NULL) {
                uLongf uncomp_dest_len = (uLongf)uncomp_output_len;
                // Call uncompress2. The input length for uncompress2 is the actual
                // compressed length returned by compress2 (dest_len).
                (void)uncompress2(uncompressed_buf, &uncomp_dest_len, compressed_buf, &dest_len);

                // Free the uncompressed buffer to prevent memory leaks.
                free(uncompressed_buf);
            }

            // Free the compressed buffer to prevent memory leaks.
            free(compressed_buf);
        }
    }

    // 5. Fuzz deflateInit2_ and inflateInit2_ with various parameters
    // This targets functions like deflateInit2_, inflateInit2_, deflateSetDictionary,
    // inflateSetDictionary, deflateEnd, inflateEnd which have lower coverage.
    z_stream strm_deflate;
    z_stream strm_inflate;
    int ret;

    // Initialize z_stream structures
    strm_deflate.zalloc = Z_NULL;
    strm_deflate.zfree = Z_NULL;
    strm_deflate.opaque = Z_NULL;

    strm_inflate.zalloc = Z_NULL;
    strm_inflate.zfree = Z_NULL;
    strm_inflate.opaque = Z_NULL;

    // Fuzz parameters for deflateInit2_
    int level = (int)FuzzerInput_ConsumeUint8(&fuzzer_input) % 10; // 0-9
    int windowBits_val = (int)FuzzerInput_ConsumeUint8(&fuzzer_input) % 8 + 8; // 8-15
    // Randomly choose raw deflate (negative windowBits) to increase branch coverage.
    if (FuzzerInput_ConsumeUint8(&fuzzer_input) % 2 == 0) {
        windowBits_val = -windowBits_val; // -8 to -15
    }
    int memLevel = (int)FuzzerInput_ConsumeUint8(&fuzzer_input) % 9 + 1; // 1-9
    int strategy = (int)FuzzerInput_ConsumeUint8(&fuzzer_input) % 5; // Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED

    // Call deflateInit2_ to improve coverage for deflateInit2_ and related initialization paths.
    ret = deflateInit2_(&strm_deflate, level, Z_DEFLATED, windowBits_val, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));
    if (ret == Z_OK) {
        // Fuzz deflateSetDictionary to improve coverage for this function.
        size_t dict_len = FuzzerInput_ConsumeSizeT(&fuzzer_input, 1024); // Max 1KB dictionary
        const uint8_t *dict_buf = FuzzerInput_ConsumeBytes(&fuzzer_input, dict_len);
        if (dict_buf != NULL) {
            (void)deflateSetDictionary(&strm_deflate, (const Bytef *)dict_buf, (uInt)dict_len);
        }

        // Perform a small deflate operation to exercise the stream after initialization and dictionary setting.
        Bytef out_buf[128];
        uLongf out_len = sizeof(out_buf);
        strm_deflate.avail_in = (uInt)input_len > 0 ? 1 : 0; // Consume 1 byte if available
        strm_deflate.next_in = (Bytef *)input_buf;
        strm_deflate.avail_out = sizeof(out_buf);
        strm_deflate.next_out = out_buf;
        (void)deflate(&strm_deflate, Z_FINISH);

        // Call deflateEnd to ensure proper cleanup and improve coverage for deflateEnd.
        (void)deflateEnd(&strm_deflate);
    }

    // Fuzz parameters for inflateInit2_
    windowBits_val = (int)FuzzerInput_ConsumeUint8(&fuzzer_input) % 8 + 8; // 8-15
    // Randomly choose raw inflate (negative windowBits) to increase branch coverage.
    if (FuzzerInput_ConsumeUint8(&fuzzer_input) % 2 == 0) {
        windowBits_val = -windowBits_val; // -8 to -15
    }

    // Call inflateInit2_ to improve coverage for inflateInit2_ and related initialization paths.
    ret = inflateInit2_(&strm_inflate, windowBits_val, ZLIB_VERSION, sizeof(z_stream));
    if (ret == Z_OK) {
        // Fuzz inflateSetDictionary to improve coverage for this function.
        size_t dict_len = FuzzerInput_ConsumeSizeT(&fuzzer_input, 1024); // Max 1KB dictionary
        const uint8_t *dict_buf = FuzzerInput_ConsumeBytes(&fuzzer_input, dict_len);
        if (dict_buf != NULL) {
            (void)inflateSetDictionary(&strm_inflate, (const Bytef *)dict_buf, (uInt)dict_len);
        }

        // Perform a small inflate operation to exercise the stream after initialization and dictionary setting.
        Bytef out_buf[128];
        uLongf out_len = sizeof(out_buf);
        strm_inflate.avail_in = (uInt)input_len > 0 ? 1 : 0; // Consume 1 byte if available
        strm_inflate.next_in = (Bytef *)input_buf;
        strm_inflate.avail_out = sizeof(out_buf);
        strm_inflate.next_out = out_buf;
        (void)inflate(&strm_inflate, Z_FINISH);

        // Call inflateEnd to ensure proper cleanup and improve coverage for inflateEnd.
        (void)inflateEnd(&strm_inflate);
    }

    return 0;
}