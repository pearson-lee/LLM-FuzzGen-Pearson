#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

// All zlib functionality is available through this single header.
#include "/src/zlib/zlib.h"

// A helper structure to safely consume data from the fuzzer input buffer.
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzStream;

// Consumes a block of data of a given size from the fuzz stream.
// Returns a pointer to the data or NULL if the requested size is not available.
static const uint8_t* FuzzStream_Consume(FuzzStream* fs, size_t amount) {
    if (fs->offset + amount > fs->size) {
        return NULL;
    }
    const uint8_t* ptr = fs->data + fs->offset;
    fs->offset += amount;
    return ptr;
}

// Consumes a single byte from the fuzz stream.
// Returns 1 on success, 0 on failure.
static int FuzzStream_ConsumeByte(FuzzStream* fs, uint8_t* value) {
    const uint8_t* ptr = FuzzStream_Consume(fs, 1);
    if (!ptr) {
        return 0;
    }
    *value = *ptr;
    return 1;
}

// The main fuzzing entry point.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzStream fs = {Data, Size, 0};
    uint8_t byte_val;
    const uint8_t* data_chunk;

    // Target 1: crc32_z
    // This function calculates the CRC32 checksum. We provide it with a chunk of
    // the fuzzer's input data. The length of the chunk is also derived from the input.
    size_t crc_data_len = 0;
    if (FuzzStream_ConsumeByte(&fs, &byte_val)) {
        crc_data_len = byte_val;
    }
    data_chunk = FuzzStream_Consume(&fs, crc_data_len);
    if (data_chunk) {
        crc32_z(0, data_chunk, crc_data_len);
    }

    // Target 2: deflateBound
    // This function provides an upper bound on the compressed size. Its output
    // depends on the stream's state, so we initialize a stream first.
    z_stream strm_deflate;
    strm_deflate.zalloc = Z_NULL;
    strm_deflate.zfree = Z_NULL;
    strm_deflate.opaque = Z_NULL;
    if (deflateInit_(&strm_deflate, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
        uLong sourceLen = 0;
        if (FuzzStream_ConsumeByte(&fs, &byte_val)) {
            sourceLen = byte_val;
        }
        deflateBound(&strm_deflate, sourceLen);
        // Memory cleanup for the stream.
        deflateEnd(&strm_deflate);
    }

    // Targets 3 & 4: gzsetparams and gzgetc
    // These functions operate on gzFile handles. We create a temporary file,
    // write to it using gzsetparams to vary compression, then read back with gzgetc.
    const char* tmp_filename = "/tmp/fuzz.gz";
    
    size_t write_len = 0;
    if (FuzzStream_ConsumeByte(&fs, &byte_val)) {
        write_len = byte_val;
    }
    data_chunk = FuzzStream_Consume(&fs, write_len);

    if (data_chunk) {
        gzFile gz_file_w = gzopen(tmp_filename, "wb");
        if (gz_file_w) {
            // Target 3: gzsetparams
            // Use fuzzer input to select compression level and strategy.
            int level = (Size % 11) - 1; // Range -1 to 9
            int strategy = Size % 5;     // Range 0 to 4
            gzsetparams(gz_file_w, level, strategy);
            
            gzwrite(gz_file_w, data_chunk, write_len);
            // Resource cleanup: gzclose flushes and closes the file handle.
            gzclose(gz_file_w);

            gzFile gz_file_r = gzopen(tmp_filename, "rb");
            if (gz_file_r) {
                // Target 4: gzgetc
                // Read a few bytes to exercise the function.
                for (int i = 0; i < 16; ++i) {
                    if (gzgetc(gz_file_r) == -1) break;
                }
                // Resource cleanup for the read handle.
                gzclose(gz_file_r);
            }
        }
    }
    // Ensure the temporary file is removed.
    remove(tmp_filename);

    // Target 5: inflateReset2
    // This function re-initializes an inflation stream with different parameters.
    z_stream strm_inflate;
    strm_inflate.zalloc = Z_NULL;
    strm_inflate.zfree = Z_NULL;
    strm_inflate.opaque = Z_NULL;
    strm_inflate.avail_in = 0;
    strm_inflate.next_in = Z_NULL;

    if (inflateInit_(&strm_inflate, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
        int windowBits = 15;
        if (FuzzStream_ConsumeByte(&fs, &byte_val)) {
            // Generate windowBits from 8 to 15, with a 50% chance of being negative.
            windowBits = 8 + (byte_val % 8);
            if (byte_val > 127) {
                windowBits = -windowBits;
            }
        }
        inflateReset2(&strm_inflate, windowBits);
        // Memory cleanup for the inflation stream.
        inflateEnd(&strm_inflate);
    }

    return 0;
}