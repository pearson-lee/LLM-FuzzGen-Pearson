// New comprehensive fuzz target for zlib.
// This fuzzer aims to maximize code coverage by exercising diverse API functions
// with low coverage, including deflate, inflate, gzwrite, gzread, and crc32_z.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Include necessary zlib headers with project-relative paths
// Only include zlib.h, as other headers like gzguts.h, deflate.h, and inflate.h
// are internal and should not be included directly by external code.
// Including internal headers caused build errors due to conflicting names
// and undefined types/macros.
#include "/src/zlib/zlib.h"

// Define a helper to consume bytes from the fuzzer input
// This is a manual implementation as FuzzedDataProvider is not available in C
typedef struct {
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} FuzzerData;

// Initialize the FuzzerData struct
void InitFuzzerData(FuzzerData *fd, const uint8_t *Data, size_t Size) {
    fd->Data = Data;
    fd->Size = Size;
    fd->Offset = 0;
}

// Consume a specified number of bytes from the fuzzer input
// Returns a pointer to the consumed data. The caller must check the actual
// number of bytes available if a fixed size is expected. This function
// consumes up to num_bytes or the remaining size, whichever is smaller.
const uint8_t* ConsumeBytes(FuzzerData *fd, size_t num_bytes) {
    if (fd->Offset + num_bytes > fd->Size) {
        num_bytes = fd->Size - fd->Offset; // Consume remaining bytes
    }
    const uint8_t *result = fd->Data + fd->Offset;
    fd->Offset += num_bytes;
    return result;
}

// Consume a single byte as a uint8_t
uint8_t ConsumeUint8(FuzzerData *fd) {
    if (fd->Offset >= fd->Size) {
        return 0; // Return a default value if out of data
    }
    return fd->Data[fd->Offset++];
}

// Consume a uint32_t (little-endian) safely.
// Returns 0 if not enough bytes are available for a full uint32_t.
uint32_t ConsumeUint32(FuzzerData *fd) {
    uint32_t value = 0;
    size_t bytes_needed = sizeof(uint32_t);
    if (fd->Offset + bytes_needed <= fd->Size) {
        const uint8_t *bytes = fd->Data + fd->Offset;
        memcpy(&value, bytes, bytes_needed);
        fd->Offset += bytes_needed;
    } else {
        // Not enough data for a full uint32_t.
        // Consume remaining bytes to ensure offset advances.
        fd->Offset = fd->Size;
        // Value remains 0.
    }
    return value;
}

// Consume a size_t (platform dependent size) safely.
// Returns 0 if not enough bytes are available for a full size_t.
size_t ConsumeSizeT(FuzzerData *fd) {
    size_t value = 0;
    size_t bytes_needed = sizeof(size_t);
    if (fd->Offset + bytes_needed <= fd->Size) {
        const uint8_t *bytes = fd->Data + fd->Offset;
        memcpy(&value, bytes, bytes_needed);
        fd->Offset += bytes_needed;
    } else {
        // Not enough data for a full size_t.
        // Consume remaining bytes to ensure offset advances.
        fd->Offset = fd->Size;
        // Value remains 0.
    }
    return value;
}


// Main fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzerData fd;
    InitFuzzerData(&fd, Data, Size);

    // Consume some bytes to determine which API(s) to call and their parameters
    // Need at least 1 byte for api_selector.
    if (Size < 1) {
        return 0;
    }

    uint8_t api_selector = ConsumeUint8(&fd);

    // Allocate buffers for compression/decompression
    size_t input_buf_size = Size - fd.Offset; // Use remaining data as input
    const uint8_t *input_buf = ConsumeBytes(&fd, input_buf_size); // Consume remaining data
    size_t output_buf_size = input_buf_size * 2 + 100; // Generous output buffer
    uint8_t *output_buf = NULL;

    // Only allocate if size is positive to avoid issues with malloc(0)
    if (output_buf_size > 0) {
        output_buf = (uint8_t *)malloc(output_buf_size);
        if (!output_buf) {
            // Allocation failed
            return 0;
        }
    }


    // --- Exercise selected APIs based on api_selector ---

    // API 1: deflate and inflate
    if (api_selector & 0x01) {
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;

        // Consume parameters for deflateInit2_
        // Ensure enough bytes are available before consuming parameters
        if (fd.Size - fd.Offset >= 5) { // Need 5 bytes for level, windowBits, memLevel, strategy, flush_mode
            int level = (ConsumeUint8(&fd) % 10) - 1; // Z_DEFAULT_COMPRESSION (-1) to 9
            int method = Z_DEFLATED; // Only Z_DEFLATED is supported
            int windowBits = (ConsumeUint8(&fd) % 8) + 8; // 8 to 15
            int memLevel = (ConsumeUint8(&fd) % 9) + 1; // 1 to 9
            int strategy = ConsumeUint8(&fd) % 5; // Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED

            // Initialize deflate stream
            if (deflateInit2_(&strm, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
                strm.avail_in = input_buf_size;
                strm.next_in = (Bytef *)input_buf;
                strm.avail_out = output_buf_size;
                strm.next_out = (Bytef *)output_buf;

                // Perform deflation
                // Use different flush modes to hit more branches
                int flush_mode = ConsumeUint8(&fd) % 4; // Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH
                deflate(&strm, flush_mode);

                // Clean up deflate stream
                deflateEnd(&strm);

                // Now attempt inflation on the compressed data
                z_stream strm_inf;
                strm_inf.zalloc = Z_NULL;
                strm_inf.zfree = Z_NULL;
                strm_inf.opaque = Z_NULL;

                // Consume parameters for inflateInit2_
                if (fd.Size - fd.Offset >= 1) { // Need 1 byte for windowBits_inf
                    int windowBits_inf = (ConsumeUint8(&fd) % 8) + 8; // 8 to 15

                    // Initialize inflate stream
                    // Use the actual amount of data written by deflate
                    size_t compressed_size = output_buf_size - strm.avail_out;

                    if (inflateInit2_(&strm_inf, windowBits_inf, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
                        strm_inf.avail_in = compressed_size;
                        strm_inf.next_in = (Bytef *)output_buf;
                        strm_inf.avail_out = input_buf_size; // Decompress back to original size buffer
                        strm_inf.next_out = (Bytef *)output_buf; // Reuse output_buf for decompressed data

                        // Perform inflation
                        // Use Z_FINISH if we expect a complete stream, otherwise Z_NO_FLUSH
                        int inflate_flush_mode = (compressed_size > 0) ? Z_FINISH : Z_NO_FLUSH;
                        inflate(&strm_inf, inflate_flush_mode);

                        // Clean up inflate stream
                        inflateEnd(&strm_inf);
                    }
                }
            }
        }
    }

    // API 2: gzwrite and gzread
    if (api_selector & 0x02) {
        // Use a temporary file for gzread/gzwrite
        FILE *tmp = tmpfile();
        if (tmp) {
            // Get the file descriptor
            int fd_tmp = fileno(tmp);
            if (fd_tmp != -1) {
                // Open as a gzFile
                gzFile gz = gzdopen(fd_tmp, "wb+"); // wb+ for writing and reading
                if (gz) {
                    // Consume data for writing
                    size_t write_size = ConsumeSizeT(&fd) % (input_buf_size + 1);
                    const uint8_t *write_data = ConsumeBytes(&fd, write_size);

                    // Exercise gzwrite
                    if (write_size > 0 && write_data != NULL) {
                         gzwrite(gz, write_data, write_size);
                    }


                    // Exercise gzflush with different modes
                    if (fd.Size - fd.Offset >= 1) { // Need 1 byte for flush_mode_gz
                        int flush_mode_gz = ConsumeUint8(&fd) % 3; // Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH
                        gzflush(gz, flush_mode_gz);
                    }


                    // Rewind the file for reading
                    gzseek(gz, 0, SEEK_SET);

                    // Exercise gzread
                    size_t read_buf_size = ConsumeSizeT(&fd) % (output_buf_size + 1);
                    uint8_t *read_buf = NULL;
                    if (read_buf_size > 0) {
                        read_buf = (uint8_t *)malloc(read_buf_size);
                        if (read_buf) {
                            gzread(gz, read_buf, read_buf_size);
                            free(read_buf);
                        }
                    }


                    // Exercise gzgets
                    char gets_buf[256]; // Small buffer for gzgets
                    gzgets(gz, gets_buf, sizeof(gets_buf));

                    // Exercise gzgetc
                    gzgetc(gz);

                    // Exercise gzungetc
                    if (fd.Size - fd.Offset >= 1) { // Need 1 byte for ungetc_char
                        int ungetc_char = ConsumeUint8(&fd);
                        gzungetc(ungetc_char, gz);
                    }


                    // Clean up gzFile
                    gzclose(gz);
                }
            }
            // tmpfile is automatically closed and deleted when the FILE* is closed
            fclose(tmp);
        }
    }

    // API 3: crc32_z
    if (api_selector & 0x04) {
        // Consume initial CRC value and data for CRC calculation
        // Ensure enough bytes are available before consuming parameters
        if (fd.Size - fd.Offset >= sizeof(uLong)) { // Need at least sizeof(uLong) for initial_crc
            uLong initial_crc = ConsumeUint32(&fd);

            size_t crc_data_size = ConsumeSizeT(&fd) % (input_buf_size + 1);
            const uint8_t *crc_data = ConsumeBytes(&fd, crc_data_size);

            // Exercise crc32_z
            if (crc_data_size > 0 && crc_data != NULL) {
                 crc32_z(initial_crc, crc_data, crc_data_size);
            } else {
                 crc32_z(initial_crc, Z_NULL, 0); // Handle empty data case
            }
        }
    }

    // API 4: zlibCompileFlags (simple call to cover it)
    if (api_selector & 0x08) {
        zlibCompileFlags();
    }

    // API 5: zcalloc and zcfree (exercise custom alloc/free)
    if (api_selector & 0x10) {
        // Consume size for allocation
        // Ensure enough bytes are available before consuming parameters
        if (fd.Size - fd.Offset >= sizeof(uInt) * 2) { // Need 2 * sizeof(uInt) for num_items and alloc_size
            uInt num_items = ConsumeUint32(&fd);
            uInt alloc_size = ConsumeUint32(&fd);

            // Exercise zcalloc
            // zcalloc takes number of items and size of each item
            voidpf allocated_mem = zcalloc(Z_NULL, num_items, alloc_size);

            // Exercise zcfree if allocation was successful
            if (allocated_mem) {
                zcfree(Z_NULL, allocated_mem);
            }
        }
    }


    // Free allocated output buffer if it was allocated
    if (output_buf) {
        free(output_buf);
    }


    return 0;
}