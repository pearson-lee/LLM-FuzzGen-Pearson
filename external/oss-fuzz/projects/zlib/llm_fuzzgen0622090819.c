// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>    // For open, close, mkstemp
#include <unistd.h>   // For close, unlink
#include <sys/stat.h> // For fchmod (though not strictly needed for this fuzzer)

// Include zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h" // Included for gz_statep, though we primarily use public APIs

// Helper structure to manage fuzzer input data
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} FuzzerData;

// Consumes a single byte from the fuzzer input
uint8_t ConsumeUint8(FuzzerData *fd) {
    if (fd->offset < fd->size) {
        return fd->data[fd->offset++];
    }
    return 0; // Return a default value if no more data
}

// Consumes an integer from the fuzzer input
int ConsumeInt(FuzzerData *fd) {
    if (fd->offset + sizeof(int) <= fd->size) {
        int val;
        memcpy(&val, fd->data + fd->offset, sizeof(int));
        fd->offset += sizeof(int);
        return val;
    }
    return 0; // Return a default value if no more data
}

// Consumes a long integer from the fuzzer input
long ConsumeLong(FuzzerData *fd) {
    if (fd->offset + sizeof(long) <= fd->size) {
        long val;
        memcpy(&val, fd->data + fd->offset, sizeof(long));
        fd->offset += sizeof(long);
        return val;
    }
    return 0; // Return a default value if no more data
}

// Generates a random integer within a specified range using fuzzer input
int GetRandInRange(FuzzerData *fd, int min, int max) {
    if (min > max) return min;
    if (fd->offset >= fd->size) return min; // Not enough data, return min

    // Use a byte from the fuzzer input to get a value between 0 and 255
    uint8_t rand_byte = ConsumeUint8(fd);
    return min + (rand_byte % (max - min + 1));
}

// The main fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzerData fd = {Data, Size, 0};

    // 1. Exercise zlibCompileFlags:
    // This function returns compile-time flags and is safe to call.
    zlibCompileFlags();

    // 2. Fuzz deflateInit2_:
    // Initializes a z_stream for compression with fuzzed parameters.
    z_stream strm_deflate;
    strm_deflate.zalloc = Z_NULL; // Use default allocation functions
    strm_deflate.zfree = Z_NULL;   // Use default free functions
    strm_deflate.opaque = Z_NULL;  // Opaque pointer for custom allocation

    // Generate fuzzed parameters for deflateInit2_
    int level = GetRandInRange(&fd, Z_NO_COMPRESSION, Z_BEST_COMPRESSION);
    int method = Z_DEFLATED; // Z_DEFLATED is the only supported method
    int windowBits = GetRandInRange(&fd, -15, 31); // Range for raw, zlib, and gzip streams
    // Adjust windowBits to valid ranges as per zlib documentation
    if (windowBits > 0 && windowBits < 8) windowBits = 8;
    if (windowBits < 0 && windowBits > -8) windowBits = -8;
    if (windowBits > 15 && windowBits < 24) windowBits = 15; // Cap at 15 for zlib/raw
    if (windowBits > 31) windowBits = 31; // Cap at 31 for gzip

    int memLevel = GetRandInRange(&fd, 1, 9); // Memory level (1-9)
    int strategy = GetRandInRange(&fd, Z_DEFAULT_STRATEGY, Z_FIXED); // Compression strategy

    // Ensure strategy is within valid Z_ constants, fallback if out of range
    if (strategy > Z_FIXED) strategy = Z_DEFAULT_STRATEGY;

    // Call deflateInit2_ and then deflateEnd to clean up resources.
    deflateInit2_(&strm_deflate, level, method, windowBits, memLevel, strategy, ZLIB_VERSION, (int)sizeof(z_stream));
    deflateEnd(&strm_deflate); // Crucial for memory safety: frees allocated resources

    // 3. Fuzz inflateReset:
    // Initializes a z_stream for decompression and then resets it.
    z_stream strm_inflate;
    strm_inflate.zalloc = Z_NULL; // Use default allocation functions
    strm_inflate.zfree = Z_NULL;   // Use default free functions
    strm_inflate.opaque = Z_NULL;  // Opaque pointer for custom allocation

    // Initialize inflate stream first, then reset, then end.
    inflateInit(&strm_inflate); // Initialize the stream
    inflateReset(&strm_inflate); // Reset the stream state
    inflateEnd(&strm_inflate);   // Crucial for memory safety: frees allocated resources

    // 4. Fuzz gzputc and gzseek:
    // These functions operate on gzipped files. We use temporary files for fuzzing.

    // Create a temporary file for write operations
    char temp_filename_write[] = "/tmp/fuzz_zlib_write_XXXXXX";
    int fd_temp_write = mkstemp(temp_filename_write); // Creates and opens a unique temp file
    if (fd_temp_write != -1) {
        // Open the file descriptor as a gzFile in write binary mode
        gzFile gz_file_write = gzdopen(fd_temp_write, "wb");
        if (gz_file_write != Z_NULL) {
            // Fuzz gzputc: write a fuzzed character
            if (fd.offset < fd.size) { // Ensure there's data to consume
                int char_to_write = ConsumeUint8(&fd);
                gzputc(gz_file_write, char_to_write);
            }

            // Fuzz gzseek: seek to a fuzzed offset with a fuzzed whence
            // Limit offset to a small range to avoid timeouts
            long offset = GetRandInRange(&fd, 0, 10);
            int whence = GetRandInRange(&fd, SEEK_SET, SEEK_END); // SEEK_SET, SEEK_CUR, SEEK_END
            gzseek(gz_file_write, offset, whence); // This call also sets state->seek = 1 for gzputc

            // Attempt to fill the internal buffer to hit specific gzputc branches
            // by writing a larger chunk of fuzzed data.
            // Ensure at least one byte is written if data_to_write_len is fuzzed.
            size_t data_to_write_len = GetRandInRange(&fd, 1, 16); // Write 1 to 16 bytes
            for (size_t i = 0; i < data_to_write_len; ++i) {
                gzputc(gz_file_write, ConsumeUint8(&fd));
            }

            gzclose(gz_file_write); // Crucial for memory safety: closes the gzFile and underlying fd
        } else {
            close(fd_temp_write); // Close the file descriptor if gzdopen failed
        }
        unlink(temp_filename_write); // Clean up the temporary file from the filesystem
    }

    // Test gzputc with a file opened in read mode to hit `state->mode != GZ_WRITE` branch
    char temp_filename_read[] = "/tmp/fuzz_zlib_read_XXXXXX";
    int fd_temp_read = mkstemp(temp_filename_read);
    if (fd_temp_read != -1) {
        close(fd_temp_read); // Close the write descriptor from mkstemp
        // Open the same temporary file in read binary mode
        gzFile gz_file_read = gzopen(temp_filename_read, "rb");
        if (gz_file_read != Z_NULL) {
            // Calling gzputc on a read-mode file should trigger the error branch
            gzputc(gz_file_read, ConsumeUint8(&fd));
            gzclose(gz_file_read); // Crucial for memory safety
        }
        unlink(temp_filename_read); // Clean up the temporary file
    }

    // Attempt to trigger gzputc(NULL, ...) to hit the `file == NULL` branch
    if (fd.offset < fd.size && ConsumeUint8(&fd) % 2 == 0) { // Randomly call with NULL
        gzputc(Z_NULL, ConsumeUint8(&fd));
    }

    return 0;
}