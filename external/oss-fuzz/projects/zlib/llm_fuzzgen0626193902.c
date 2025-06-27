#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h> // For fabs if needed, though not directly used in the fuzzer logic

// Include necessary zlib headers with project-relative paths
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h" // For gz_statep if needed, though we will use public APIs
#include "/src/zlib/zconf.h" // Required for MAX_WBITS and other configuration macros

// Define a maximum size for compressed and uncompressed buffers to prevent excessive memory usage.
#define MAX_BUF_SIZE 4096

// Custom memory allocation functions for zlib (optional, but good practice for fuzzing)
static voidpf zlib_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    // Prevent excessive allocations
    // Check for overflow before multiplication
    size_t total_size;
    if (__builtin_mul_overflow(items, size, &total_size)) return Z_NULL;

    if (total_size > MAX_BUF_SIZE) return Z_NULL;
    return calloc(items, size);
}

static void zlib_free(voidpf opaque, voidpf address) {
    (void)opaque;
    free(address);
}

// Entry point for the fuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure we have at least some data to work with
    if (Size < 10) {
        return 0;
    }

    // Use a portion of the input for different API calls
    size_t offset = 0;

    // --- Fuzzing gz* functions (requires file operations) ---
    // Create a temporary file
    char filename[] = "/tmp/fuzz-zlib-XXXXXX";
    int fd = mkstemp(filename);
    if (fd < 0) {
        // mkstemp failed, cannot proceed with gz* tests
        return 0;
    }

    // Open the temporary file as a gzFile for writing
    gzFile gz_file_write = gzdopen(fd, "wb");
    if (gz_file_write) {
        // Write some data to the gzFile
        size_t write_size = Size / 3;
        if (offset + write_size > Size) write_size = Size - offset;
        if (write_size > 0) {
            // gzwrite expects unsigned int size
            gzwrite(gz_file_write, Data + offset, (unsigned int)write_size);
            offset += write_size;
        }

        // Fuzz gzflush
        gzflush(gz_file_write, Z_SYNC_FLUSH); // Test Z_SYNC_FLUSH
        gzflush(gz_file_write, Z_FULL_FLUSH); // Test Z_FULL_FLUSH

        // Close the write file
        gzclose_w(gz_file_write);
    } else {
        // If gzdopen failed, close the file descriptor obtained from mkstemp
        close(fd);
    }

    // Reopen the temporary file as a gzFile for reading
    // Need to close and reopen the file descriptor for reading
    // The previous gzdopen/gzclose_w already closed the fd passed to gzdopen.
    fd = open(filename, O_RDONLY);
     if (fd >= 0) {
        gzFile gz_file_read = gzdopen(fd, "rb");
        if (gz_file_read) {
            // Fuzz gzfread
            char read_buf[MAX_BUF_SIZE];
            size_t read_size = Size / 3;
            if (offset + read_size > Size) read_size = Size - offset;
            if (read_size > 0) {
                 // gzfread expects size_t for size and nmemb
                 gzfread(read_buf, 1, read_size, gz_file_read);
                 offset += read_size;
            }

            // Fuzz gzseek and gztell
            gzseek(gz_file_read, 0, SEEK_SET);
            gztell(gz_file_read);
            gzseek64(gz_file_read, 0, SEEK_SET);
            gztell64(gz_file_read);

            // Fuzz gzeof, gzerror, gzclearerr
            gzeof(gz_file_read);
            int err;
            const char* err_msg = gzerror(gz_file_read, &err);
            gzclearerr(gz_file_read);

            // Close the read file
            gzclose_r(gz_file_read);
        } else {
             // If gzdopen failed, close the file descriptor obtained from open
             close(fd);
        }
    }

    // Clean up the temporary file
    unlink(filename);

    // --- Fuzzing inflate dictionary and sync functions ---
    z_stream strm;
    strm.zalloc = zlib_alloc;
    strm.zfree = zlib_free;
    strm.opaque = Z_NULL;
    strm.avail_in = (uInt)(Size - offset);
    strm.next_in = (Bytef *)Data + offset;

    // Initialize inflate stream
    // Use inflateInit2 to specify window bits. MAX_WBITS is the default.
    // MAX_WBITS is defined in zconf.h
    int ret = inflateInit2(&strm, MAX_WBITS);
    if (ret == Z_OK) {
        // Fuzz inflateSetDictionary
        size_t dict_size = (Size - offset) / 2;
        if (offset + dict_size <= Size) {
             // inflateSetDictionary expects uInt size
             inflateSetDictionary(&strm, (const Bytef *)Data + offset, (uInt)dict_size);
             offset += dict_size;
        }

        // Fuzz inflateGetDictionary
        Bytef dictionary[MAX_BUF_SIZE];
        uInt dict_len = 0;
        // inflateGetDictionary expects uInt* for dict_len
        inflateGetDictionary(&strm, dictionary, &dict_len);

        // Fuzz inflateSyncPoint
        inflateSyncPoint(&strm);

        // Fuzz inflateReset
        inflateReset(&strm);

        // Fuzz inflateReset2
        inflateReset2(&strm, MAX_WBITS);

        // Clean up inflate stream
        inflateEnd(&strm);
    }


    // --- Fuzzing zlibCompileFlags ---
    zlibCompileFlags();

    return 0;
}