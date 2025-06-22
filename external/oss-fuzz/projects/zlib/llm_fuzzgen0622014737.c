// Your generated fuzz target code here
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h> // For open, close, O_RDWR, O_CREAT
#include <unistd.h> // For close, unlink
#include <sys/stat.h> // For S_IRUSR, S_IWUSR

// Include zlib headers
#include "/src/zlib/zlib.h"

// Define a maximum size for the temporary file to prevent excessive resource usage
#define MAX_FILE_SIZE 1024 * 1024 // 1 MB

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure we have enough data for basic decisions
    if (Size < 2) {
        return 0;
    }

    // Create a temporary file
    char filename[] = "/tmp/fuzz-zlib-XXXXXX";
    // mkstemp creates and opens a unique temporary file.
    // The file is created with read/write permissions for the owner.
    int fd = mkstemp(filename);
    if (fd == -1) {
        // Failed to create temporary file, return.
        // This is a rare system error, so no need to fuzz further.
        return 0;
    }

    // Write some data from the fuzzer input to the temporary file.
    // This data will be used by gzread or gzwrite.
    // Limiting the written size to prevent excessively large files.
    size_t bytes_to_write = Size - 2; // Reserve first 2 bytes for choices
    if (bytes_to_write > MAX_FILE_SIZE) {
        bytes_to_write = MAX_FILE_SIZE;
    }
    if (bytes_to_write > 0) {
        write(fd, Data + 2, bytes_to_write);
        // Rewind to the beginning for reading operations later.
        lseek(fd, 0, SEEK_SET);
    }

    gzFile file = NULL;
    // Use the first byte of fuzzer input to decide the mode (read/write).
    int mode_choice = Data[0] % 2; // 0 for read ("rb"), 1 for write ("wb")
    // Use the second byte of fuzzer input to decide whether to use a valid or invalid file descriptor.
    int fd_choice = Data[1] % 2;   // 0 for valid fd, 1 for invalid fd (-1)

    // Test gzdopen: Opens a gzip file from an existing file descriptor.
    if (fd_choice == 0) { // Use the valid file descriptor created by mkstemp
        if (mode_choice == 0) { // Open in read mode
            file = gzdopen(fd, "rb");
        } else { // Open in write mode
            file = gzdopen(fd, "wb");
        }
    } else { // Use an invalid file descriptor (-1) to test error handling
        if (mode_choice == 0) { // Open in read mode
            file = gzdopen(-1, "rb");
        } else { // Open in write mode
            file = gzdopen(-1, "wb");
        }
        // If gzdopen was called with -1, the original valid 'fd' from mkstemp
        // was not used by gzdopen and needs to be closed manually.
        close(fd);
        fd = -1; // Mark the original fd as closed to avoid double-closing.
    }

    // Perform operations only if gzdopen successfully returned a gzFile.
    if (file != NULL) {
        // Test gzgetc: Reads a single character from the gzip file.
        // Read a few characters to exercise gzgetc and its internal buffering.
        // Limit the number of reads to prevent excessive execution time for large inputs.
        for (size_t i = 0; i < Size / 4 && i < 100; ++i) {
            gzgetc(file);
        }

        // Test gzwrite: Writes data to the gzip file.
        // Only perform write operations if the file was opened in write mode.
        if (mode_choice == 1) {
            // Write a portion of the fuzzer input.
            gzwrite(file, Data, Size);
            // Also test writing with zero length to cover that specific branch in gzwrite.
            gzwrite(file, Data, 0);
        }

        // Test gzclose: Closes the gzip file, flushing any pending output.
        // This function handles resource cleanup (memory and file descriptor)
        // associated with the gzFile object.
        gzclose(file);
    } else {
        // If 'file' is NULL, it means gzdopen failed.
        // Ensure the original file descriptor 'fd' is closed if it hasn't been already
        // (e.g., if gzdopen was called with -1).
        if (fd != -1) {
            close(fd);
        }
    }

    // Clean up the temporary file from the filesystem.
    // This is safe even if 'fd' was -1, as 'filename' still holds the path.
    unlink(filename);

    return 0;
}