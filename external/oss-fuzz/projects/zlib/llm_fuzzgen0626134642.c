#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Include zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h"

// Define a maximum buffer size to avoid excessive allocations
#define MAX_BUFFER_SIZE 4096

// Entry point for the libFuzzer.
// This function is called with a new input data buffer and its size.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Need at least 2 bytes: 1 for open mode, 1 for the first operation type.
    if (Size < 2) {
        return 0;
    }

    // Create a unique temporary file name.
    char filename[] = "/tmp/fuzz-zlib-XXXXXX";
    int fd = mkstemp(filename);
    if (fd < 0) {
        // Failed to create temporary file, return without crashing.
        return 0;
    }
    // Close the file descriptor immediately, gzopen64 works with the path.
    close(fd);

    gzFile file = NULL;
    uint8_t *read_buffer = NULL;
    char *gets_buffer = NULL;

    // Use the first byte of the input data to determine the file open mode.
    // Simple mapping to cover common modes.
    const char *mode = "wb"; // Default to write binary
    if (Data[0] == 1) {
        mode = "rb"; // Read binary
    } else if (Data[0] == 2) {
        mode = "a+b"; // Append and read binary
    }
    // Other values will use the default "wb".

    // Open the temporary file using gzopen64.
    file = gzopen64(filename, mode);

    // Consume the byte used for the mode.
    size_t consumed_size = 1;

    // If the file was opened successfully, proceed with operations.
    if (file) {
        // Allocate buffers for read and gets operations.
        read_buffer = (uint8_t *)malloc(MAX_BUFFER_SIZE);
        gets_buffer = (char *)malloc(MAX_BUFFER_SIZE);

        // Check if buffer allocations were successful.
        if (!read_buffer || !gets_buffer) {
            // Allocation failed, clean up any allocated buffers and the gzFile.
            if (read_buffer) free(read_buffer);
            if (gets_buffer) free(gets_buffer);
            gzclose(file);
            // Remove the temporary file.
            unlink(filename);
            return 0; // Indicate failure to libFuzzer (optional, but good practice)
        }

        // Process the rest of the input data as a sequence of operations.
        // Each byte (after the first) can potentially trigger an operation.
        while (consumed_size < Size) {
            uint8_t operation = Data[consumed_size];
            consumed_size++;

            // Use modulo to select one of the target operations based on the byte value.
            switch (operation % 5) {
                case 0: { // Target API: gzwrite
                    // Need enough data for the size parameter (unsigned int).
                    if (consumed_size + sizeof(unsigned int) <= Size) {
                        unsigned int write_size = *(unsigned int *)(Data + consumed_size);
                        consumed_size += sizeof(unsigned int);
                        // Limit the write size to the remaining input data to avoid reading out of bounds.
                        if (consumed_size + write_size > Size) {
                            write_size = Size - consumed_size;
                        }
                        // Perform the write operation if there's data to write.
                        if (write_size > 0) {
                            gzwrite(file, Data + consumed_size, write_size);
                            consumed_size += write_size; // Consume the data that was written.
                        }
                    } else {
                         // Not enough data for the write size parameter, stop processing operations.
                         consumed_size = Size;
                    }
                    break;
                }
                case 1: { // Target API: gzread
                    // Need enough data for the size parameter (unsigned int).
                    if (consumed_size + sizeof(unsigned int) <= Size) {
                        unsigned int read_size = *(unsigned int *)(Data + consumed_size);
                        consumed_size += sizeof(unsigned int);
                        // Limit the read size to the allocated buffer size.
                        if (read_size > MAX_BUFFER_SIZE) {
                            read_size = MAX_BUFFER_SIZE;
                        }
                        // Perform the read operation if the size is valid and buffer exists.
                        if (read_size > 0 && read_buffer) {
                             gzread(file, read_buffer, read_size);
                        }
                    } else {
                        // Not enough data for the read size parameter, stop processing operations.
                        consumed_size = Size;
                    }
                    break;
                }
                case 2: { // Target API: gzbuffer
                    // Need enough data for the size parameter (unsigned int).
                    if (consumed_size + sizeof(unsigned int) <= Size) {
                        unsigned int buffer_size = *(unsigned int *)(Data + consumed_size);
                        consumed_size += sizeof(unsigned int);
                        // Call gzbuffer with the extracted size.
                        gzbuffer(file, buffer_size);
                    } else {
                        // Not enough data for the buffer size parameter, stop processing operations.
                        consumed_size = Size;
                    }
                    break;
                }
                case 3: { // Target API: gzgets
                    // Need enough data for the size parameter (int).
                    if (consumed_size + sizeof(int) <= Size) {
                        int gets_size = *(int *)(Data + consumed_size);
                        consumed_size += sizeof(int);
                        // Limit the gets size to the allocated buffer size.
                        if (gets_size > MAX_BUFFER_SIZE) {
                            gets_size = MAX_BUFFER_SIZE;
                        }
                        // Perform the gzgets operation if the size is valid and buffer exists.
                        if (gets_size > 0 && gets_buffer) {
                            gzgets(file, gets_buffer, gets_size);
                        }
                    } else {
                        // Not enough data for the gets size parameter, stop processing operations.
                        consumed_size = Size;
                    }
                    break;
                }
                 case 4: { // Target API: gzopen64 (attempt to reopen or open another file - less common in a single fuzzer iteration but can test state)
                    // This case is less likely to be hit frequently with modulo 5,
                    // and reopening the same file might have specific behaviors.
                    // For simplicity and focusing on the initial open and subsequent ops,
                    // we can make this case less impactful or skip it if needed.
                    // Let's just consume a byte to keep the input stream moving.
                    // A more complex fuzzer might generate a new filename and mode here.
                    // For now, just consume the byte.
                    break;
                 }
            }
        }

        // Clean up the gzFile handle.
        gzclose(file);

        // Free the allocated buffers.
        free(read_buffer);
        free(gets_buffer);
    }

    // Remove the temporary file created at the beginning.
    unlink(filename);

    return 0; // Indicate successful execution of the fuzzer iteration.
}