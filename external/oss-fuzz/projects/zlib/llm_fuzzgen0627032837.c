// Comprehensive fuzz target for zlib, focusing on low-coverage APIs.
// This fuzzer aims to maximize code coverage by exercising
// crc32_z, inflateSyncPoint, gzfread, inflateGetDictionary, and gzwrite.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // For mkstemp, unlink

// Include necessary zlib headers with project-relative paths
// Reordered includes based on build errors to resolve type and macro conflicts.
#include "/src/zlib/zconf.h" // Often needed first for configuration
#include "/src/zlib/zutil.h" // Defines utility functions and types like Bytef, uInt, etc.
#include "/src/zlib/inftrees.h" // Defines code and ENOUGH used by inflate.h
#include "/src/zlib/inffixed.h" // Defines fixed tables used by inflate.h
#include "/src/zlib/inflate.h" // Defines inflate_state and related structures/functions
#include "/src/zlib/zlib.h" // Main zlib API header
#include "/src/zlib/gzguts.h" // Internal gz definitions, included after inflate.h to avoid COPY macro conflict

// Function to create a temporary file and return its path
// Used for fuzzing gz* functions that operate on files.
static char* create_temp_file() {
    char template[] = "/tmp/gzfuzz_XXXXXX";
    int fd = mkstemp(template);
    if (fd == -1) {
        perror("mkstemp");
        return NULL;
    }
    close(fd); // Close the file descriptor, gzopen will open it again
    return strdup(template); // Return a dynamically allocated copy
}

// Fuzzing logic for crc32_z
// This function indirectly exercises byte_swap and crc_word_big.
void fuzz_crc32_z(const uint8_t *Data, size_t Size) {
    // crc32_z calculates the CRC of a buffer.
    // We use the remaining fuzzer data as the input buffer.
    uLong crc = 0; // Start with initial CRC 0
    crc32_z(crc, Data, Size);
}

// Fuzzing logic for inflateSyncPoint
// Targets low branch coverage in state checks.
void fuzz_inflateSyncPoint(const uint8_t *Data, size_t Size) {
    // Test inflateSyncPoint with a NULL z_stream pointer to hit the initial check.
    inflateSyncPoint(NULL);

    // Allocate and initialize z_stream and inflate_state.
    // inflate_state is an internal structure, accessing it directly is for fuzzing purposes.
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.msg = Z_NULL;
    strm.next_in = Z_NULL;
    strm.avail_in = 0;
    strm.next_out = Z_NULL;
    strm.avail_out = 0;
    strm.adler = 0;
    strm.total_in = 0;
    strm.total_out = 0;
    strm.data_type = 0;
    strm.state = NULL; // Start with NULL state to test inflateStateCheck

    // Note: Accessing inflate_state directly is fragile and depends on zlib internals.
    // The original code attempted to set 'mode' and 'bits'.
    // We will keep this attempt for now, assuming these members exist,
    // but acknowledge this is implementation-dependent.
    struct inflate_state *state = (struct inflate_state *)calloc(1, sizeof(struct inflate_state));
    if (state) {
        strm.state = state;

        // Use fuzzer data to set mode and bits to hit different branches in inflateSyncPoint.
        // Consume data carefully to avoid reading out of bounds.
        if (Size >= sizeof(int)) {
            memcpy(&state->mode, Data, sizeof(int));
            Data += sizeof(int);
            Size -= sizeof(int);
        }
         if (Size >= sizeof(int)) {
            memcpy(&state->bits, Data, sizeof(int));
            Data += sizeof(int);
            Size -= sizeof(int);
        }

        // Call the target function with the initialized stream.
        inflateSyncPoint(&strm);

        // Free the allocated state.
        free(state);
    }
}

// Fuzzing logic for gzfread
// Targets low branch coverage related to file state and input parameters.
void fuzz_gzfread(const uint8_t *Data, size_t Size) {
    // Test gzfread with a NULL gzFile pointer.
    // Need a dummy buffer, size, and nitems for the call.
    size_t dummy_size = 1;
    size_t dummy_nitems = 1;
    void *dummy_buf = malloc(dummy_size * dummy_nitems);
    if (dummy_buf) {
        gzfread(dummy_buf, dummy_size, dummy_nitems, NULL);
        free(dummy_buf);
    }

    // Create a temporary file for gzopen.
    char *temp_filename = create_temp_file();
    if (temp_filename) {
        // Determine file mode based on fuzzer data to test different modes (read/write).
        const char *mode = "rb"; // Default read mode
        if (Size >= 1) {
            uint8_t mode_selector = Data[0];
            Data++;
            Size--;
            if (mode_selector % 2 == 1) {
                 mode = "wb"; // Test write mode to hit the mode check branch
            }
        }

        // Open the temporary file.
        gzFile gz_file = gzopen(temp_filename, mode);
        if (gz_file) {
            // Allocate buffer for reading.
            // Derive size and nitems from fuzzer data, capping buffer size to avoid excessive memory use.
            size_t item_size = 1; // Fixed item size for simplicity
            size_t nitems = 0;
            // Ensure enough data for size_t
            if (Size >= sizeof(size_t)) {
                 memcpy(&nitems, Data, sizeof(size_t));
                 Data += sizeof(size_t);
                 Size -= sizeof(size_t);
            } else {
                 // Not enough data, use a default small size
                 nitems = 1;
            }

            size_t buf_len = item_size * nitems;
            size_t max_buf_size = 4096; // Cap buffer size
            if (buf_len > max_buf_size || buf_len == 0) buf_len = max_buf_size;

            void *read_buf = malloc(buf_len);
            if (read_buf) {
                // Attempt to inject error state (implementation-dependent and tricky).
                // gz_statep state = (gz_statep)gz_file;
                // if (Size >= sizeof(int)) {
                //     memcpy(&state->err, Data, sizeof(int));
                //     Data += sizeof(int);
                //     Size -= sizeof(int);
                // }

                // Call the target function.
                gzfread(read_buf, item_size, nitems, gz_file);
                free(read_buf); // Free the read buffer.
            }
            gzclose(gz_file); // Close the gzFile.
        }
        unlink(temp_filename); // Clean up the temporary file from the filesystem.
        free(temp_filename); // Free the temporary filename string.
    }
}

// Fuzzing logic for inflateGetDictionary
// Targets low coverage related to NULL pointers and state dictionary presence.
void fuzz_inflateGetDictionary(const uint8_t *Data, size_t Size) {
    // Test inflateGetDictionary with NULL pointers for all arguments.
    inflateGetDictionary(NULL, NULL, NULL);

    // Allocate and initialize z_stream and inflate_state.
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.msg = Z_NULL;
    strm.next_in = Z_NULL;
    strm.avail_in = 0;
    strm.next_out = Z_NULL;
    strm.avail_out = 0;
    strm.adler = 0;
    strm.total_in = 0;
    strm.total_out = 0;
    strm.data_type = 0;
    strm.state = NULL; // Start with NULL state

    // Note: Accessing inflate_state directly is fragile and depends on zlib internals.
    // Removed attempts to set state->dictionary and state->dictLength as they caused build errors.
    struct inflate_state *state = (struct inflate_state *)calloc(1, sizeof(struct inflate_state));
     if (state) {
        strm.state = state;

        Bytef *dictionary = NULL;
        uInt *dictLength = NULL;
        uInt actualDictLength = 0;

        // Use fuzzer data to control which pointers are NULL or allocated.
        uint8_t control = 0;
        if (Size >= 1) {
             control = Data[0];
             Data++;
             Size--;
        }

        // Control the dictionary and dictLength pointers passed to the function.
        if (control & 1) dictionary = (Bytef*)malloc(100); // Allocate dummy dictionary buffer
        if (control & 2) dictLength = &actualDictLength; // Provide a non-NULL dictLength pointer

        // Call the target function.
        // inflateGetDictionary will write to 'dictionary' and 'dictLength' if a dictionary is present in the state.
        inflateGetDictionary(&strm, dictionary, dictLength);

        // Free allocated memory.
        if (dictionary) free(dictionary);
        // Removed free(state->dictionary) as state->dictionary is not directly manipulated/allocated here.
        free(state); // Free the allocated state.
     }
}

// Fuzzing logic for gzwrite
// Targets low branch coverage related to file state.
void fuzz_gzwrite(const uint8_t *Data, size_t Size) {
    // Test gzwrite with a NULL gzFile pointer.
    // Use the remaining fuzzer data as the input buffer.
    gzwrite(NULL, (void*)Data, Size);

    // Create a temporary file for gzopen.
    char *temp_filename = create_temp_file();
    if (temp_filename) {
        // Determine file mode based on fuzzer data to test different modes (write/read).
        const char *mode = "wb"; // Default write mode
        if (Size >= 1) {
            uint8_t mode_selector = Data[0];
            Data++;
            Size--;
            if (mode_selector % 2 == 1) {
                 mode = "rb"; // Test read mode to hit the mode check branch
            }
        }

        // Open the temporary file.
        gzFile gz_file = gzopen(temp_filename, mode);
        if (gz_file) {
             // Attempt to inject error state (implementation-dependent and tricky).
             // gz_statep state = (gz_statep)gz_file;
             // if (Size >= sizeof(int)) {
             //     memcpy(&state->err, Data, sizeof(int));
             //     Data += sizeof(int);
             //     Size -= sizeof(int);
             // }

            // Call the target function. Use remaining fuzzer data as the buffer.
            gzwrite(gz_file, (void*)Data, Size);
            gzclose(gz_file); // Close the gzFile.
        }
        unlink(temp_filename); // Clean up the temporary file from the filesystem.
        free(temp_filename); // Free the temporary filename string.
    }
}


// Entry point for the fuzzer.
// This function is called with a new fuzzer input each time.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure there's at least one byte to select the API.
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input to select which API fuzzing logic to execute.
    uint8_t api_selector = Data[0];
    Data++; // Move pointer past the selector byte
    Size--; // Decrease remaining size

    // Call one of the fuzzing functions based on the selector.
    // Each function receives the rest of the fuzzer input.
    switch (api_selector % 5) {
        case 0:
            fuzz_crc32_z(Data, Size);
            break;
        case 1:
            fuzz_inflateSyncPoint(Data, Size);
            break;
        case 2:
            fuzz_gzfread(Data, Size);
            break;
        case 3:
            fuzz_inflateGetDictionary(Data, Size);
            break;
        case 4:
            fuzz_gzwrite(Data, Size);
            break;
    }

    return 0; // Fuzzer always returns 0.
}