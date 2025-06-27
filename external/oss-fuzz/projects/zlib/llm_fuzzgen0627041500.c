// Comprehensive fuzz target for zlib, focusing on low-coverage APIs.
// This fuzzer aims to maximize code coverage by exercising
// crc32_z, inflateSyncPoint, inflateGetDictionary, gzfread, gzwrite, and deflate.
// Enhancements are based on analyzing coverage reports to target missed branches and lines,
// particularly in crc32.c (byte_swap, crc_word_big), trees.c (_tr_tally),
// inflate.c (inflateGetDictionary, inflateSyncPoint), and various deflate/gz* functions.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // For mkstemp, unlink
#include <fcntl.h>  // For open, write, close

// Include necessary zlib headers with project-relative paths
// Reordered includes based on build errors to resolve type and macro conflicts.
#include "/src/zlib/zconf.h" // Often needed first for configuration
#include "/src/zlib/zutil.h" // Defines utility functions and types like Bytef, uInt, etc.
#include "/src/zlib/inftrees.h" // Defines code and ENOUGH used by inflate.h
#include "/src/zlib/inffixed.h" // Defines fixed tables used by inflate.h
#include "/src/zlib/inflate.h" // Defines inflate_state and related structures/functions
#include "/src/zlib/zlib.h" // Main zlib API header
#include "/src/zlib/gzguts.h" // Internal gz definitions, included after inflate.h to avoid COPY macro conflict
#include "/src/zlib/deflate.h" // Defines deflate_state and related structures/functions

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
    // Coverage report shows missed coverage in crc32.c:byte_swap and crc32.c:crc_word_big.
    // These are likely called when processing data in chunks or with specific configurations
    // or on big-endian systems (byte_swap). The fuzzer cannot control endianness.
    // Call crc32_z in a loop with varying chunk sizes to hit these paths.
    uLong crc = 0; // Start with initial CRC 0
    size_t offset = 0;

    while (offset < Size) {
        size_t chunk_size = 1; // Default chunk size

        // Use fuzzer data to determine chunk size, ensure at least 1 byte for size.
        if (Size - offset >= sizeof(size_t)) {
             memcpy(&chunk_size, Data + offset, sizeof(size_t));
             // Cap chunk size to avoid excessive memory/time and ensure it's at least 1.
             if (chunk_size == 0 || chunk_size > Size - offset) {
                 chunk_size = (Size - offset > 0) ? (Size - offset) : 1;
             }
        } else if (Size - offset > 0) {
             // Not enough data for size_t, use remaining size as chunk size.
             chunk_size = Size - offset;
        } else {
            // No data left.
            break;
        }

        crc = crc32_z(crc, Data + offset, chunk_size);
        offset += chunk_size;
    }
}

// Fuzzing logic for inflateSyncPoint
// Targets low branch coverage in state checks.
void fuzz_inflateSyncPoint(const uint8_t *Data, size_t Size) {
    // Test inflateSyncPoint with a NULL z_stream pointer to hit the initial check.
    inflateSyncPoint(NULL);

    // Coverage report shows missed branches related to different inflate_state modes,
    // specifically the SYNC_POINT mode.
    // Initialize z_stream properly using inflateInit to get a valid state.
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
    strm.state = NULL;

    // Initialize the inflate stream. This sets up the internal state machine.
    int ret = inflateInit(&strm);
    if (ret == Z_OK) {
        // Added inflation logic to potentially reach the SYNC_POINT state
        // before calling inflateSyncPoint, based on coverage report analysis.
        if (Size > 0) {
            strm.next_in = (Bytef*)Data;
            strm.avail_in = (uInt)Size;

            // Allocate a small output buffer for inflation.
            size_t out_buf_size = 1024;
            Bytef *out_buf = (Bytef*)malloc(out_buf_size);
            if (out_buf) {
                strm.next_out = out_buf;
                strm.avail_out = (uInt)out_buf_size;

                // Perform inflation. Z_SYNC_FLUSH can help reach sync points.
                inflate(&strm, Z_SYNC_FLUSH);

                // Call the target function with the initialized and potentially updated stream state.
                inflateSyncPoint(&strm);

                free(out_buf); // Ensure memory safety: free allocated output buffer.
            } else {
                 // Call inflateSyncPoint even if allocation failed, to cover the initialized state path.
                 inflateSyncPoint(&strm);
            }
        } else {
             // Call inflateSyncPoint with the initialized state if no input data.
             inflateSyncPoint(&strm);
        }


        // Clean up the inflate stream.
        inflateEnd(&strm);
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
        free(dummy_buf); // Ensure memory safety: free allocated dummy buffer.
    }

    // Create a temporary file for gzopen.
    char *temp_filename = create_temp_file();
    if (temp_filename) {
        // Determine file mode based on fuzzer data to test different modes (read/write).
        // Coverage report shows missed branches related to file modes.
        const char *mode = "rb"; // Default read mode
        if (Size >= 1) {
            uint8_t mode_selector = Data[0];
            Data++;
            Size--;
            if (mode_selector % 2 == 1) {
                 mode = "wb"; // Test write mode to hit the mode check branch in gzfread
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
                // Call the target function.
                gzfread(read_buf, item_size, nitems, gz_file);
                free(read_buf); // Ensure memory safety: free the read buffer.
            }
            gzclose(gz_file); // Close the gzFile.
        }
        unlink(temp_filename); // Clean up the temporary file from the filesystem.
        free(temp_filename); // Ensure memory safety: free the temporary filename string.
    }
}

// Fuzzing logic for inflateGetDictionary
// Targets low coverage related to NULL pointers and state dictionary presence,
// specifically the Z_BUF_ERROR branch.
void fuzz_inflateGetDictionary(const uint8_t *Data, size_t Size) {
    // Test inflateGetDictionary with NULL pointers for all arguments.
    inflateGetDictionary(NULL, NULL, NULL);

    // Coverage report shows low coverage, likely missing the path where a dictionary is present
    // and the provided dictLength is too small (Z_BUF_ERROR).
    // Initialize z_stream properly and set a dictionary using inflateSetDictionary.
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
    strm.state = NULL;

    // Initialize the inflate stream.
    int ret = inflateInit(&strm);
    if (ret == Z_OK) {
        // Use fuzzer data to potentially set a dictionary.
        if (Size > 0) {
            // Cap dictionary size to avoid excessive memory use.
            size_t dict_size = Size > 1024 ? 1024 : Size;
            // Ensure enough data for the dictionary size.
            if (Size >= dict_size) {
                 inflateSetDictionary(&strm, Data, (uInt)dict_size);
                 // Consume data used for dictionary
                 Data += dict_size;
                 Size -= dict_size;
            }
        }

        Bytef *dictionary = NULL;
        uInt actualDictLength = 0;
        uInt *dictLength_ptr = NULL;

        // Use fuzzer data to control which pointers are NULL or allocated,
        // and to control the value pointed to by dictLength_ptr to hit the Z_BUF_ERROR branch.
        uint8_t control = 0;
        if (Size >= 1) {
             control = Data[0];
             Data++;
             Size--;
        }

        // Control the dictionary buffer pointer.
        // Allocate dummy dictionary buffer if control bit 0 is set.
        if (control & 1) dictionary = (Bytef*)malloc(100);

        // Control the dictLength pointer and its value.
        // Provide a non-NULL dictLength pointer if control bit 1 is set.
        if (control & 2) {
            dictLength_ptr = &actualDictLength;
            // Use fuzzer data to set the value pointed to by dictLength_ptr.
            // This is crucial to hit the Z_BUF_ERROR branch in inflateGetDictionary
            // where the provided length is less than the actual dictionary length.
            if (Size >= sizeof(uInt)) {
                memcpy(&actualDictLength, Data, sizeof(uInt));
                Data += sizeof(uInt);
                Size -= sizeof(uInt);
            } else {
                // Not enough data, set a small value to increase chances of hitting Z_BUF_ERROR
                actualDictLength = 1;
            }
        }

        // Call the target function.
        inflateGetDictionary(&strm, dictionary, dictLength_ptr);

        // Free allocated memory.
        if (dictionary) free(dictionary); // Ensure memory safety: free allocated dictionary buffer.

        // Clean up the inflate stream.
        inflateEnd(&strm);
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
        // Coverage report shows missed branches related to file modes.
        const char *mode = "wb"; // Default write mode
        if (Size >= 1) {
            uint8_t mode_selector = Data[0];
            Data++;
            Size--;
            if (mode_selector % 2 == 1) {
                 mode = "rb"; // Test read mode to hit the mode check branch in gzwrite
            }
        }

        // Open the temporary file.
        gzFile gz_file = gzopen(temp_filename, mode);
        if (gz_file) {
             // Call the target function. Use remaining fuzzer data as the buffer.
            gzwrite(gz_file, (void*)Data, Size);

            // Added call to gzflush based on coverage report showing missed branches in gzwrite.c:gz_flush.
            // This helps exercise the flushing logic.
            gzflush(gz_file, Z_SYNC_FLUSH);

            gzclose(gz_file); // Close the gzFile.
        }
        unlink(temp_filename); // Clean up the temporary file from the filesystem.
        free(temp_filename); // Ensure memory safety: free the temporary filename string.
    }
}

// Fuzzing logic for deflate
// Added based on low coverage of deflate and internal functions like _tr_tally.
void fuzz_deflate(const uint8_t *Data, size_t Size) {
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
    strm.state = NULL;

    // Initialize deflate stream. Use fuzzer data for level and strategy.
    int level = Z_DEFAULT_COMPRESSION;
    int strategy = Z_DEFAULT_STRATEGY;
    if (Size >= 2) {
        level = Data[0] % (Z_BEST_COMPRESSION + 1); // 0-9
        strategy = Data[1] % (Z_FIXED + 1); // 0-4
        Data += 2;
        Size -= 2;
    }

    int ret = deflateInit2(&strm, level, Z_DEFLATED, 15, 8, strategy);
    if (ret == Z_OK) {
        strm.next_in = (Bytef*)Data;
        strm.avail_in = (uInt)Size;

        // Allocate output buffer.
        size_t out_buf_size = deflateBound(&strm, Size); // Use deflateBound for size estimate
        if (out_buf_size == 0) out_buf_size = 1024; // Fallback if input size is 0
        Bytef *out_buf = (Bytef*)malloc(out_buf_size);

        if (out_buf) {
            strm.next_out = out_buf;
            strm.avail_out = (uInt)out_buf_size;

            // Perform deflation. Use fuzzer data for flush mode.
            int flush = Z_NO_FLUSH;
            if (Size >= 1) {
                flush = Data[0] % (Z_FINISH + 1); // 0-4
                // Consume the byte used for flush, but only if Size was >= 1 initially.
                // The previous check ensures Size >= 1 before accessing Data[0].
                Data++;
                Size--;
            }

            deflate(&strm, flush);

            free(out_buf); // Ensure memory safety: free allocated output buffer.
        }

        // Clean up the deflate stream.
        deflateEnd(&strm);
    }
}


// Entry point for the fuzzer.
// This function is called with a new fuzzer input each time.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure there's at least one byte to select the API.
    // Coverage report showed the Size < 1 branch was not taken, indicating no size 0 inputs.
    // The code correctly handles size 0, but the fuzzer runner needs to provide such inputs.
    // This check is kept as it's a standard fuzzer practice, but the coverage gap is in the fuzzer runner, not the code.
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input to select which API fuzzing logic to execute.
    uint8_t api_selector = Data[0];
    Data++; // Move pointer past the selector byte
    Size--; // Decrease remaining size

    // Call one of the fuzzing functions based on the selector.
    // Each function receives the rest of the fuzzer input.
    // Modified the modulo operator from % 6 to % 7 to include the new deflate case.
    switch (api_selector % 7) {
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
        case 5:
            // Added a case to cover the default branch of the switch statement,
            // which was previously unreachable according to the coverage report.
            // This case can simply return or call a dummy function.
            break;
        case 6:
            // Added a case to fuzz the deflate API directly, based on low coverage
            // of deflate and internal compression functions like _tr_tally.
            fuzz_deflate(Data, Size);
            break;
    }

    return 0; // Fuzzer always returns 0.
}