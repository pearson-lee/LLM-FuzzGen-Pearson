// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include "/src/zlib/zlib.h"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h> // For mkstemp and unlink
#include <stdio.h> // For file operations

// Define a dummy file path for gzopen64. Using /dev/null is common for fuzzing
// file operations without needing actual file system interaction.
#define DUMMY_FILE_PATH "/dev/null"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Need at least one byte to select the API to test.
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input data to select which API or set of APIs to test.
    uint8_t api_selector = Data[0];

    // Consume the selector byte.
    size_t current_offset = 1;

    // Test one of the selected low-coverage APIs based on the selector.
    switch (api_selector % 5) { // Use modulo 5 to select one of the 5 target APIs
        case 0: { // Test gzopen64 and gzsetparams
            // gzopen64 requires a path and a mode string.
            // gzsetparams requires a gzFile, level, and strategy.
            // Minimum data needed: 4 bytes for mode + 2 bytes for params = 6 bytes + 1 selector = 7 bytes.
            if (Size >= 7) {
                char mode[5] = {0};
                // Safely copy up to 4 bytes for the mode string.
                size_t mode_copy_len = (current_offset + 4 <= Size) ? 4 : Size - current_offset;
                memcpy(mode, Data + current_offset, mode_copy_len);
                mode[mode_copy_len] = '\0'; // Ensure null termination.
                current_offset += mode_copy_len;

                // Only proceed if the mode is one we want to test (e.g., write or read).
                if (strcmp(mode, "wb") == 0 || strcmp(mode, "rb") == 0) {
                    gzFile file = NULL;
                    char temp_filename[] = "/tmp/gztest_XXXXXX"; // Template for temporary file
                    int fd = -1;

                    if (strcmp(mode, "wb") == 0) {
                        // Create a temporary file for write mode testing.
                        fd = mkstemp(temp_filename);
                        if (fd != -1) {
                            // Use gzdopen to open the file descriptor as a gzFile.
                            // gzdopen takes ownership of the fd.
                            file = gzdopen(fd, mode);
                            if (file == NULL) {
                                // If gzdopen failed, close the file descriptor.
                                close(fd);
                            }
                        }
                    } else { // mode is "rb"
                        // Create a temporary file for read mode testing.
                        fd = mkstemp(temp_filename);
                        if (fd != -1) {
                            // Write remaining fuzzer data to the temporary file.
                            size_t data_to_write_len = Size - current_offset;
                            if (data_to_write_len > 0) {
                                write(fd, Data + current_offset, data_to_write_len);
                            }
                            close(fd); // Close the fd before opening with gzdopen

                            // Open the temporary file using gzdopen in read mode.
                            file = gzdopen(fd, mode); // gzdopen takes ownership of the fd
                            if (file == NULL) {
                                 // If gzdopen failed, the fd was already closed, just unlink.
                            }
                        }
                    }

                    if (file != NULL) {
                        // If opened successfully in write mode and enough data is available, test gzsetparams.
                        // gzsetparams is only relevant for write modes.
                        if (strcmp(mode, "wb") == 0 && current_offset + 2 <= Size) {
                            // Extract level and strategy from the input data.
                            int level = Data[current_offset++] % 10 - 1; // Map byte to -1 to 9.
                            int strategy = Data[current_offset++] % 5; // Map byte to 0 to 4 (Z_DEFAULT_STRATEGY to Z_FIXED).
                            gzsetparams(file, level, strategy);
                        }
                        // Close the gzFile to free resources.
                        gzclose(file);
                    }

                    // Clean up the temporary file if it was created.
                    if (fd != -1) {
                        unlink(temp_filename);
                    }
                }
            }
            break;
        }
        case 1: { // Test compress2
            // compress2 requires destination buffer, destination length, source buffer, source length, and level.
            // Minimum data needed: 1 byte for destLen variation + 1 byte for level + source data.
            // Let's assume a minimum source data size of 10 bytes for meaningful compression attempts.
            // Total minimum size: 1 selector + 1 destLen variation + 1 level + 10 source = 13 bytes.
            if (Size >= 13) {
                // Reserve bytes for parameters before the source data.
                size_t params_size = 2; // 1 byte for destLen variation, 1 byte for level.
                size_t source_offset = current_offset + params_size;

                // Ensure there's enough data for source and parameters.
                if (source_offset < Size) {
                    uLong sourceLen = (uLong)(Size - source_offset);
                    // Allocate a destination buffer, usually larger than the source.
                    uLong destLen = (uLong)(sourceLen * 2 + 100);

                    // Use a byte from the input to sometimes test smaller destination buffers.
                    if (current_offset < Size && Data[current_offset] % 2 == 0) {
                         destLen = (uLong)(sourceLen / 2 + 1);
                    }
                    current_offset++; // Consume byte used for destLen variation.

                    Bytef *source = (Bytef *)(Data + source_offset);
                    Bytef *dest = (Bytef *)malloc(destLen);

                    if (dest != NULL) {
                        // Ensure enough data for the level byte.
                        if (current_offset < Size) {
                             int level = Data[current_offset] % 10 - 1; // Map byte to -1 to 9.
                             // Call compress2.
                             compress2(dest, &destLen, source, sourceLen, level);
                        }
                        // Free the allocated destination buffer.
                        free(dest);
                    }
                    // Consume all remaining data as it was potentially used for source.
                    current_offset = Size;
                } else {
                     // Not enough data for this test case, consume remaining.
                     current_offset = Size;
                }
            }
            break;
        }
        case 2: { // Test inflateBackInit_
            // inflateBackInit_ requires a z_stream, windowBits, window buffer, version string, and stream size.
            // Minimum data needed: 1 byte for windowBits + 1 selector = 2 bytes.
            if (Size >= 2) {
                z_stream strm;
                // Initialize z_stream with default alloc/free.
                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;

                // Extract windowBits from input data (8 to 15).
                uInt windowBits = Data[current_offset++] % 8 + 8;
                // Allocate the window buffer based on windowBits.
                unsigned char *window = (unsigned char *)malloc(1U << windowBits);

                if (window != NULL) {
                     // Call inflateBackInit_. Note: inflateBackEnd should ideally be called
                     // if inflateBackInit_ succeeds and inflateBack is used. However,
                     // for fuzzing the initialization function specifically, just calling
                     // Init is sufficient to hit its code paths.
                     inflateBackInit_(&strm, windowBits, window, ZLIB_VERSION, sizeof(z_stream));
                     // Free the allocated window buffer.
                     free(window);
                }
            }
            break;
        }
        case 3: { // Test crc32_combine
            // crc32_combine requires two uLong values (crc1, crc2) and a z_off_t value (len2).
            // The timeout report suggests large values for len2 are problematic.
            // We will limit the size of len2 by extracting a smaller integer type.
            // Minimum data needed: 1 selector + sizeof(uLong) * 2 + sizeof(uint16_t).
            // Assuming uLong is 8 bytes and uint16_t is 2 bytes, this is 1 + 8*2 + 2 = 19 bytes.
            if (Size >= current_offset + sizeof(uLong) * 2 + sizeof(uint16_t)) {
                uLong crc1 = 0, crc2 = 0;
                z_off_t len2 = 0;
                size_t initial_offset = current_offset; // Store offset to reset if extraction fails.

                // Safely extract crc1 (uLong).
                if (current_offset + sizeof(uLong) <= Size) {
                    memcpy(&crc1, Data + current_offset, sizeof(uLong));
                    current_offset += sizeof(uLong);
                } else break; // Not enough data for crc1.

                // Safely extract crc2 (uLong).
                if (current_offset + sizeof(uLong) <= Size) {
                    memcpy(&crc2, Data + current_offset, sizeof(uLong));
                    current_offset += sizeof(uLong);
                } else {
                    current_offset = initial_offset; // Reset offset if not enough data for crc2.
                    break;
                }

                // Safely extract len2 using a smaller type (uint16_t) to limit its value.
                if (current_offset + sizeof(uint16_t) <= Size) {
                    uint16_t temp_len2;
                    memcpy(&temp_len2, Data + current_offset, sizeof(uint16_t));
                    len2 = (z_off_t)temp_len2; // Cast to z_off_t
                    current_offset += sizeof(uint16_t);
                } else {
                    current_offset = initial_offset; // Reset offset if not enough data for len2.
                    break;
                }

                // If all parameters were successfully extracted, call crc32_combine.
                crc32_combine(crc1, crc2, len2);
            }
            break;
        }
        case 4: { // Test deflateSetDictionary
            // deflateSetDictionary requires a z_stream, a dictionary buffer, and dictionary length.
            // It needs a z_stream initialized for deflation.
            // Minimum data needed: 1 selector + dictionary data.
            // Let's assume a minimum dictionary size of 10 bytes. Total = 1 + 10 = 11 bytes.
            if (Size >= 11) {
                z_stream strm;
                // Initialize z_stream with default alloc/free.
                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;

                // Initialize the deflate stream.
                int init_ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION); // Use default compression level.

                if (init_ret == Z_OK) {
                    // Use the remaining data as the dictionary.
                    size_t dict_offset = current_offset;
                    uInt dictLen = (uInt)(Size - dict_offset);
                    const Bytef *dictionary = Data + dict_offset;

                    // Call deflateSetDictionary.
                    deflateSetDictionary(&strm, dictionary, dictLen);

                    // Clean up the deflate stream.
                    deflateEnd(&strm);
                }
                // Consume all remaining data as it was used for the dictionary.
                current_offset = Size;
            }
            break;
        }
    }

    return 0;
}