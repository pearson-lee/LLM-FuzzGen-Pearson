#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // for malloc, free, unlink
#include <stdio.h>  // for fopen, fwrite, fclose, remove
#include <string.h> // for memcpy, memset

// Include zlib headers with full paths
#include "/src/zlib/zconf.h"
#include "/src/zlib/zlib.h"
#include "/src/zlib/gzguts.h" // For gz_statep and related structures/macros

// Function to create a temporary filename.
// Using a fixed name and unlink for cleanup is sufficient for a single-threaded fuzzer.
char *create_temp_file() {
    char *filename = malloc(strlen("fuzz_temp_file.gz") + 1);
    if (filename) {
        strcpy(filename, "fuzz_temp_file.gz");
    }
    return filename;
}

// Entry point for the fuzzer.
// This function receives fuzzed data and its size.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Need at least 1 byte to select the API.
    if (Size < 1) {
        return 0;
    }

    // Consume 1 byte to select which API to test (0-4).
    uint8_t api_selector = Data[0];
    Data++;
    Size--;

    // Use a switch statement to call different APIs based on the selector.
    switch (api_selector % 5) { // Test up to 5 diverse APIs
        case 0: {
            // Test crc32_z: Calculates the CRC of a buffer.
            // uLong crc32_z(uLong crc, const Bytef *buf, uInt len);

            uLong initial_crc = 0; // Start with initial CRC 0, or fuzzed value
            if (Size >= sizeof(uLong)) {
                 memcpy(&initial_crc, Data, sizeof(uLong));
                 Data += sizeof(uLong);
                 Size -= sizeof(uLong);
            }

            // Ensure len fits in uInt, cap at remaining size.
            uInt len = (Size > (uInt)-1) ? (uInt)-1 : Size;

            // Call the target function.
            crc32_z(initial_crc, Data, len);

            break;
        }
        case 1: {
            // Test deflateBound: Returns an upper bound on the compressed size.
            // uLong deflateBound(z_streamp strm, uLong sourceLen);

            z_stream strm;
            // Need enough data for deflateInit2 parameters.
            if (Size < 4) {
                return 0;
            }

            // Consume fuzzer data for deflateInit2 parameters.
            int level = (Data[0] % 10) - 1; // Z_DEFAULT_COMPRESSION (-1) to 9
            int windowBits = (Data[1] % 8) + 8; // 8 to 15 (for raw deflate)
            int memLevel = (Data[2] % 9) + 1; // 1 to 9
            int strategy = Data[3] % 4; // Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE

            // Add 16 to windowBits to test gzip header inclusion paths in deflateBound.
            windowBits += 16;

            Data += 4;
            Size -= 4;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Initialize the deflate stream.
            int ret = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);

            if (ret == Z_OK) {
                uLong sourceLen = 0;
                // Consume fuzzer data for sourceLen.
                 if (Size >= sizeof(uLong)) {
                     memcpy(&sourceLen, Data, sizeof(uLong));
                 } else if (Size > 0) {
                     // Use remaining size if not enough for uLong.
                     sourceLen = Size;
                 }

                // Call the target function.
                deflateBound(&strm, sourceLen);

                // Clean up the deflate stream.
                deflateEnd(&strm);
            }
            break;
        }
        case 2: {
            // Test inflateCopy: Copies an inflate state.
            // int inflateCopy(z_streamp dest, z_streamp source);

            z_stream source_strm, dest_strm;

            // Initialize source stream.
            // Need at least 1 byte for windowBits.
            if (Size < 1) {
                return 0;
            }
            int windowBits = (Data[0] % 8) + 8; // 8 to 15
            // Add 16 to windowBits to test gzip header parsing paths.
            windowBits += 16;
            Data++;
            Size--;

            source_strm.zalloc = Z_NULL;
            source_strm.zfree = Z_NULL;
            source_strm.opaque = Z_NULL;
            source_strm.avail_in = 0;
            source_strm.next_in = Z_NULL;
            source_strm.state = Z_NULL; // Ensure state is NULL before init

            int ret_source = inflateInit2(&source_strm, windowBits);

            // Initialize destination stream (state will be allocated by inflateCopy).
            dest_strm.zalloc = Z_NULL;
            dest_strm.zfree = Z_NULL;
            dest_strm.opaque = Z_NULL;
            dest_strm.avail_in = 0;
            dest_strm.next_in = Z_NULL;
            dest_strm.state = Z_NULL; // Crucial: state must be NULL for inflateCopy

            if (ret_source == Z_OK) {
                // Optionally feed some data to source_strm to build up state/window,
                // targeting the state->window != Z_NULL branch in inflateCopy.
                source_strm.avail_in = Size;
                source_strm.next_in = (z_const Bytef *)Data;
                // Use a dummy output buffer for inflate.
                Bytef dummy_out[1024];
                source_strm.avail_out = sizeof(dummy_out);
                source_strm.next_out = dummy_out;
                // Call inflate to process some data and potentially allocate the window.
                inflate(&source_strm, Z_NO_FLUSH);

                // Call the target function.
                inflateCopy(&dest_strm, &source_strm);

                // Clean up both streams.
                inflateEnd(&source_strm);
                // inflateCopy allocates state for dest_strm, so we need inflateEnd for it.
                if (dest_strm.state != Z_NULL) {
                     inflateEnd(&dest_strm);
                }
            }
            break;
        }
        case 3: {
            // Test gzread: Reads data from a gzip file.
            // int gzread(gzFile file, voidp buf, unsigned len);

            char *temp_filename = create_temp_file();
            if (temp_filename) {
                // Write fuzzed data to the temporary file.
                FILE *temp_file = fopen(temp_filename, "wb");
                if (temp_file) {
                    fwrite(Data, 1, Size, temp_file);
                    fclose(temp_file);

                    // Open the file for reading.
                    gzFile gz_file = gzopen(temp_filename, "rb");
                    if (gz_file) {
                        // Determine read length from fuzzer data.
                        unsigned read_len = 0;
                        if (Size >= sizeof(unsigned)) {
                            memcpy(&read_len, Data, sizeof(unsigned));
                            // Cap read_len to avoid excessive memory allocation.
                            if (read_len > 4096) read_len = 4096;
                        } else if (Size > 0) {
                            read_len = Size;
                        } else {
                             // If no data left, still call with a small length to exercise paths.
                             read_len = 1;
                        }

                        // Allocate a buffer for reading.
                        if (read_len > 0) {
                            void *read_buf = malloc(read_len);
                            if (read_buf) {
                                // Call the target function.
                                gzread(gz_file, read_buf, read_len);
                                // Ensure memory safety: free the read buffer.
                                free(read_buf);
                            }
                        } else {
                             // Call with len = 0, still need a valid buffer pointer.
                             void *read_buf = malloc(1);
                             if (read_buf) {
                                 gzread(gz_file, read_buf, 0);
                                 free(read_buf);
                             }
                        }

                        // Close the gzFile.
                        gzclose(gz_file);
                    }
                }
                // Clean up the temporary file from the filesystem.
                unlink(temp_filename);
                // Ensure memory safety: free the temporary filename string.
                free(temp_filename);
            }
            break;
        }
        case 4: {
            // Test gzwrite: Writes data to a gzip file.
            // int gzwrite(gzFile file, voidpc buf, unsigned len);

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
                         // Use a different mode to potentially hit mode check branches in gzwrite.
                         // Although gzwrite is for writing, passing a read mode might trigger error paths.
                         mode = "rb";
                    } else if (mode_selector % 3 == 1) {
                         // Test different compression levels.
                         mode = "wb1";
                    } else if (mode_selector % 3 == 2) {
                         mode = "wb9";
                    }
                }

                // Open the temporary file.
                gzFile gz_file = gzopen(temp_filename, mode);
                if (gz_file) {
                    // Call the target function. Use remaining fuzzer data as the buffer.
                    unsigned write_len = (Size > (unsigned)-1) ? (unsigned)-1 : Size;
                    gzwrite(gz_file, (void*)Data, write_len);

                    // Added call to gzflush based on coverage report showing missed branches in gzwrite.c:gz_flush.
                    // This helps exercise the flushing logic.
                    if (Size >= 1) {
                        int flush_mode = Data[0] % 3; // Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FINISH
                        gzflush(gz_file, flush_mode);
                        // Data++; Size--; // Not strictly necessary as we are done with Data
                    }


                    // Close the gzFile.
                    gzclose(gz_file);
                }
                // Clean up the temporary file from the filesystem.
                unlink(temp_filename);
                // Ensure memory safety: free the temporary filename string.
                free(temp_filename);
            }
            break;
        }
    }

    return 0;
}