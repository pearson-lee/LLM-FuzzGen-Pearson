#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h> // For unlink and close
#include <fcntl.h> // For open

// Include zlib headers with project-relative paths
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // For z_stream and other types

// Define initial buffer size for compression/decompression output
#define INITIAL_BUF_SIZE 1024

// Define a reasonable limit for dictionary size
#define MAX_DICT_SIZE 1024

// Define a reasonable limit for filename length in gzopen
#define MAX_FILENAME_LEN 255

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte to select which API group to fuzz
    uint8_t api_selector = Data[0];
    Data++;
    Size--;

    // Minimum size checks based on the selected API group
    // These are approximate minimums to allow parameter extraction and basic calls
    if (api_selector % 5 == 0 && Size < 4 * sizeof(int)) return 0; // deflateInit2_ parameters
    if (api_selector % 5 == 1 && Size < sizeof(int)) return 0; // inflateInit2_ parameter
    if (api_selector % 5 == 2 && Size < 3) return 0; // gzopen mode + filename
    if (api_selector % 5 == 3 && Size < sizeof(int) + sizeof(uInt)) return 0; // inflateGetDictionary parameters (windowBits + dict_len)
    if (api_selector % 5 == 4 && Size < sizeof(uLong)) return 0; // deflateBound parameter


    switch (api_selector % 5) { // Fuzz up to 5 diverse API groups
        case 0: { // Fuzz deflateInit2_ and deflate (Compression)
            z_stream strm;
            memset(&strm, 0, sizeof(strm));

            // Extract parameters for deflateInit2_ from fuzzer input
            int level = Z_DEFAULT_COMPRESSION;
            int windowBits = 15;
            int memLevel = 8;
            int strategy = Z_DEFAULT_STRATEGY;

            if (Size >= sizeof(int)) {
                memcpy(&level, Data, sizeof(int));
                level = (level % 10) - 1; // Map to -1..9
                Data += sizeof(int);
                Size -= sizeof(int);
            }
            if (Size >= sizeof(int)) {
                memcpy(&windowBits, Data, sizeof(int));
                windowBits = (windowBits % 16) + 9; // Map to 9..24 (adjusting range slightly for variety, includes gzip header options)
                Data += sizeof(int);
                Size -= sizeof(int);
            }
             if (Size >= sizeof(int)) {
                memcpy(&memLevel, Data, sizeof(int));
                memLevel = (memLevel % 9) + 1; // Map to 1..9
                Data += sizeof(int);
                Size -= sizeof(int);
            }
             if (Size >= sizeof(int)) {
                memcpy(&strategy, Data, sizeof(int));
                strategy = strategy % 5; // Map to 0..4 (Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED)
                Data += sizeof(int);
                Size -= sizeof(int);
            }

            // Initialize the deflate stream
            int ret = deflateInit2_(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy, ZLIB_VERSION, sizeof(z_stream));

            if (ret == Z_OK) {
                // Fuzz deflate
                strm.next_in = (Bytef *)Data;
                strm.avail_in = Size;

                size_t out_buf_size = INITIAL_BUF_SIZE;
                Bytef *out = (Bytef*)malloc(out_buf_size);
                if (!out) {
                    deflateEnd(&strm);
                    return 0; // Allocation failed
                }

                strm.next_out = out;
                strm.avail_out = out_buf_size;

                int flush = Z_NO_FLUSH;
                if (Size > 0) {
                     // Use part of the remaining data for flush parameter
                     flush = Data[0] % 5; // Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH, Z_BLOCK
                }

                // Call deflate in a loop until input is consumed or stream ends
                do {
                    ret = deflate(&strm, flush);

                    if (ret == Z_BUF_ERROR) {
                        // Resize output buffer and continue
                        size_t old_buf_size = out_buf_size;
                        out_buf_size *= 2; // Double the buffer size
                        Bytef *new_out = (Bytef*)realloc(out, out_buf_size);
                        if (!new_out) {
                            // Reallocation failed, clean up and exit
                            free(out);
                            deflateEnd(&strm);
                            return 0;
                        }
                        out = new_out;
                        // Update next_out to point to the correct position in the new buffer
                        strm.next_out = out + old_buf_size - strm.avail_out;
                        strm.avail_out += out_buf_size - old_buf_size; // Add the newly allocated space
                    } else if (ret != Z_OK && ret != Z_STREAM_END) {
                        // Other errors, break the loop
                        break;
                    }
                } while (strm.avail_in > 0 && ret == Z_OK);

                // Clean up allocated output buffer and deflate stream
                free(out);
                deflateEnd(&strm);
            }
            break;
        }
        case 1: { // Fuzz inflateInit2_ and inflate (Decompression)
            z_stream strm;
            memset(&strm, 0, sizeof(strm));

            // Extract parameter for inflateInit2_
            int windowBits = 15;
            if (Size >= sizeof(int)) {
                memcpy(&windowBits, Data, sizeof(int));
                windowBits = (windowBits % 16) + 9; // Map to 9..24 (includes gzip header options)
                Data += sizeof(int);
                Size -= sizeof(int);
            }

            // Initialize the inflate stream
            int ret = inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream));

            if (ret == Z_OK) {
                // Fuzz inflate
                strm.next_in = (Bytef *)Data;
                strm.avail_in = Size;

                size_t out_buf_size = INITIAL_BUF_SIZE;
                Bytef *out = (Bytef*)malloc(out_buf_size);
                if (!out) {
                    inflateEnd(&strm);
                    return 0; // Allocation failed
                }

                strm.next_out = out;
                strm.avail_out = out_buf_size;

                // Call inflate in a loop until input is consumed or stream ends
                do {
                    ret = inflate(&strm, Z_NO_FLUSH); // Inflate typically uses Z_NO_FLUSH or Z_FINISH
                     if (ret == Z_BUF_ERROR) {
                        // Resize output buffer and continue
                        size_t old_buf_size = out_buf_size;
                        out_buf_size *= 2; // Double the buffer size
                        Bytef *new_out = (Bytef*)realloc(out, out_buf_size);
                        if (!new_out) {
                            // Reallocation failed, clean up and exit
                            free(out);
                            inflateEnd(&strm);
                            return 0;
                        }
                        out = new_out;
                        // Update next_out to point to the correct position in the new buffer
                        strm.next_out = out + old_buf_size - strm.avail_out;
                        strm.avail_out += out_buf_size - old_buf_size; // Add the newly allocated space
                    } else if (ret != Z_OK && ret != Z_STREAM_END) {
                        // Other errors, break the loop
                        break;
                    }
                } while (strm.avail_in > 0 && ret == Z_OK);

                // Clean up allocated output buffer and inflate stream
                free(out);
                inflateEnd(&strm);
            }
            break;
        }
        case 2: { // Fuzz gzopen (Gzip File Handling Initialization)
            // Need at least 2 bytes for mode string (e.g., "rb") and some data for filename
            if (Size < 3) return 0;

            // Extract mode string (e.g., "rb", "wb", "ab")
            char mode[3];
            mode[0] = Data[0];
            mode[1] = Data[1];
            mode[2] = '\0';

            // Consume bytes used for mode
            Data += 2;
            Size -= 2;

            // Use remaining data as filename. Ensure null termination.
            // Limit filename size to prevent excessive memory usage or file system issues
            size_t filename_len = Size > MAX_FILENAME_LEN ? MAX_FILENAME_LEN : Size;

            char filename[filename_len + 1];
            memcpy(filename, Data, filename_len);
            filename[filename_len] = '\0';

            // gzopen requires a real file path. Create a temporary file.
            // This makes the fuzzer stateful and potentially slower, but necessary for gzopen.
            char temp_filename_template[] = "/tmp/fuzz_gz_XXXXXX";
            char temp_filename[sizeof(temp_filename_template)];
            strcpy(temp_filename, temp_filename_template);

            int fd = mkstemp(temp_filename);
            if (fd == -1) {
                // Failed to create temp file
                return 0;
            }
            close(fd); // Close the file descriptor, gzopen will open it again

            // Call gzopen
            gzFile file = gzopen(temp_filename, mode);

            if (file != NULL) {
                // If opened successfully, attempt basic read/write operations
                // to exercise the file handle before closing.
                // This also helps cover gzwrite/gzread indirectly.
                if (mode[0] == 'w' || mode[0] == 'a') {
                    // Write some fuzzer data to the file
                    // Use remaining data after filename as content to write
                    if (Size > filename_len) {
                        gzwrite(file, Data + filename_len, Size - filename_len);
                    }
                } else if (mode[0] == 'r') {
                    // If opened for reading, attempt to read
                    Bytef in_buf[INITIAL_BUF_SIZE];
                    gzread(file, in_buf, INITIAL_BUF_SIZE);
                }

                // Close the gzFile
                gzclose(file);
            }

            // Clean up the temporary file
            unlink(temp_filename);

            break;
        }
        case 3: { // Fuzz inflateGetDictionary (Inflate Dictionary Handling)
             // Need at least sizeof(int) for windowBits and sizeof(uInt) for dict_len
             if (Size < sizeof(int) + sizeof(uInt)) return 0;

            z_stream strm;
            memset(&strm, 0, sizeof(strm));

            // Extract parameter for inflateInit2_
            int windowBits = 15;
            if (Size >= sizeof(int)) {
                memcpy(&windowBits, Data, sizeof(int));
                windowBits = (windowBits % 16) + 9; // Map to 9..24
                Data += sizeof(int);
                Size -= sizeof(int);
            }

            // Initialize inflate stream (may or may not succeed based on fuzzer input)
            inflateInit2_(&strm, windowBits, ZLIB_VERSION, sizeof(z_stream));


            // Allocate a buffer for the dictionary based on fuzzer input
            uInt dict_len = 0;
            if (Size >= sizeof(uInt)) {
                memcpy(&dict_len, Data, sizeof(uInt));
                dict_len %= (MAX_DICT_SIZE + 1); // Limit dictionary size
                Data += sizeof(uInt);
                Size -= sizeof(uInt);
            }

            Bytef *dictionary = NULL;
            uInt actual_dict_len = 0;

            if (dict_len > 0) {
                 dictionary = (Bytef*)malloc(dict_len);
                 if (!dictionary) {
                     inflateEnd(&strm);
                     return 0; // Allocation failed
                 }
                 // Optionally fill dictionary with fuzzer data if available
                 if (Size > 0) {
                     size_t copy_len = Size > dict_len ? dict_len : Size;
                     memcpy(dictionary, Data, copy_len);
                 }
            }

            // Call inflateGetDictionary. This tests calling the function
            // potentially in invalid states (e.g., before a dictionary is set).
            int ret = inflateGetDictionary(&strm, dictionary, &actual_dict_len);
            (void)ret; // Ignore return value for now

            // Clean up allocated dictionary buffer and inflate stream
            if (dictionary) {
                free(dictionary);
            }
            inflateEnd(&strm);

            break;
        }
        case 4: { // Fuzz deflateBound (Compression Utility)
            if (Size < sizeof(uLong)) return 0;

            // Extract sourceLen from fuzzer input
            uLong sourceLen;
            memcpy(&sourceLen, Data, sizeof(uLong));

            // Consume bytes used for sourceLen
            Data += sizeof(uLong);
            Size -= sizeof(uLong);

            // deflateBound requires a z_stream, but the function itself doesn't use the stream state
            // other than potentially checking version/struct size in debug builds.
            // Provide a minimally initialized stream for safety.
            z_stream strm;
            memset(&strm, 0, sizeof(strm));

            // Minimal initialization to make it look somewhat valid
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Call deflateBound
            uLong bound = deflateBound(&strm, sourceLen);
            (void)bound; // Ignore the result

            // No deflateEnd needed as deflateInit was not called

            break;
        }
    }

    return 0;
}