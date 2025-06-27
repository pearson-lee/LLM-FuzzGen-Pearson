// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
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
#include "/src/zlib/zconf.h" // For Z_DICT_MAX and other configuration defines

// Define initial buffer size for compression/decompression output
#define INITIAL_BUF_SIZE 1024

// Define a reasonable limit for dictionary size (Z_DICT_MAX is 32768)
// Corrected: Z_DICT_MAX is not a standard macro, use the value directly.
#define MAX_DICT_SIZE 32768

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
    // Adjusted minimum sizes for new cases and enhanced existing ones
    if (api_selector % 7 == 0 && Size < 4 * sizeof(int)) return 0; // deflateInit2_ parameters
    if (api_selector % 7 == 1 && Size < sizeof(int)) return 0; // inflateInit2_ parameter
    if (api_selector % 7 == 2 && Size < 3) return 0; // gzopen mode + filename (need at least 2 for mode, 1 for filename)
    if (api_selector % 7 == 3 && Size < sizeof(int) + sizeof(uInt)) return 0; // inflateGetDictionary parameters (windowBits + dict_len)
    if (api_selector % 7 == 4 && Size < sizeof(uLong)) return 0; // deflateBound parameter
    if (api_selector % 7 == 5 && Size < sizeof(int)) return 0; // compress2 parameters (level)
    if (api_selector % 7 == 6 && Size < 0) return 0; // uncompress2 parameters (no specific minimum beyond 1 for selector)


    switch (api_selector % 7) { // Fuzz up to 7 diverse API groups
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
        case 2: { // Fuzz gzopen and related gz* functions
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

            // Consume bytes used for filename
            Data += filename_len;
            Size -= filename_len;

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
                    if (Size > 0) {
                        gzwrite(file, Data, Size);
                    }
                    // Added calls to gz* utility functions based on coverage report
                    // to improve coverage of gzflush, gzsetparams, etc.
                    gzflush(file, Z_SYNC_FLUSH);
                    int level = Z_DEFAULT_COMPRESSION;
                    int strategy = Z_DEFAULT_STRATEGY;
                    if (Size > 0) { // Use fuzzer data for parameters if available
                         level = Data[0] % 10 - 1;
                         if (Size > 1) strategy = Data[1] % 5;
                    }
                    gzsetparams(file, level, strategy);
                } else if (mode[0] == 'r') {
                    // If opened for reading, attempt to read
                    Bytef in_buf[INITIAL_BUF_SIZE];
                    gzread(file, in_buf, INITIAL_BUF_SIZE);

                    // Added calls to gz* utility functions based on coverage report
                    // to improve coverage of gzseek, gztell, gzeof, etc.
                    gzseek(file, 0, SEEK_SET);
                    gztell(file);
                    gzeof(file);
                    gzrewind(file);
                    gzdirect(file); // Check if file is being read directly
                    gzbuffer(file, 1024); // Set buffer size
                    gzungetc('a', file); // Push a character back
                    char read_char = gzgetc(file); // Read a character
                    char* read_line = gzgets(file, (char*)in_buf, INITIAL_BUF_SIZE); // Read a line
                    gzclearerr(file); // Clear error flags
                    int err;
                    const char* err_str = gzerror(file, &err); // Get error string
                    (void)read_char; // Avoid unused variable warning
                    (void)read_line; // Avoid unused variable warning
                    (void)err_str; // Avoid unused variable warning
                }

                // Close the gzFile
                gzclose(file);
            }

            // Clean up the temporary file
            unlink(temp_filename);

            break;
        }
        case 3: { // Fuzz inflateSetDictionary and inflateGetDictionary (Inflate Dictionary Handling)
             // Need at least sizeof(int) for windowBits, sizeof(uInt) for dict_len, and some data for the dictionary itself
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
            // Use a windowBits value that allows dictionaries (15 or -15)
            int init_windowBits = (windowBits % 2 == 0) ? 15 : -15;
            int ret_init = inflateInit2_(&strm, init_windowBits, ZLIB_VERSION, sizeof(z_stream));


            // Allocate a buffer for the dictionary based on fuzzer input
            uInt dict_len = 0;
            if (Size >= sizeof(uInt)) {
                memcpy(&dict_len, Data, sizeof(uInt));
                dict_len %= (MAX_DICT_SIZE + 1); // Limit dictionary size
                Data += sizeof(uInt);
                Size -= sizeof(uInt);
            }

            Bytef *dictionary_in = NULL;
            Bytef *dictionary_out = NULL;
            uInt actual_dict_len = 0;

            if (dict_len > 0) {
                 dictionary_in = (Bytef*)malloc(dict_len);
                 if (!dictionary_in) {
                     inflateEnd(&strm);
                     return 0; // Allocation failed
                 }
                 // Fill dictionary with fuzzer data if available
                 if (Size > 0) {
                     size_t copy_len = Size > dict_len ? dict_len : Size;
                     memcpy(dictionary_in, Data, copy_len);
                 }
            }

            // Added call to inflateSetDictionary based on coverage report
            // This helps cover branches related to setting a dictionary.
            if (ret_init == Z_OK && dictionary_in != NULL) {
                 inflateSetDictionary(&strm, dictionary_in, dict_len);
            }

            // Allocate buffer to receive dictionary from inflateGetDictionary
            // Increased buffer size to MAX_DICT_SIZE to cover cases where a large dictionary is available.
            dictionary_out = (Bytef*)malloc(MAX_DICT_SIZE);
            if (!dictionary_out) {
                 if (dictionary_in) free(dictionary_in);
                 inflateEnd(&strm);
                 return 0; // Allocation failed
            }


            // Call inflateGetDictionary. This tests calling the function
            // potentially in invalid states (e.g., before a dictionary is set).
            // Added call with a valid buffer to receive the dictionary.
            int ret_get = inflateGetDictionary(&strm, dictionary_out, &actual_dict_len);
            (void)ret_get; // Ignore return value for now

            // Clean up allocated dictionary buffers and inflate stream
            if (dictionary_in) {
                free(dictionary_in);
            }
            if (dictionary_out) {
                free(dictionary_out);
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
        case 5: { // Fuzz compress2 (Compression Convenience Function)
            if (Size < sizeof(int)) return 0; // Need at least size for level

            // Extract level from fuzzer input
            int level;
            memcpy(&level, Data, sizeof(int));
            level = (level % 10) - 1; // Map to -1..9
            Data += sizeof(int);
            Size -= sizeof(int);

            // Input data is the rest of the fuzzer input
            const Bytef *in_buf = Data;
            uLong in_len = Size;

            // Allocate output buffer (deflateBound gives a safe upper bound)
            uLong out_len_bound = compressBound(in_len);
            Bytef *out_buf = (Bytef*)malloc(out_len_bound);
            if (!out_buf) {
                return 0; // Allocation failed
            }
            uLong out_len = out_len_bound; // Use the bound as initial output size

            // Call compress2
            int ret = compress2(out_buf, &out_len, in_buf, in_len, level);
            (void)ret; // Ignore return value for now

            // Clean up allocated output buffer
            free(out_buf);

            break;
        }
        case 6: { // Fuzz uncompress2 (Decompression Convenience Function)
            // Input data is the entire fuzzer input
            const Bytef *in_buf = Data;
            uLong in_len = Size;

            // Allocate output buffer (arbitrary initial size, will need resizing for real use)
            // For fuzzing uncompress2, we can provide a fixed-size output buffer
            // and let the function report Z_BUF_ERROR if it's too small.
            // A small buffer helps trigger Z_BUF_ERROR paths.
            uLong out_len = INITIAL_BUF_SIZE;
            Bytef *out_buf = (Bytef*)malloc(out_len);
            if (!out_buf) {
                return 0; // Allocation failed
            }

            // Call uncompress2
            // Note: uncompress2 requires the *initial* size of the output buffer
            // and updates the uLong pointer with the actual decompressed size.
            int ret = uncompress2(out_buf, &out_len, in_buf, &in_len);
            (void)ret; // Ignore return value for now

            // Clean up allocated output buffer
            free(out_buf);

            break;
        }
    }

    return 0;
}