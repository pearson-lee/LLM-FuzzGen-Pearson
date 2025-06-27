// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // Required for ULONG_MAX

// Include zlib headers with specified paths
// Include zlib.h and zutil.h first as they contain fundamental definitions and macros
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h" // Defines ZLIB_INTERNAL and other utilities
// Include inftrees.h before inflate.h as it defines types and macros used in inflate.h
#include "/src/zlib/inftrees.h" // Required for 'code' type and 'ENOUGH' macro used in inflate.h
#include "/src/zlib/inflate.h" // For inflateInit, inflateSetDictionary, inflateEnd, inflate
#include "/src/zlib/deflate.h" // For deflateInit, deflatePrime, deflateEnd, deflate
#include "/src/zlib/crc32.h" // For get_crc_table

// Fuzz target that exercises several low-coverage zlib APIs.
// It uses the first byte of the input data to select which API to call,
// and the rest of the data as input for the selected API.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Need at least one byte to select the API
    if (Size < 1) {
        return 0;
    }

    // Use the first byte to determine which API to test
    uint8_t api_selector = Data[0];
    const uint8_t *input_data = Data + 1;
    size_t input_size = Size - 1;

    // Use a switch to select API(s) based on api_selector
    // Modulo is used to select one of the target APIs. Increased modulo to cover more APIs.
    switch (api_selector % 10) { // Increased cases to 10
        case 0: {
            // Target API: gzputs(gzFile file, const char *s)
            // This function writes a null-terminated string to a gzip file.
            // We need to create a temporary file and open it as a gzFile in write mode.
            FILE *tmp = tmpfile();
            if (!tmp) {
                // Failed to create temporary file
                return 0;
            }
            // Open the file descriptor as a gzFile in write mode
            gzFile gz_file = gzdopen(fileno(tmp), "w");
            if (!gz_file) {
                // Failed to open gzFile, close the underlying FILE*
                fclose(tmp);
                return 0;
            }

            // Create a null-terminated string from input_data to pass to gzputs.
            // Allocate memory for the string including the null terminator.
            char *str_data = NULL;
            if (input_size > 0) {
                str_data = (char*)malloc(input_size + 1);
                if (str_data) {
                    // Copy input data and add null terminator
                    memcpy(str_data, input_data, input_size);
                    str_data[input_size] = '\0';
                    // Call the target function
                    gzputs(gz_file, str_data);
                    // Free the allocated string memory
                    free(str_data);
                }
            } else {
                 // If input_size is 0, test with an empty string.
                 gzputs(gz_file, "");
            }

            // Close the gzFile. This also closes the underlying FILE* and removes the temporary file.
            gzclose(gz_file);
            break;
        }
        case 1: {
            // Target API: gzgetc(gzFile file)
            // This function reads a single character from a gzip file.
            // We need to create a temporary file, write some data to it,
            // and then open it as a gzFile in read mode.
            FILE *tmp = tmpfile();
            if (!tmp) {
                return 0; // Cannot create temporary file
            }

            // Write some data from the input to the temporary file using standard I/O.
            if (input_size > 0) {
                fwrite(input_data, 1, input_size, tmp);
                // Rewind the file pointer to the beginning before opening with gzdopen for reading.
                rewind(tmp);
            }

            // Open the file descriptor as a gzFile in read mode.
            gzFile gz_file = gzdopen(fileno(tmp), "r");
            if (!gz_file) {
                // Failed to open gzFile, close the underlying FILE*
                fclose(tmp);
                return 0;
            }

            // Read characters from the gzFile until the end of the file or an error occurs.
            while (gzgetc(gz_file) != EOF) {
                // We don't need to do anything with the character, just exercise the read path.
            }

            // Close the gzFile. This also closes the underlying FILE* and removes the temporary file.
            gzclose(gz_file);
            break;
        }
        case 2: {
            // Target API: gzrewind(gzFile file)
            // This function rewinds the file position indicator to the beginning of the file.
            // We need to create a temporary file, write some data, and open it as a gzFile.
            FILE *tmp = tmpfile();
            if (!tmp) {
                return 0; // Cannot create temporary file
            }

            // Write some data from the input to the temporary file.
            if (input_size > 0) {
                fwrite(input_data, 1, input_size, tmp);
                // Rewind the file pointer to the beginning before opening with gzdopen.
                rewind(tmp);
            }

            // Open the file descriptor as a gzFile in read mode.
            // Changed mode from "r+" to "r" to avoid gz_open returning NULL and hitting gzrewind.
            gzFile gz_file = gzdopen(fileno(tmp), "r");
            if (!gz_file) {
                // Failed to open gzFile, close the underlying FILE*
                fclose(tmp);
                return 0;
            }

            // Call the target function to rewind the file.
            gzrewind(gz_file);

            // Close the gzFile. This also closes the underlying FILE* and removes the temporary file.
            gzclose(gz_file);
            break;
        }
        case 3: {
            // Target API: inflateSetDictionary(z_streamp strm, const Bytef *dictionary, uInt dictLength)
            // This function sets the dictionary for inflate.
            // We need to initialize a z_stream structure for inflate.
            z_stream strm;
            strm.zalloc = Z_NULL; // Use default allocation functions
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Initialize the inflate stream.
            int ret = inflateInit(&strm);
            if (ret != Z_OK) {
                // Initialization failed
                return 0;
            }

            // Use the input data as the dictionary.
            // Call the target function.
            // Added logic to test dictLength < 3 and dictLength > state->wsize for inflateSetDictionary coverage.
            if (input_size > 0 && input_data[0] % 3 == 0) {
                 // Test dictLength < 3
                 inflateSetDictionary(&strm, (const Bytef *)input_data, input_size % 3);
            } else if (input_size > 0 && input_data[0] % 3 == 1) {
                 // Test dictLength > state->wsize (assuming default wsize is 32768)
                 // Provide a size larger than 32768 if input allows.
                 uInt large_size = 32769 + (input_size > 32769 ? input_size - 32769 : 0);
                 inflateSetDictionary(&strm, (const Bytef *)input_data, large_size);
            }
            else {
                 inflateSetDictionary(&strm, (const Bytef *)input_data, input_size);
            }


            // Clean up the inflate stream.
            // Added a call to inflate with dummy data to potentially transition state for inflateEnd coverage.
            Bytef output_buffer[10];
            strm.next_in = (Bytef *)input_data;
            strm.avail_in = input_size;
            strm.next_out = output_buffer;
            strm.avail_out = sizeof(output_buffer);
            inflate(&strm, Z_NO_FLUSH); // Call inflate before inflateEnd

            inflateEnd(&strm);
            break;
        }
        case 4: {
            // Target API: deflatePrime(z_streamp strm, int bits, int value)
            // This function primes the deflate stream with bits.
            // We need to initialize a z_stream structure for deflate.
            z_stream strm;
            strm.zalloc = Z_NULL; // Use default allocation functions
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Initialize the deflate stream with default compression level.
            int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (ret != Z_OK) {
                // Initialization failed
                return 0;
            }

            // Use parts of the input data for the 'bits' and 'value' parameters.
            // Ensure we have enough data for at least 'bits'.
            int bits = 0;
            int value = 0;

            if (input_size >= sizeof(int)) {
                // Read 'bits' from the input data.
                memcpy(&bits, input_data, sizeof(int));
                // The 'bits' parameter should be between 0 and 16.
                // Modified to sometimes produce bits > 8 to hit the bi_valid < 8 branch.
                if (input_data[0] % 2 == 0) {
                    bits = (bits % 8) + 9; // Ensure bits is between 9 and 16
                } else {
                    bits = bits % 17; // Original logic (0-16)
                }
                // Ensure bits is within the valid range [0, 16] after modification
                if (bits < 0) bits = 0;
                if (bits > 16) bits = 16;

            }
            // Ensure we have enough data for 'value'.
            if (input_size >= 2 * sizeof(int)) {
                 // Read 'value' from the input data.
                 memcpy(&value, input_data + sizeof(int), sizeof(int));
            }

            // Call the target function.
            deflatePrime(&strm, bits, value);

            // Clean up the deflate stream.
            // Added a call to deflate with dummy data to potentially transition state for deflateEnd coverage.
            Bytef output_buffer[10];
            strm.next_in = (Bytef *)input_data;
            strm.avail_in = input_size;
            strm.next_out = output_buffer;
            strm.avail_out = sizeof(output_buffer);
            deflate(&strm, Z_NO_FLUSH); // Call deflate before deflateEnd

            deflateEnd(&strm);
            break;
        }
        case 5: {
            // Target API: deflateGetDictionary(z_streamp strm, Bytef *dictionary, uInt *dictLength)
            // Added new case to cover deflateGetDictionary.
            z_stream strm;
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Initialize the deflate stream.
            int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (ret != Z_OK) {
                return 0;
            }

            // Allocate buffers for the dictionary and length.
            // Using a fixed size buffer for simplicity in this fuzzer.
            Bytef dictionary_buffer[1024];
            uInt dict_length = 0;

            // Call the target function.
            deflateGetDictionary(&strm, dictionary_buffer, &dict_length);

            // Clean up the deflate stream.
            deflateEnd(&strm);
            break;
        }
        case 6: {
            // Target API: inflatePrime(z_streamp strm, int bits, int value)
            // Added new case to cover inflatePrime.
            z_stream strm;
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;

            // Initialize the inflate stream.
            int ret = inflateInit(&strm);
            if (ret != Z_OK) {
                return 0;
            }

            // Use parts of the input data for 'bits' and 'value'.
            int bits = 0;
            int value = 0;

            if (input_size >= sizeof(int)) {
                memcpy(&bits, input_data, sizeof(int));
                bits = bits % 17; // bits should be between 0 and 16
            }
            if (input_size >= 2 * sizeof(int)) {
                 memcpy(&value, input_data + sizeof(int), sizeof(int));
            }

            // Call the target function.
            inflatePrime(&strm, bits, value);

            // Clean up the inflate stream.
            inflateEnd(&strm);
            break;
        }
        case 7: {
            // Target API: gzungetc(int c, gzFile file)
            // Added new case to cover gzungetc.
            FILE *tmp = tmpfile();
            if (!tmp) {
                return 0;
            }

            // Write some data to the temporary file.
            if (input_size > 0) {
                fwrite(input_data, 1, input_size, tmp);
                rewind(tmp);
            }

            // Open the file as a gzFile in read mode.
            gzFile gz_file = gzdopen(fileno(tmp), "r");
            if (!gz_file) {
                fclose(tmp);
                return 0;
            }

            // Read a character, then unget it.
            int c = gzgetc(gz_file);
            if (c != EOF) {
                gzungetc(c, gz_file);
            }

            // Close the gzFile.
            gzclose(gz_file);
            break;
        }
        case 8: {
            // Target API: gzflush(gzFile file, int flush)
            // Added new case to cover gzflush with different flush modes.
            FILE *tmp = tmpfile();
            if (!tmp) {
                return 0;
            }

            // Open the file as a gzFile in write mode.
            gzFile gz_file = gzdopen(fileno(tmp), "w");
            if (!gz_file) {
                fclose(tmp);
                return 0;
            }

            // Write some data.
            if (input_size > 0) {
                gzwrite(gz_file, input_data, input_size);
            }

            // Call gzflush with different modes based on input.
            int flush_mode = Z_NO_FLUSH;
            if (input_size > 0) {
                switch (input_data[0] % 4) {
                    case 0: flush_mode = Z_NO_FLUSH; break;
                    case 1: flush_mode = Z_SYNC_FLUSH; break;
                    case 2: flush_mode = Z_FULL_FLUSH; break;
                    case 3: flush_mode = Z_FINISH; break;
                }
            }
            gzflush(gz_file, flush_mode);

            // Close the gzFile.
            gzclose(gz_file);
            break;
        }
        case 9: {
            // Target API: get_crc_table(void)
            // Added new case to cover get_crc_table.
            // This function initializes and returns the CRC-32 table.
            // Simply calling it is sufficient for coverage.
            const z_crc_t *crc_table = get_crc_table();
            // No cleanup needed for the returned pointer as it points to static data.
            break;
        }
        // Add more cases here for other low-coverage functions identified.
    }

    return 0;
}