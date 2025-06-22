#include <stdint.h>
#include <stddef.h>
#include "/src/zlib/zlib.h" // Required for zlib functions and types
#include <stdio.h>  // Required for tmpfile, fclose, fileno, fwrite, fflush, fseek
#include <stdlib.h> // Required for general utilities like malloc/free if zlib's aren't used (though zlib uses its own)
#include <string.h> // Required for strlen

// Fuzzer entry point
// This function is called repeatedly with new fuzzed data.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    // 1. Fuzzing crc32_z:
    // This function calculates the CRC-32 checksum of a data buffer.
    // We aim to exercise its internal logic, including paths that might
    // involve byte swapping based on system endianness (though endianness
    // is compile-time, diverse inputs can still explore other branches).
    if (Size > 0) {
        // Use a fuzzed initial CRC value to explore different states.
        unsigned long initial_crc = 0;
        if (Size >= sizeof(unsigned long)) {
            // Consume bytes from the fuzzed data for the initial_crc.
            // This ensures the initial_crc itself is fuzzed.
            for (size_t i = 0; i < sizeof(unsigned long); ++i) {
                initial_crc = (initial_crc << 8) | Data[i];
            }
        }
        // Call crc32_z with the fuzzed initial CRC and data.
        (void)crc32_z(initial_crc, Data, Size);
    }

    // 2. Fuzzing gzsetparams:
    // This function sets the compression parameters for a gzip file.
    // We will create various gzFile states to hit different branches within gzsetparams.

    // Case 1: Call gzsetparams with a NULL file pointer.
    // This specifically targets the 'if (file == NULL)' branch.
    gzsetparams(Z_NULL, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);

    // Case 2: Valid gzFile in compressed write mode.
    // This case explores setting parameters for a standard compressed output file.
    FILE *temp_file_compressed_write = tmpfile(); // Create a temporary file
    if (temp_file_compressed_write) {
        // Open the temporary file for compressed writing.
        // gzopen_w is not a standard zlib function. Use gzdopen with fileno.
        gzFile file_compressed_write = gzdopen(fileno(temp_file_compressed_write), "wb");
        if (file_compressed_write != Z_NULL) {
            int level = Z_DEFAULT_COMPRESSION;
            int strategy = Z_DEFAULT_STRATEGY;

            // Fuzz compression level (0-9)
            if (Size > 0) {
                level = Data[0] % 10;
                if (level == 0) level = Z_NO_COMPRESSION; // Ensure valid level
                else if (level == 9) level = Z_BEST_COMPRESSION;
            }
            // Fuzz compression strategy (0-4)
            if (Size > 1) {
                strategy = Data[1] % 5;
                if (strategy == 0) strategy = Z_DEFAULT_STRATEGY;
                else if (strategy == 1) strategy = Z_FILTERED;
                else if (strategy == 2) strategy = Z_HUFFMAN_ONLY;
                else if (strategy == 3) strategy = Z_RLE;
                else if (strategy == 4) strategy = Z_FIXED;
            }

            // Call gzsetparams with fuzzed level and strategy.
            gzsetparams(file_compressed_write, level, strategy);

            // Write some data to potentially trigger the 'state->size' branch
            // within gzsetparams if it's called again after data has been buffered.
            if (Size > 2) {
                gzwrite(file_compressed_write, Data + 2, Size - 2);
                gzsetparams(file_compressed_write, level, strategy); // Call again after write
            }

            // Attempt to hit the 'state->seek' branch by performing a seek operation.
            if (Size > 3) {
                long offset = (long)Data[3]; // Fuzz the seek offset
                gzseek(file_compressed_write, offset, SEEK_SET);
                gzsetparams(file_compressed_write, level, strategy); // Call again after seek
            }

            gzclose(file_compressed_write); // Close the gzFile to free resources
        }
        fclose(temp_file_compressed_write); // Close the underlying FILE*
    }

    // Case 3: Valid gzFile in direct (uncompressed) write mode.
    // This aims to hit the 'state->direct' branch within gzsetparams.
    FILE *temp_file_direct_write = tmpfile();
    if (temp_file_direct_write) {
        // Open in "wb" mode for direct writing (no compression).
        gzFile file_direct_write = gzdopen(fileno(temp_file_direct_write), "wb");
        if (file_direct_write != Z_NULL) {
            int level = Z_NO_COMPRESSION; // Force no compression for direct mode
            int strategy = Z_DEFAULT_STRATEGY;

            gzsetparams(file_direct_write, level, strategy); // This should hit state->direct

            gzclose(file_direct_write); // Close the gzFile
        }
        fclose(temp_file_direct_write); // Close the underlying FILE*
    }

    // Case 4: Valid gzFile in read mode.
    // This aims to hit the 'state->mode != GZ_WRITE' branch, as gzsetparams is typically for write mode.
    FILE *temp_file_read_data = tmpfile();
    if (temp_file_read_data) {
        // Write some dummy data to the file so it's not empty when opened for reading.
        const char *dummy_data = "dummy data for reading";
        fwrite(dummy_data, 1, strlen(dummy_data), temp_file_read_data);
        fflush(temp_file_read_data); // Ensure data is written to disk
        fseek(temp_file_read_data, 0, SEEK_SET); // Rewind to beginning for reading

        // Open the file for reading.
        gzFile file_read = gzdopen(fileno(temp_file_read_data), "rb");
        if (file_read != Z_NULL) {
            int level = Z_DEFAULT_COMPRESSION;
            int strategy = Z_DEFAULT_STRATEGY;

            gzsetparams(file_read, level, strategy); // This should hit state->mode != GZ_WRITE

            gzclose(file_read); // Close the gzFile
        }
        fclose(temp_file_read_data); // Close the underlying FILE*
    }

    // 3. Fuzzing zlibCompileFlags:
    // This function returns a uLong indicating compile-time flags.
    // It's a simple call that doesn't take input, but calling it ensures
    // its execution path is covered.
    (void)zlibCompileFlags();

    return 0; // Indicate successful execution
}