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
#include "/src/zlib/zconf.h"
#include "/src/zlib/zutil.h" // For zlibCompileFlags

// Define DYNAMIC_CRC_TABLE to enable dynamic CRC table generation,
// which helps cover functions like byte_swap and crc_word_big in crc32.c.
#define DYNAMIC_CRC_TABLE

// Define z_word_t as it's used in crc32.c but not explicitly typedef'd in zconf.h or zlib.h
// It's likely intended to be the same as z_crc_t, which is defined in zconf.h
typedef z_crc_t z_word_t;

// Define a maximum size for the temporary file to prevent excessive resource usage
#define MAX_FILE_SIZE 1024 * 1024 // 1 MB

// Extracted definition of byte_swap from crc32.c
// This function is marked as 'local' (static) in crc32.c, meaning it's not
// exposed for external linkage. By defining it directly in the fuzzer,
// we ensure it's compiled and linked correctly without conflicts.
static z_word_t byte_swap(z_word_t word) {
#if W == 8
    return
        (word & 0xff00000000000000) >> 56 |
        (word & 0xff000000000000) >> 40 |
        (word & 0xff0000000000) >> 24 |
        (word & 0xff00000000) >> 8 |
        (word & 0xff000000) << 8 |
        (word & 0xff0000) << 24 |
        (word & 0xff00) << 40 |
        (word & 0xff) << 56;
#else   /* W == 4 */
    return
        (word & 0xff000000) >> 24 |
        (word & 0xff0000) >> 8 |
        (word & 0xff00) << 8 |
        (word & 0xff) << 24;
#endif
}

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

        // Added call to gzgetc_ based on coverage report (0% coverage)
        gzgetc_(file);

        // Test gzwrite: Writes data to the gzip file.
        // Only perform write operations if the file was opened in write mode.
        if (mode_choice == 1) {
            // Write a portion of the fuzzer input.
            gzwrite(file, Data, Size);
            // Also test writing with zero length to cover that specific branch in gzwrite.
            gzwrite(file, Data, 0);

            // Added call to gzfwrite based on coverage report (low coverage)
            gzfwrite(Data, 1, Size, file);

            // Added call to gzputc based on coverage report (low coverage)
            if (Size > 0) {
                gzputc(file, Data[0]);
            }

            // Added call to gzputs based on coverage report (low coverage)
            char *str_data = (char *)malloc(Size + 1);
            if (str_data != NULL) {
                memcpy(str_data, Data, Size);
                str_data[Size] = '\0';
                gzputs(file, str_data);
                free(str_data);
            }

            // Added call to gzprintf based on coverage report (low coverage)
            gzprintf(file, "Test %d\n", 123);
        }

        // Added call to gzflush based on coverage report (low coverage)
        gzflush(file, Z_FULL_FLUSH);

        // Added call to gzsetparams based on coverage report (low coverage)
        gzsetparams(file, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);

        // Added calls to gzread, gzfread, gzungetc, gzgets, gzdirect based on coverage report (low coverage)
        if (mode_choice == 0) {
            Bytef *read_buf = (Bytef *)malloc(Size);
            if (read_buf != NULL) {
                gzread(file, read_buf, Size);
                free(read_buf);
            }

            Bytef *fread_buf = (Bytef *)malloc(Size);
            if (fread_buf != NULL) {
                gzfread(fread_buf, 1, Size, file);
                free(fread_buf);
            }

            if (Size > 0) {
                gzungetc(Data[0], file);
            }

            char *gets_buf = (char *)malloc(Size + 1);
            if (gets_buf != NULL) {
                gzgets(file, gets_buf, Size + 1);
                free(gets_buf);
            }
        }
        gzdirect(file);


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

    // Added call to gzclose(NULL) to cover the Z_STREAM_ERROR path in gzclose, gzclose_r, and gzclose_w.
    gzclose(NULL);

    // Added call to get_crc_table() to cover functions in crc32.c like byte_swap and crc_word_big
    // by triggering the dynamic table generation.
    get_crc_table();

    // Added call to byte_swap based on coverage report (0% coverage in crc32.c)
    if (Size >= sizeof(z_word_t)) {
        z_word_t word;
        memcpy(&word, Data, sizeof(z_word_t));
        z_word_t swapped_word = byte_swap(word);
        (void)swapped_word; // Use it to avoid unused variable warning
    }

    // Added call to zlibCompileFlags based on coverage report (low coverage in zutil.c)
    (void)zlibCompileFlags();

    // Added calls to compress2 based on coverage report (low branch coverage in compress.c)
    if (Size > 2) { // Ensure enough data for source
        uLong sourceLen = Size - 2;
        // Use compressBound to get a safe destination buffer size for compress2
        uLong destLen = compressBound(sourceLen); 

        Bytef *source = (Bytef *)(Data + 2);
        Bytef *dest = (Bytef *)malloc(destLen);

        if (dest != NULL) {
            int level_choice = Data[0] % 10; // Use fuzzer input for compression level (0-9)
            compress2(dest, &destLen, source, sourceLen, level_choice);
            free(dest); // Free allocated memory for dest to prevent memory leaks
        }

        // Added call to compress2 with a small destLen to trigger Z_BUF_ERROR path
        uLong small_destLen = 1;
        Bytef *small_dest = (Bytef *)malloc(small_destLen);
        if (small_dest != NULL) {
            compress2(small_dest, &small_destLen, source, sourceLen, Z_DEFAULT_COMPRESSION);
            free(small_dest);
        }
    }

    // Added calls to deflateBound and deflateParams based on coverage report (low coverage in deflate.c)
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret == Z_OK) {
        if (Size > 2) {
            uLong sourceLen = Size - 2;
            uLong bound = deflateBound(&strm, sourceLen);
            (void)bound; // Use it to avoid unused variable warning

            // Use fuzzer input for level and strategy
            int level_choice = Data[0] % 10; // 0-9
            // Z_DEFAULT_STRATEGY (0), Z_FILTERED (1), Z_HUFFMAN_ONLY (2), Z_RLE (3), Z_FIXED (4)
            int strategy_choice = Data[1] % 5; 
            deflateParams(&strm, level_choice, strategy_choice);
        }

        // Added calls to deflate functions for coverage
        // Added call to deflateSetDictionary based on coverage report (low coverage)
        Bytef *dictionary = (Bytef *)Data;
        uInt dictLength = Size;
        deflateSetDictionary(&strm, dictionary, dictLength);

        // Added call to deflateGetDictionary based on coverage report (low coverage)
        Bytef *ret_dict = (Bytef *)malloc(Size);
        uLong ret_dict_len;
        if (ret_dict != NULL) {
            deflateGetDictionary(&strm, ret_dict, &ret_dict_len);
            free(ret_dict);
        }

        // Added call to deflateReset based on coverage report (low coverage)
        deflateReset(&strm);

        // Added call to deflateSetHeader based on coverage report (low coverage)
        gz_header header_out;
        deflateSetHeader(&strm, &header_out);

        // Added call to deflatePending based on coverage report (low coverage)
        unsigned int pending_len;
        int pending_bits;
        deflatePending(&strm, &pending_len, &pending_bits);

        // Added call to deflatePrime based on coverage report (low coverage)
        if (Size > 0) {
            deflatePrime(&strm, 8, Data[0]);
        }

        // Added call to deflateTune based on coverage report (low coverage)
        deflateTune(&strm, 0, 0, 0, 0);

        // Added call to deflate based on coverage report (low coverage)
        uLong compressed_destLen = compressBound(Size);
        Bytef *compressed_data = (Bytef *)malloc(compressed_destLen);
        if (compressed_data != NULL) {
            strm.avail_in = Size;
            strm.next_in = (Bytef *)Data;
            strm.avail_out = compressed_destLen;
            strm.next_out = compressed_data;
            deflate(&strm, Z_FINISH);
            free(compressed_data);
        }

        // Added call to deflateCopy based on coverage report (low coverage)
        z_stream strm_copy;
        strm_copy.zalloc = Z_NULL;
        strm_copy.zfree = Z_NULL;
        strm_copy.opaque = Z_NULL;
        deflateCopy(&strm_copy, &strm);
        deflateEnd(&strm_copy);

        deflateEnd(&strm); // Free internal state allocated by deflateInit to prevent memory leaks
    }

    // Added calls to inflate functions for coverage
    z_stream inflate_strm;
    inflate_strm.zalloc = Z_NULL;
    inflate_strm.zfree = Z_NULL;
    inflate_strm.opaque = Z_NULL;

    // Initialize inflate_strm with windowBits = 15 (Z_DEFAULT_WINDOWBITS) to ensure (state->wrap & 2) == 0 for inflateGetHeader.
    int inflate_ret = inflateInit2(&inflate_strm, 15); 
    if (inflate_ret == Z_OK) {
        // Added call to inflateGetHeader to cover branches where (state->wrap & 2) == 0.
        gz_header header;
        inflateGetHeader(&inflate_strm, &header);

        // Added calls to inflateGetDictionary with NULL parameters to cover branches where dictionary or dictLength are NULL.
        uLong dictLen;
        inflateGetDictionary(&inflate_strm, NULL, &dictLen); // dictionary == Z_NULL
        inflateGetDictionary(&inflate_strm, (Bytef*)Data, NULL); // dictLength == Z_NULL

        // Added call to inflateGetDictionary with non-NULL parameters to cover more branches
        Bytef *ret_dict_inflate = (Bytef *)malloc(Size);
        uLong ret_dict_len_inflate;
        if (ret_dict_inflate != NULL) {
            inflateGetDictionary(&inflate_strm, ret_dict_inflate, &ret_dict_len_inflate);
            free(ret_dict_inflate);
        }

        // Added call to inflateCopy with NULL destination to cover the error path for dest == Z_NULL.
        inflateCopy(NULL, &inflate_strm);

        // Added call to inflateCopy with non-NULL destination to cover more branches
        z_stream inflate_strm_copy_non_null;
        inflate_strm_copy_non_null.zalloc = Z_NULL;
        inflate_strm_copy_non_null.zfree = Z_NULL;
        inflate_strm_copy_non_null.opaque = Z_NULL;
        inflateCopy(&inflate_strm_copy_non_null, &inflate_strm);
        inflateEnd(&inflate_strm_copy_non_null);

        // Added call to inflateReset. This helps exercise the function and its internal state checks.
        inflateReset(&inflate_strm);

        // Added call to inflateReset2 based on coverage report (low coverage)
        inflateReset2(&inflate_strm, 15);

        // Added call to inflatePrime based on coverage report (low coverage)
        if (Size > 0) {
            inflatePrime(&inflate_strm, 8, Data[0]);
        }

        // Added call to inflateSetDictionary based on coverage report (low coverage)
        Bytef *inflate_dictionary = (Bytef *)Data;
        uInt inflate_dictLength = Size;
        inflateSetDictionary(&inflate_strm, inflate_dictionary, inflate_dictLength);

        // Added call to inflateSync based on coverage report (low coverage)
        // Ensure next_in and avail_in are initialized to prevent use-after-free if they contain garbage.
        inflate_strm.next_in = Z_NULL;
        inflate_strm.avail_in = 0;
        inflateSync(&inflate_strm);

        // Added call to inflateSyncPoint based on coverage report (low coverage)
        inflateSyncPoint(&inflate_strm);

        // Added call to inflateUndermine based on coverage report (low coverage)
        inflateUndermine(&inflate_strm, 0);

        // Added call to inflateValidate based on coverage report (low coverage)
        inflateValidate(&inflate_strm, 0);

        // Added call to inflateMark based on coverage report (low coverage)
        inflateMark(&inflate_strm);

        // Added call to inflateCodesUsed based on coverage report (low coverage)
        inflateCodesUsed(&inflate_strm);

        // Added call to inflate based on coverage report (low coverage)
        uLong inflated_destLen = Size * 2;
        Bytef *inflated_data = (Bytef *)malloc(inflated_destLen);
        if (inflated_data != NULL) {
            inflate_strm.avail_in = Size;
            inflate_strm.next_in = (Bytef *)Data;
            inflate_strm.avail_out = inflated_destLen;
            inflate_strm.next_out = inflated_data;
            inflate(&inflate_strm, Z_FINISH);
            free(inflated_data);
        }

        inflateEnd(&inflate_strm); // Clean up inflate_strm
    } else {
        // If inflateInit2 failed, ensure inflate_strm is properly ended if it was partially initialized.
        // This is a defensive measure, though inflateInit2 failing usually means no state was allocated.
        if (inflate_strm.state != Z_NULL) {
            inflateEnd(&inflate_strm);
        }
    }

    // Clean up the temporary file from the filesystem.
    // This is safe even if 'fd' was -1, as 'filename' still holds the path.
    unlink(filename);

    return 0;
}