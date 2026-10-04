/* BLOCKER_STRATEGY_CONTRACT
required_state: The internal push-back buffer of the `gz_state` struct must be full, which corresponds to the predicate `state->x.have == (state->size << 1)`.
state_constructor: After opening the file for reading, `gzbuffer()` is called to set a small, predictable buffer size (e.g., 256 bytes). This makes `state->size = 256` and the total ungetc buffer capacity `512` bytes. A loop then calls `gzungetc()` more than 512 times to guarantee an attempt to write to a full buffer.
trigger_api: `gzungetc(c, file)`
preserved_invariants: The top-level input consumption contract is preserved. The initial data writing and subsequent reading logic remains intact. The `gzbuffer()` call and the modified `gzungetc()` loop are added to establish the required state without altering the core API sequence.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "/src/zlib/zlib.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        exit(1); \
    } \
}

// Fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0;
    }

    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", "fuzz");

    gzFile file;
    z_stream strm;
    int err;

    // Consume data for parameters
    int level = data[0] % 10 - 1; // -1 to 8
    int strategy = data[1] % 5; // 0 to 4
    int flush_type = data[2] % 7; // To get different flush types
    int windowBits = (data[3] % 8) + 8; // 8 to 15
    int memLevel = (data[4] % 9) + 1; // 1 to 9
    const uint8_t *remaining_data = data + 5;
    size_t remaining_size = size - 5;
    
    if (remaining_size == 0) {
        unlink(path);
        return 0;
    }

    // --- Test gzopen, gzsetparams, gzwrite, gzflush, gzclose ---
    
    file = gzopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "gzopen error\n");
        unlink(path);
        return 0;
    }

    gzwrite(file, "dummy", 5);
    gzbuffer(file, 1024);

    if (gzwrite(file, remaining_data, remaining_size > 10 ? 10 : remaining_size) == 0) {
        // Error or nothing written, still proceed to test other things
    }

    gzsetparams(file, level, strategy);

    gzwrite(file, remaining_data, remaining_size);

    if (size > 1) {
        if (data[1] % 10 == 0) { 
             gzflush(file, 99); 
        }
    }

    gzflush(file, flush_type);
    gzclose(file);

    // --- Test gzopen, gzungetc, gzgets, gzclose ---

    file = gzopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "gzopen error for reading\n");
        unlink(path);
        return 0;
    }
    
    // BLOCKER-ORIENTED CHANGE:
    // Set a small buffer size before any read operations. This makes it feasible
    // to fill the buffer completely. gzbuffer must be called after gzopen but
    // before any reads. A size of 256 results in a 512-byte ungetc buffer.
    gzbuffer(file, 256);

    char buffer[256];
    gzgets(file, buffer, sizeof(buffer));

    if (remaining_size > 0) {
        long offset = remaining_data[0]; 
        gzseek(file, offset, SEEK_SET);
    }

    // BLOCKER-ORIENTED CHANGE:
    // The blocker `if (state->x.have == (state->size << 1))` is reached when the
    // ungetc buffer is full. With gzbuffer(file, 256), the buffer capacity is 512.
    // This loop runs more than 512 times to ensure it attempts to push a
    // character into a full buffer, triggering the error.
    for (int i = 0; i < 513; i++) { 
        if (gzungetc('a', file) == -1) {
            break;
        }
    }
    gzungetc(-1, file); 

    gzrewind(file);
    gzgets(file, buffer, sizeof(buffer)); 
    gzclose(file);
    gzclearerr(NULL); 

    // --- Test deflateBound and deflate ---
    
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (size > 6 && data[6] % 2 == 0) {
        windowBits += 16;
    }
    
    err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (err != Z_OK) {
        unlink(path);
        return 0;
    }

    if (size > 8) {
        if (data[8] % 3 == 1) {
            deflateParams(&strm, level, Z_HUFFMAN_ONLY);
        } else if (data[8] % 3 == 2) {
            deflateParams(&strm, level, Z_RLE);
        }
    }


    unsigned long compressed_size = deflateBound(&strm, remaining_size);
    unsigned char *compressed_buffer = (unsigned char *)malloc(compressed_size);
    if (compressed_buffer == NULL) {
        deflateEnd(&strm);
        unlink(path);
        return 0;
    }

    strm.avail_in = remaining_size;
    strm.next_in = (Bytef *)remaining_data;
    strm.avail_out = compressed_size;
    strm.next_out = compressed_buffer;

    if (size > 7) {
        if (data[7] % 4 == 1) {
            strm.next_out = Z_NULL;
        } else if (data[7] % 4 == 2) {
            strm.avail_out = 0;
        }
    }

    err = deflate(&strm, Z_FINISH);

    deflateEnd(&strm);
    free(compressed_buffer);

    unlink(path);

    return 0;
}
