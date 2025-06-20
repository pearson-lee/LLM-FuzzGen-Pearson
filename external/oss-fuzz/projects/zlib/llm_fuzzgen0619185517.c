#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

// Fuzz target for gzsetparams, deflateBound, gzwrite, gzread, and gzclose.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to write to and read from.
    char filename[256];
    sprintf(filename, "/tmp/fuzz-XXXXXX");
    int fd = mkstemp(filename);
    if (fd < 0) {
        return 0;
    }
    close(fd);

    // Open the file for writing.
    gzFile file = gzopen(filename, "wb");
    if (file == NULL) {
        remove(filename);
        return 0;
    }

    // Set compression parameters.
    // The level and strategy are chosen based on the first byte of the input data.
    int level = data[0] % 10;
    int strategy = data[0] % 5;
    gzsetparams(file, level, strategy);

    // Write the rest of the data to the file.
    gzwrite(file, data + 1, size - 1);

    // Close the file.
    gzclose(file);

    // Open the file for reading.
    file = gzopen(filename, "rb");
    if (file == NULL) {
        remove(filename);
        return 0;
    }

    // Read the data back from the file.
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        gzclose(file);
        remove(filename);
        return 0;
    }
    gzread(file, buffer, size - 1);

    // Get the deflate bound.
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    deflateInit(&strm, level);
    deflateBound(&strm, size);
    deflateEnd(&strm);

    // Clean up.
    free(buffer);
    gzclose(file);
    remove(filename);

    return 0;
}