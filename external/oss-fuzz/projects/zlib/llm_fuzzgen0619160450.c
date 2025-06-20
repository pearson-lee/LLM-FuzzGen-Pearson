#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/zlib/zlib.h"

// The fuzzer entry point.
// It takes a buffer of data and its size as input.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to be used with gzdopen.
    FILE *tmp = tmpfile();
    if (!tmp) {
        return 0;
    }
    int fd = fileno(tmp);

    // The mode for gzdopen is determined by the first byte of the input data.
    const char *mode = (data[0] % 2 == 0) ? "rb" : "wb";
    data++;
    size--;

    // Open the temporary file as a gzFile.
    gzFile file = gzdopen(fd, mode);
    if (file == NULL) {
        fclose(tmp);
        return 0;
    }

    // Consume the fuzzer data to exercise the target APIs.
    if (size > 0) {
        // Use one byte to decide which API to call.
        uint8_t api_selector = data[0];
        data++;
        size--;

        switch (api_selector % 4) {
        case 0:
            // Call gzputc with the remaining data.
            for (size_t i = 0; i < size; ++i) {
                gzputc(file, data[i]);
            }
            break;
        case 1:
            // Call gzputs with the remaining data as a string.
            // The data is not null-terminated, so we create a null-terminated string.
            if (size > 0) {
                char *str = (char *)malloc(size + 1);
                if (str) {
                    memcpy(str, data, size);
                    str[size] = '\0';
                    gzputs(file, str);
                    free(str);
                }
            }
            break;
        case 2:
            // Call gzgets to read a line from the file.
            // First, write the data to the file.
            if (size > 0) {
                gzwrite(file, data, size);
                gzrewind(file);
                char *buf = (char *)malloc(size);
                if (buf) {
                    gzgets(file, buf, size);
                    free(buf);
                }
            }
            break;
        case 3:
            // Call gzseek to move the file pointer.
            if (size > 0) {
                // Use one byte for the offset and one for the whence.
                off_t offset = (off_t)data[0];
                int whence = data[1 % size];
                data += 2;
                size -= 2;
                gzseek(file, offset, whence);
            }
            break;
        }
    }

    // Close the gzFile. This also closes the underlying file descriptor.
    gzclose(file);

    return 0;
}