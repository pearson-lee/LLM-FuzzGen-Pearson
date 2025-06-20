#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#include "/src/zlib/zlib.h"

// The fuzzer targets the following functions, which have low coverage:
// - gzseek (which calls the uncovered gz_skip)
// - gzungetc
// - gzgetc
// - gzgets
// - gzdirect
// New targets based on coverage analysis:
// - gzputc, gzputs, gzflush (from gzwrite.c)
// - adler32, crc32 (from adler32.c, crc32.c)
// - gzrewind (from gzlib.c)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) { // Increased minimum size for more operations
    return 0;
  }

  // Create a temporary file to write the fuzzing data to.
  char filename[] = "/tmp/fuzz-XXXXXX";
  int fd = mkstemp(filename);
  if (fd < 0) {
    return 0;
  }

  // Write the fuzzing data to the temporary file, reserving the first few bytes for operations.
  ssize_t written = write(fd, data + 4, size - 4);
  if (written != (ssize_t)(size - 4)) {
    close(fd);
    unlink(filename);
    return 0;
  }
  close(fd);

  // Consume bytes from the input data to determine the operations.
  uint8_t operations = data[0];
  uint8_t mode_selector = data[1];
  size_t data_offset = 4;

  // Added checksum calculations to cover adler32 and crc32 functions.
  if (size > data_offset) {
      uLong adler = adler32(0L, Z_NULL, 0);
      adler32(adler, data + data_offset, size - data_offset);
      uLong crc = crc32(0L, Z_NULL, 0);
      crc32(crc, data + data_offset, size - data_offset);
  }

  // Decide whether to test reading or writing based on an input byte.
  if (mode_selector % 2 == 0) {
    // Test writing functions (gzputc, gzputs, etc.) which were previously uncovered.
    gzFile file = gzopen(filename, "wb");
    if (file == NULL) {
      unlink(filename);
      return 0;
    }

    // Added call to gzputc to improve coverage in gzwrite.c.
    if ((operations & 0x01) && size > data_offset) {
      gzputc(file, data[data_offset++]);
    }

    // Added call to gzputs to improve coverage in gzwrite.c.
    if ((operations & 0x02) && size > data_offset) {
      size_t puts_len = size - data_offset;
      char *puts_buf = (char *)malloc(puts_len + 1);
      if (!puts_buf) {
        gzclose(file);
        unlink(filename);
        return 0;
      }
      memcpy(puts_buf, data + data_offset, puts_len);
      puts_buf[puts_len] = '\0';
      gzputs(file, puts_buf);
      free(puts_buf);
    }

    // Added call to gzflush to cover flushing logic.
    if (operations & 0x04) {
        int flush_mode = data[2] % 5; // Valid flush modes are 0-4
        gzflush(file, flush_mode);
    }

    gzclose(file);

  } else {
    // Test reading functions
    gzFile file = gzopen(filename, "rb");
    if (file == NULL) {
      unlink(filename);
      return 0;
    }

    // Reordered gzungetc before gzgetc to improve coverage of gzgetc's internal buffer handling.
    if ((operations & 0x04) && size > data_offset) {
      gzungetc(data[data_offset++], file);
    }

    if (operations & 0x02) {
      gzgetc(file);
    }

    if ((operations & 0x01) && size > data_offset + sizeof(long)) {
      long offset = 0;
      memcpy(&offset, data + data_offset, sizeof(long));
      data_offset += sizeof(long);
      gzseek(file, offset, SEEK_SET);
    }

    if (operations & 0x08) {
      char buffer[256];
      gzgets(file, buffer, sizeof(buffer));
    }

    if (operations & 0x10) {
      gzdirect(file);
    }
    
    // Added call to gzrewind to improve coverage.
    if (operations & 0x20) {
        gzrewind(file);
    }

    gzclose(file);
  }

  // This is a crucial step to prevent resource leaks.
  unlink(filename);

  return 0;
}