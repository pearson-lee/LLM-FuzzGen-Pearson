#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

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
// - compress, uncompress (from compress.c, uncompr.c)
// - adler32_combine, crc32_combine (from adler32.c, crc32.c)
// - gzeof, gzerror, gzclearerr (from gzlib.c)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) { // Increased minimum size for more operations
    return 0;
  }

  // Added calls to compress and uncompress to improve coverage.
  uLong comprLen = compressBound(size);
  uLong uncomprLen = size;
  Byte *compr = (Byte*)malloc(comprLen);
  Byte *uncompr = (Byte*)malloc(uncomprLen);

  if (!compr || !uncompr) {
    free(compr);
    free(uncompr);
    return 0;
  }

  if (compress(compr, &comprLen, data, size) == Z_OK) {
    // Ensure that uncompressing the compressed data gives back the original data.
    if (uncompress(uncompr, &uncomprLen, compr, comprLen) == Z_OK) {
      assert(size == uncomprLen);
      assert(memcmp(data, uncompr, size) == 0);
    }
  }
  free(compr);
  free(uncompr);


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

  // Added checksum calculations to cover adler32_combine and crc32_combine functions.
  if (size > 8) {
      size_t half_size = (size - data_offset) / 2;
      uLong adler1 = adler32(0L, Z_NULL, 0);
      adler1 = adler32(adler1, data + data_offset, half_size);
      uLong adler2 = adler32(0L, Z_NULL, 0);
      adler2 = adler32(adler2, data + data_offset + half_size, size - data_offset - half_size);
      adler32_combine(adler1, adler2, size - data_offset - half_size);

      uLong crc1 = crc32(0L, Z_NULL, 0);
      crc1 = crc32(crc1, data + data_offset, half_size);
      uLong crc2 = crc32(0L, Z_NULL, 0);
      crc2 = crc32(crc2, data + data_offset + half_size, size - data_offset - half_size);
      crc32_combine(crc1, crc2, size - data_offset - half_size);
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

    // Added calls to gzeof, gzerror, and gzclearerr to improve coverage.
    if (operations & 0x40) {
        gzeof(file);
        int errnum = 0;
        gzerror(file, &errnum);
        gzclearerr(file);
    }

    gzclose(file);
  }

  // This is a crucial step to prevent resource leaks.
  unlink(filename);

  return 0;
}