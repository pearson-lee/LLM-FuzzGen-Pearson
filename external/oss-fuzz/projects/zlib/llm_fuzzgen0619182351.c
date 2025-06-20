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
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Create a temporary file to write the fuzzing data to.
  char filename[] = "/tmp/fuzz-XXXXXX";
  int fd = mkstemp(filename);
  if (fd < 0) {
    return 0;
  }

  // Write the fuzzing data to the temporary file.
  ssize_t written = write(fd, data, size);
  if (written != (ssize_t)size) {
    close(fd);
    unlink(filename);
    return 0;
  }
  close(fd);

  // Open the temporary file with gzopen.
  gzFile file = gzopen(filename, "rb");
  if (file == NULL) {
    unlink(filename);
    return 0;
  }

  // Consume the first byte of the input data to determine the operations.
  uint8_t operations = data[0];
  size_t data_offset = 1;

  // Perform a series of operations based on the consumed byte.
  if (operations & 0x01 && size > data_offset + sizeof(long)) {
    long offset = 0;
    memcpy(&offset, data + data_offset, sizeof(long));
    data_offset += sizeof(long);
    gzseek(file, offset, SEEK_SET);
  }

  if (operations & 0x02) {
    gzgetc(file);
  }

  if (operations & 0x04 && size > data_offset) {
    gzungetc(data[data_offset++], file);
  }

  if (operations & 0x08) {
    char buffer[256];
    gzgets(file, buffer, sizeof(buffer));
  }

  if (operations & 0x10) {
    gzdirect(file);
  }

  // Close the gzFile and remove the temporary file.
  // This is a crucial step to prevent resource leaks.
  gzclose(file);
  unlink(filename);

  return 0;
}