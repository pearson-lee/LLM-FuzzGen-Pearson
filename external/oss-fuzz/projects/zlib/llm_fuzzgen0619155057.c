#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  char filename[] = "/tmp/fuzz-XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) {
    return 0;
  }
  close(fd);

  gzFile file = gzopen(filename, "wb");
  if (file == NULL) {
    unlink(filename);
    return 0;
  }

  // Parameters from fuzzer data
  int level = (int)(data[0] % 11) - 1; // -1 to 9
  int strategy = (int)(data[1] % 5);   // 0 to 4
  int flush = (int)(data[2] % 6);      // 0 to 5
  size_t write_size = data[3];
  const uint8_t *write_data = data + 4;
  size_t remaining_size = size - 4;

  if (write_size > remaining_size) {
    write_size = remaining_size;
  }

  gzsetparams(file, level, strategy);

  if (write_size > 0) {
    gzfwrite(write_data, 1, write_size, file);
  }

  gzflush(file, flush);
  gzclose(file);
  unlink(filename);

  return 0;
}