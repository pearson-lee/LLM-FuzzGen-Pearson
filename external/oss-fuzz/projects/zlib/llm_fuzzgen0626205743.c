// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // Required for fileno, SEEK_SET, SEEK_CUR, SEEK_END

// Include necessary zlib headers
#include "/src/zlib/zlib.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/gzguts.h" // For gz_statep and z_off64_t

// Define a dummy file descriptor for gzdopen when we want to test the error path
// In a real fuzzer, you might use a temporary file or a pipe, but for testing
// the negative fd path of gzdopen, a simple negative number is sufficient.
#define DUMMY_NEGATIVE_FD -1

// Fuzz target entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Call a simple utility function with low coverage
  zlibCompileFlags();

  // Ensure we have enough data for basic operations
  if (Size < 4) {
    return 0;
  }

  // Use the first byte to decide which main path to take
  uint8_t action = Data[0];
  Data++;
  Size--;

  // Use the next byte to determine the file descriptor or mode
  int fd = DUMMY_NEGATIVE_FD; // Default to negative to hit the error path
  if (Size >= sizeof(int)) {
      memcpy(&fd, Data, sizeof(int));
      Data += sizeof(int);
      Size -= sizeof(int);
  } else if (Size > 0) {
      // Use remaining bytes to influence the fd if not enough for a full int
      for (size_t i = 0; i < Size; ++i) {
          fd = (fd << 8) | Data[i];
      }
      Data += Size;
      Size = 0;
  }

  // Simple mode selection based on remaining data
  const char *mode = "rb"; // Default mode
  if (Size > 0) {
      switch (action % 4) {
          case 0: mode = "rb"; break;
          case 1: mode = "wb"; break;
          case 2: mode = "r"; break;
          case 3: mode = "w"; break;
      }
  }

  // Test gzdopen, including the negative fd path identified by coverage analysis
  gzFile file = gzdopen(fd, mode);

  // If gzdopen was successful, exercise other gz* functions
  if (file != NULL) {
    // Cast to internal state pointer to call internal functions like gzgetc_
    // This is generally discouraged in production code but acceptable in a fuzzer
    // to reach specific low-level functions.
    // gz_statep state = (gz_statep)file; // Not needed if calling public API like gzseek64

    // Exercise gzgetc_
    if (Size > 0) {
        gzgetc_(file);
        // Consume 1 byte if gzgetc_ was called, though it doesn't use input data directly
        // This is just to advance the data pointer for subsequent calls.
        Data++;
        Size--;
    }

    // Exercise gzseek64 (instead of gz_skip)
    // Need enough data for offset (z_off64_t) and whence (int, using 1 byte)
    if (Size >= sizeof(z_off64_t) + 1) {
        z_off64_t offset;
        memcpy(&offset, Data, sizeof(z_off64_t));
        Data += sizeof(z_off64_t);
        Size -= sizeof(z_off64_t);

        int whence = SEEK_SET; // Default whence
        // Use the next byte for whence (modulo 3 for SEEK_SET, SEEK_CUR, SEEK_END)
        whence = Data[0] % 3;
        if (whence == 1) whence = SEEK_CUR;
        else if (whence == 2) whence = SEEK_END;
        else whence = SEEK_SET; // 0 maps to SEEK_SET

        Data++;
        Size--;

        gzseek64(file, offset, whence);

    } else if (Size >= sizeof(z_off64_t)) {
         // Enough data for offset but not for whence, use default whence
        z_off64_t offset;
        memcpy(&offset, Data, sizeof(z_off64_t));
        Data += sizeof(z_off64_t);
        Size -= sizeof(z_off64_t);

        int whence = SEEK_SET; // Default whence

        gzseek64(file, offset, whence);

    } else if (Size > 0) {
         // Not enough data for a full z_off64_t, use remaining bytes for offset
        z_off64_t offset = 0;
        for (size_t i = 0; i < Size; ++i) {
            offset = (offset << 8) | Data[i];
        }
        // No data left for whence, use default
        int whence = SEEK_SET;

        gzseek64(file, offset, whence);

        Data += Size; // Consume remaining data
        Size = 0;
    }


    // Exercise gzfread
    if (Size > 0) {
      uInt read_size = (uInt)(Size > 1024 ? 1024 : Size); // Limit read size
      void *buffer = malloc(read_size);
      if (buffer) {
        gzfread(buffer, 1, read_size, file);
        free(buffer);
      }
      // Consume data used for gzfread buffer content (though gzfread reads from file)
      // This is just to advance the data pointer for subsequent calls.
      Data += read_size;
      Size -= read_size;
    }

    // Exercise gzfwrite
    if (Size > 0) {
      // Limit write size to prevent timeouts in compression
      uInt write_size = (uInt)(Size > 128 ? 128 : Size); // Reduced limit
      // Use remaining input data as the buffer to write
      gzfwrite(Data, 1, write_size, file);
      Data += write_size;
      Size -= write_size;
    }

    // Close the gzFile to free resources
    gzclose(file);
  }

  // Note: crc32_combine_op and _tr_tally are internal helper functions
  // that are difficult to call directly without setting up complex zlib
  // internal states (like deflate_state or inflate_state). Fuzzing them
  // effectively usually requires reaching them through public API calls
  // like deflate() or inflate(). The selected gz* functions and zlibCompileFlags
  // provide a more accessible set of low-coverage targets for a simple fuzzer.

  return 0;
}