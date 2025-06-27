// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy

// Include necessary zlib headers with full project-relative paths
// Include fundamental headers first for type and macro definitions
#include "/src/zlib/zconf.h"
#include "/src/zlib/zutil.h"
#include "/src/zlib/inftrees.h" // Defines code and ENOUGH
#include "/src/zlib/zlib.h"
#include "/src/zlib/crc32.h"
#include "/src/zlib/inflate.h"


// Define internal functions for direct testing (assuming they are accessible)
// These signatures are based on the API Information and coverage report.
// Note: In a real scenario, calling internal functions might require careful
// consideration of their dependencies and state. For fuzzing purposes,
// we attempt to call them directly if their inputs are simple.
// Removed declarations and calls to byte_swap and crc_word_big as they are internal 'local' functions.
// Removed declaration and call to crc32_combine_op as it was causing timeouts.
// uLong ZEXPORT crc32_combine_op(uLong, uLong, uLong); // Removed

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const uint8_t *data_ptr = Data;
  size_t data_remaining = Size;

  // Helper to consume data safely
  // Ensure type is known before using sizeof
  #define CONSUME_DATA(type, var) \
    type var = 0; \
    if (data_remaining >= sizeof(type)) { \
      memcpy(&var, data_ptr, sizeof(type)); \
      data_ptr += sizeof(type); \
      data_remaining -= sizeof(type); \
    } else { \
      /* Not enough data, var remains 0 */ \
    }

  // Removed call to crc32_combine_op due to timeout issues.

  // 4. Call inflateSyncPoint
  // Requires z_streamp strm. Needs initialization and cleanup.
  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;

  // inflateInit2_ allocates the state
  // Use MAX_WBITS for the windowBits parameter as Z_DEFAULT_WINDOWBITS is not defined.
  if (inflateInit2_(&strm, MAX_WBITS, ZLIB_VERSION, sizeof(z_stream)) == Z_OK) {
    // Call inflateSyncPoint
    inflateSyncPoint(&strm);

    // inflateEnd frees the state
    inflateEnd(&strm);
  }


  // 5. Call uncompress2
  // Requires dest buffer, destLen, source buffer, sourceLen
  if (data_remaining > 0) {
    uLong sourceLen = (uLong)data_remaining;
    const Bytef *source = data_ptr;

    // Allocate destination buffer (e.g., twice the source size + some margin)
    uLongf destLen = sourceLen * 2 + 100;
    Bytef *dest = (Bytef *)malloc(destLen);

    if (dest != NULL) {
      // Call uncompress2
      uncompress2(dest, &destLen, source, &sourceLen); // uncompress2 takes a pointer to sourceLen

      // Free destination buffer
      free(dest);
    }
  }

  return 0;
}