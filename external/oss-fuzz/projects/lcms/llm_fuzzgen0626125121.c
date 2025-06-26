#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the main lcms header and the internal header for access to internal APIs.
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

// A helper structure to safely consume data from the fuzzer input buffer.
typedef struct {
  const uint8_t *data;
  size_t size;
} FuzzData;

// Helper functions to safely consume different data types from the fuzzer input.
static int consume_bytes(FuzzData *fd, void *dest, size_t len) {
  if (fd->size < len) {
    return 0;
  }
  memcpy(dest, fd->data, len);
  fd->data += len;
  fd->size -= len;
  return 1;
}

static int consume_u32(FuzzData *fd, uint32_t *val) {
  return consume_bytes(fd, val, sizeof(uint32_t));
}

static int consume_u64(FuzzData *fd, uint64_t *val) {
  return consume_bytes(fd, val, sizeof(uint64_t));
}

// Consumes a length-prefixed string from the fuzzer input.
static char *consume_string(FuzzData *fd) {
  if (fd->size < 1) {
    return NULL;
  }
  uint8_t str_len = fd->data[0];
  fd->data++;
  fd->size--;

  if (fd->size < str_len) {
    return NULL;
  }

  char *str = (char *)malloc(str_len + 1);
  if (!str) {
    return NULL;
  }
  memcpy(str, fd->data, str_len);
  str[str_len] = '\0';
  fd->data += str_len;
  fd->size -= str_len;
  return str;
}

// Fuzz target entry point.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzData fuzz_data = {Data, Size};

  // Create a Little CMS context.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return 0;
  }

  // Consume data to determine the number of sequences to create.
  // Limit to a reasonable number to avoid excessive allocations.
  uint32_t n_sequences;
  if (!consume_u32(&fuzz_data, &n_sequences)) {
    cmsDeleteContext(ctx);
    return 0;
  }
  n_sequences %= 5;

  // Allocate a profile sequence description structure.
  cmsSEQ *seq = cmsAllocProfileSequenceDescription(ctx, n_sequences);
  if (!seq) {
    cmsDeleteContext(ctx);
    return 0;
  }

  // Populate the sequence description with data from the fuzzer.
  for (uint32_t i = 0; i < n_sequences; i++) {
    cmsPSEQDESC *pseq = &seq->seq[i];
    consume_u32(&fuzz_data, &pseq->deviceMfg);
    consume_u32(&fuzz_data, &pseq->deviceModel);
    consume_u64(&fuzz_data, &pseq->attributes);
    consume_u32(&fuzz_data, &pseq->technology);
    consume_bytes(&fuzz_data, &pseq->ProfileID, sizeof(cmsProfileID));

    // Allocate and populate MLU (Multi-Localized Unicode) objects for text fields.
    pseq->Manufacturer = cmsMLUalloc(ctx, 1);
    pseq->Model = cmsMLUalloc(ctx, 1);
    pseq->Description = cmsMLUalloc(ctx, 1);

    char *str = consume_string(&fuzz_data);
    if (str && pseq->Manufacturer) {
      cmsMLUsetASCII(pseq->Manufacturer, "en", "US", str);
      free(str);
    }
    str = consume_string(&fuzz_data);
    if (str && pseq->Model) {
      cmsMLUsetASCII(pseq->Model, "en", "US", str);
      free(str);
    }
    str = consume_string(&fuzz_data);
    if (str && pseq->Description) {
      cmsMLUsetASCII(pseq->Description, "en", "US", str);
      free(str);
    }
  }

  // Create a placeholder profile to write the tags to.
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(ctx);
  if (!hProfile) {
    cmsFreeProfileSequenceDescription(seq);
    cmsDeleteContext(ctx);
    return 0;
  }

  // Write the sequence description to the profile. This exercises _cmsWriteProfileSequence.
  if (_cmsWriteProfileSequence(hProfile, seq)) {
    // If writing was successful, try to read it back to exercise _cmsReadProfileSequence.
    cmsSEQ *read_seq = _cmsReadProfileSequence(hProfile);
    if (read_seq) {
      // Free the newly allocated sequence object.
      cmsFreeProfileSequenceDescription(read_seq);
    }
  }

  // Clean up all allocated resources to prevent memory leaks.
  cmsCloseProfile(hProfile);
  cmsFreeProfileSequenceDescription(seq);
  cmsDeleteContext(ctx);

  return 0;
}