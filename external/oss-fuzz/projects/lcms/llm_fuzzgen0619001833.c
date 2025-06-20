#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"

// The maximum length for strings consumed from the fuzzer input.
#define MAX_STR_LEN 256

// This fuzz target focuses on the IT8 file parsing functionality in lcms,
// which is primarily located in the cmscgats.c file. This file has very
// low coverage and deals with complex data parsing, making it a good
// candidate for fuzzing.
//
// The fuzzer will:
// 1. Attempt to load an IT8 handle from the fuzzer data using
//    cmsIT8LoadFromMem.
// 2. If successful, it will use the remaining fuzzer data to call various
//    uncovered functions that operate on the IT8 handle, such as
//    cmsIT8SetPropertyMulti, cmsIT8GetDataDbl, cmsIT8GetPatchName, and
//    cmsIT8EnumProperties.
//
// This approach ensures that both the parsing and the subsequent data
// manipulation logic within the IT8 module are exercised.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a lcms context. This is required for most lcms operations.
  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  // Split the input data. The first half will be used to create the IT8
  // handle, and the second half will be used to generate arguments for the
  // other API calls.
  size_t it8_size = size / 2;
  const uint8_t *it8_data = data;
  const uint8_t *remaining_data = data + it8_size;
  size_t remaining_size = size - it8_size;

  // Target API 1: cmsIT8LoadFromMem
  // Attempt to load an IT8 handle from the first part of the fuzzer data.
  cmsHANDLE hIT8 = cmsIT8LoadFromMem(context, it8_data, it8_size);

  if (hIT8) {
    // If the IT8 handle was created successfully, proceed to call other
    // related APIs.

    // Added call to uncovered function cmsIT8SetComment based on coverage report.
    if (remaining_size > 1) {
      size_t len = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len) {
        char comment[MAX_STR_LEN];
        memcpy(comment, remaining_data, len);
        comment[len] = '\0';
        cmsIT8SetComment(hIT8, comment);
        remaining_data += len;
        remaining_size -= len;
      }
    }

    // Added call to uncovered function cmsIT8SetPropertyDbl based on coverage report.
    if (remaining_size > sizeof(double) + 1) {
      size_t len = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len + sizeof(double)) {
        char key[MAX_STR_LEN];
        memcpy(key, remaining_data, len);
        key[len] = '\0';
        remaining_data += len;
        remaining_size -= len;
        cmsIT8SetPropertyDbl(hIT8, key, *(double *)remaining_data);
        remaining_data += sizeof(double);
        remaining_size -= sizeof(double);
      }
    }

    // Target API 2: cmsIT8SetPropertyMulti
    // This function has 0% coverage and is a good candidate for finding bugs
    // related to string handling and memory management.
    if (remaining_size > 3) {
      // Consume bytes from the remaining data to create null-terminated strings
      // for the function arguments.
      size_t len1 = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len1) {
        char key[MAX_STR_LEN];
        memcpy(key, remaining_data, len1);
        key[len1] = '\0';
        remaining_data += len1;
        remaining_size -= len1;

        if (remaining_size > 2) {
          size_t len2 = remaining_data[0] % (MAX_STR_LEN - 1);
          remaining_data++;
          remaining_size--;
          if (remaining_size > len2) {
            char subkey[MAX_STR_LEN];
            memcpy(subkey, remaining_data, len2);
            subkey[len2] = '\0';
            remaining_data += len2;
            remaining_size -= len2;

            if (remaining_size > 1) {
              size_t len3 = remaining_data[0] % (MAX_STR_LEN - 1);
              remaining_data++;
              remaining_size--;
              if (remaining_size > len3) {
                char value[MAX_STR_LEN];
                memcpy(value, remaining_data, len3);
                value[len3] = '\0';
                cmsIT8SetPropertyMulti(hIT8, key, subkey, value);
              }
            }
          }
        }
      }
    }

    // Target API 3: cmsIT8GetDataDbl
    // This function also has 0% coverage and tests data retrieval and type
    // conversion.
    if (remaining_size > 2) {
      size_t len1 = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len1) {
        char patch[MAX_STR_LEN];
        memcpy(patch, remaining_data, len1);
        patch[len1] = '\0';
        remaining_data += len1;
        remaining_size -= len1;

        if (remaining_size > 1) {
          size_t len2 = remaining_data[0] % (MAX_STR_LEN - 1);
          remaining_data++;
          remaining_size--;
          if (remaining_size > len2) {
            char sample[MAX_STR_LEN];
            memcpy(sample, remaining_data, len2);
            sample[len2] = '\0';
            cmsIT8GetDataDbl(hIT8, patch, sample);
          }
        }
      }
    }

    // Target API 4: cmsIT8GetPatchName
    // This function has 0% coverage and tests patch name lookup.
    if (remaining_size > sizeof(uint32_t)) {
      char patch_name[MAX_STR_LEN];
      cmsIT8GetPatchName(hIT8, *(uint32_t *)remaining_data, patch_name);
    }

    // Target API 5: cmsIT8EnumProperties
    // This function has 0% coverage and exercises property enumeration.
    char **propertyNames;
    cmsIT8EnumProperties(hIT8, &propertyNames);

    // Added call to uncovered function cmsIT8SetPropertyStr based on coverage report.
    if (remaining_size > 2) {
      size_t len1 = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len1) {
        char key[MAX_STR_LEN];
        memcpy(key, remaining_data, len1);
        key[len1] = '\0';
        remaining_data += len1;
        remaining_size -= len1;

        if (remaining_size > 1) {
          size_t len2 = remaining_data[0] % (MAX_STR_LEN - 1);
          remaining_data++;
          remaining_size--;
          if (remaining_size > len2) {
            char value[MAX_STR_LEN];
            memcpy(value, remaining_data, len2);
            value[len2] = '\0';
            cmsIT8SetPropertyStr(hIT8, key, value);
          }
        }
      }
    }

    // Added call to uncovered function cmsIT8SetPropertyHex based on coverage report.
    if (remaining_size > sizeof(cmsUInt32Number) + 1) {
      size_t len = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len + sizeof(cmsUInt32Number)) {
        char key[MAX_STR_LEN];
        memcpy(key, remaining_data, len);
        key[len] = '\0';
        remaining_data += len;
        remaining_size -= len;
        cmsIT8SetPropertyHex(hIT8, key, *(cmsUInt32Number *)remaining_data);
        remaining_data += sizeof(cmsUInt32Number);
        remaining_size -= sizeof(cmsUInt32Number);
      }
    }

    // Added call to uncovered function cmsIT8GetProperty based on coverage report.
    if (remaining_size > 1) {
      size_t len = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len) {
        char key[MAX_STR_LEN];
        memcpy(key, remaining_data, len);
        key[len] = '\0';
        cmsIT8GetProperty(hIT8, key);
      }
    }

    // Added call to uncovered function cmsIT8TableCount based on coverage report.
    cmsIT8TableCount(hIT8);

    // Added call to uncovered function cmsIT8GetPatchByName based on coverage report.
    if (remaining_size > 1) {
      size_t len = remaining_data[0] % (MAX_STR_LEN - 1);
      remaining_data++;
      remaining_size--;
      if (remaining_size > len) {
        char patch_name[MAX_STR_LEN];
        memcpy(patch_name, remaining_data, len);
        patch_name[len] = '\0';
        cmsIT8GetPatchByName(hIT8, patch_name);
      }
    }

    // Added call to uncovered function cmsIT8SaveToMem based on coverage report.
    // This also improves memory safety by ensuring the allocated buffer is freed.
    cmsUInt32Number bytes_needed = 0;
    cmsIT8SaveToMem(hIT8, NULL, &bytes_needed);
    if (bytes_needed > 0) {
      void *buffer = malloc(bytes_needed);
      if (buffer) {
        cmsIT8SaveToMem(hIT8, buffer, &bytes_needed);
        free(buffer);
      }
    }

    // Clean up the IT8 handle to prevent memory leaks.
    cmsIT8Free(hIT8);
  }

  // Clean up the lcms context.
  cmsDeleteContext(context);
  return 0;
}