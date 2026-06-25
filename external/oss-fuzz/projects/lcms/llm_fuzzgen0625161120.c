#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

// Target profile sequence and text description tag handlers
#define _FUZZ_TARGET_NAME "llm_fuzz_cms_pseq_text"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a placeholder profile.
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (!hProfile) {
    return 0;
  }

  // --- Add profileSequenceDescType Tag ---
  cmsSEQ *seq = cmsAllocProfileSequenceDescription(NULL, 1);
  if (seq) {
    // Use a portion of the data for the description text.
    if (size > 10) {
      seq->seq[0].Description = cmsMLUalloc(NULL, 1);
      if (seq->seq[0].Description) {
        // Create a null-terminated string from the first half of the data.
        size_t first_half_size = size / 2;
        char *first_half_str = (char *)malloc(first_half_size + 1);
        if (first_half_str) {
          memcpy(first_half_str, data, first_half_size);
          first_half_str[first_half_size] = '\0';
          cmsMLUsetASCII(seq->seq[0].Description, "en", "US", first_half_str);
          free(first_half_str);
        }
      }
    }
    // Write the sequence description tag.
    cmsWriteTag(hProfile, cmsSigProfileSequenceDescTag, seq);
    cmsFreeProfileSequenceDescription(seq);
  }

  // --- Add textDescriptionType Tag ---
  cmsMLU *mlu = cmsMLUalloc(NULL, 1);
  if (mlu) {
    // Create a null-terminated string from the second half of the data.
    size_t first_half_size = size / 2;
    const uint8_t *second_half_data = data + first_half_size;
    size_t second_half_size = size - first_half_size;
    char *second_half_str = (char *)malloc(second_half_size + 1);
    if (second_half_str) {
      memcpy(second_half_str, second_half_data, second_half_size);
      second_half_str[second_half_size] = '\0';
      cmsMLUsetASCII(mlu, "en", "US", second_half_str);
      free(second_half_str);
    }
    cmsWriteTag(hProfile, cmsSigProfileDescriptionTag, mlu);
    cmsMLUfree(mlu);
  }

  // --- Save and Re-open Profile ---
  unsigned char *buffer = NULL;
  cmsUInt32Number bytes_needed = 0;
  // Use cmsSaveProfileToMem with NULL to get the required size.
  cmsSaveProfileToMem(hProfile, NULL, &bytes_needed);

  if (bytes_needed > 0) {
    buffer = (unsigned char *)malloc(bytes_needed);
    if (buffer) {
      if (cmsSaveProfileToMem(hProfile, buffer, &bytes_needed)) {
        // Now, open the profile from the buffer to exercise read handlers.
        cmsHPROFILE hReadProfile = cmsOpenProfileFromMem(buffer, bytes_needed);
        if (hReadProfile) {
          cmsCloseProfile(hReadProfile);
        }
      }
      free(buffer);
    }
  }

  // Clean up the profile handle.
  cmsCloseProfile(hProfile);

  return 0;
}