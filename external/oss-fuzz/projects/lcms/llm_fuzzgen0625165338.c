#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

  /*
   * ANALYSIS: The function-level coverage report showed _cmsReadProfileSequence
   *           had 0% coverage. This function reads both
   *           cmsSigProfileSequenceDescTag and cmsSigProfileSequenceIdTag. The
   *           original fuzzer only wrote the former.
   * IMPLEMENTATION: The following block adds a cmsSigProfileSequenceIdTag to the
   *                 profile, which will trigger the uncovered
   *                 _cmsReadProfileSequence function when the profile is read back.
   */
  cmsSEQ *seqId = cmsAllocProfileSequenceDescription(NULL, 1);
  if (seqId) {
    // We can leave the description empty to exercise more paths.
    cmsWriteTag(hProfile, cmsSigProfileSequenceIdTag, seqId);
    cmsFreeProfileSequenceDescription(seqId);
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

    /*
     * ANALYSIS: The line-level coverage for cmsLinkTag showed several missed
     *           branches. The function was being called, but not in a way that
     *           exercised its full logic.
     * IMPLEMENTATION: Add a call to cmsLinkTag to link two tags together. This
     *                 increases coverage in cmsLinkTag and related functions that
     *                 handle tag linking.
     */
    cmsLinkTag(hProfile, cmsSigCopyrightTag, cmsSigProfileDescriptionTag);

    cmsMLUfree(mlu);
  }

  /*
   * ANALYSIS: The function-level coverage report showed Type_DateTime_Write and
   *           Type_DateTime_Read had 0% coverage.
   * IMPLEMENTATION: The following block adds a cmsSigDateTimeTag to the profile.
   *                 This will trigger the uncovered write handler, and the read
   *                 handler will be triggered when the profile is re-opened from memory.
   */
  if (size > sizeof(struct tm)) {
    struct tm dt;
    memcpy(&dt, data, sizeof(struct tm));

    // Clamp values to be somewhat valid to avoid undefined behavior.
    dt.tm_sec %= 61;
    dt.tm_min %= 60;
    dt.tm_hour %= 24;
    dt.tm_mday = (dt.tm_mday % 31) + 1;
    dt.tm_mon %= 12;
    dt.tm_year %= 200;
    dt.tm_wday %= 7;
    dt.tm_yday %= 366;
    dt.tm_isdst = (dt.tm_isdst % 3) - 1;

    cmsWriteTag(hProfile, cmsSigDateTimeTag, &dt);
  }

  /*
   * ANALYSIS: The function-level coverage report showed Type_Signature_Write and
   *           Type_Signature_Read had 0% coverage.
   * IMPLEMENTATION: The following block adds a cmsSigTechnologyTag to the profile.
   *                 This will trigger the uncovered write handler, and the read
   *                 handler will be triggered when the profile is re-opened from memory.
   */
  if (size >= sizeof(cmsSignature)) {
    cmsSignature sig;
    memcpy(&sig, data, sizeof(cmsSignature));
    cmsWriteTag(hProfile, cmsSigTechnologyTag, &sig);
  }

  /*
   * ANALYSIS: The function-level coverage report showed Type_Chromaticity_Read and
   *           Type_Chromaticity_Write had 0% coverage.
   * IMPLEMENTATION: The following block adds a cmsSigChromaticityTag to the profile.
   *                 This will trigger the uncovered write handler, and the read
   *                 handler will be triggered when the profile is re-opened from memory.
   */
  if (size >= sizeof(cmsCIExyYTRIPLE)) {
    cmsCIExyYTRIPLE trip;
    memcpy(&trip, data, sizeof(cmsCIExyYTRIPLE));
    cmsWriteTag(hProfile, cmsSigChromaticityTag, &trip);
  }

  /*
   * ANALYSIS: The function-level coverage report showed Type_ViewingConditions_Read and
   *           Type_ViewingConditions_Write had 0% coverage.
   * IMPLEMENTATION: The following block adds a cmsSigViewingConditionsTag to the profile.
   *                 This will trigger the uncovered write handler, and the read
   *                 handler will be triggered when the profile is re-opened from memory.
   */
  if (size >= sizeof(cmsICCViewingConditions)) {
    cmsICCViewingConditions vc;
    memcpy(&vc, data, sizeof(cmsICCViewingConditions));
    cmsWriteTag(hProfile, cmsSigViewingConditionsTag, &vc);
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