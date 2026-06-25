#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

// FuzzedDataProvider is not available in C, so we'll use the raw data.
// Helper function to get data from the fuzzing input
static void *get_data(const uint8_t **data, size_t *size, size_t len) {
  if (*size < len) {
    return NULL;
  }
  void *ret = malloc(len);
  if (ret == NULL) {
    return NULL;
  }
  memcpy(ret, *data, len);
  *data += len;
  *size -= len;
  return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a context
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  // Create a placeholder profile
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(ctx);
  if (hProfile == NULL) {
    cmsDeleteContext(ctx);
    return 0;
  }

  /*
   * ANALYSIS: The function cmsWriteTag has several uncovered branches related to
   *           handling different tag types. Many of the underlying Type_*_Write
   *           functions in cmstypes.c have 0% coverage.
   * IMPLEMENTATION: We will write a tag with a fuzzer-driven type and data.
   *                 This will allow the fuzzer to explore the various tag
   *                 writing handlers that are currently uncovered.
   */
  cmsTagSignature tag_sig = (cmsTagSignature)size; // Use size as a pseudo-random tag
  void *tag_data = get_data(&data, &size, size);
  if (tag_data != NULL) {
    // The data is consumed, so we pass 0 for the size.
    if (cmsWriteTag(hProfile, tag_sig, tag_data)) {
      // The tag owns the data now, so we don't free it.
    } else {
      free(tag_data);
    }
  }

  /*
   * ANALYSIS: The functions _cmsReadProfileSequence and
   *           _cmsCompileProfileSequence have 0% coverage. They are
   *           related to handling profile sequence description tags.
   * IMPLEMENTATION: We create a profile sequence from the current profile,
   *                 write it to the profile, and then read it back after
   *                 re-opening the profile from memory.
   */
  cmsHPROFILE profile_array[] = { hProfile };
  cmsSEQ* seq_to_write = _cmsCompileProfileSequence(ctx, 1, profile_array);
  if (seq_to_write) {
      // cmsWriteTag will duplicate the sequence for this tag type.
      // We are responsible for freeing the sequence we created.
      cmsWriteTag(hProfile, cmsSigProfileSequenceDescTag, seq_to_write);
      cmsFreeProfileSequenceDescription(seq_to_write);
  }

  // Save the profile to a memory buffer
  char *buffer;
  cmsUInt32Number buffer_size;
  if (cmsSaveProfileToMem(hProfile, NULL, &buffer_size)) {
    buffer = (char *)malloc(buffer_size);
    if (buffer != NULL) {
      if (cmsSaveProfileToMem(hProfile, buffer, &buffer_size)) {
        // Now open the profile from memory to use it
        cmsHPROFILE hProfileFromMem = cmsOpenProfileFromMem(buffer, buffer_size);
        if (hProfileFromMem != NULL) {
          /*
           * ANALYSIS: The function cmsDetectDestinationBlackPoint has very low
           *           coverage (34.45%). It takes a profile and an intent.
           * IMPLEMENTATION: We call this function with the in-memory profile
           *                 and a fuzzer-driven intent value to explore its
           *                 different code paths.
           */
          cmsCIExyY black_point;
          cmsDetectDestinationBlackPoint(&black_point, hProfileFromMem, size % 5, 0);

          /*
           * Read the profile sequence description tag we wrote earlier to
           * improve coverage of sequence reading logic.
           */
          cmsSEQ* seq = (cmsSEQ*)cmsReadTag(hProfileFromMem, cmsSigProfileSequenceDescTag);
          if (seq != NULL) {
              cmsFreeProfileSequenceDescription(seq);
          }
          cmsCloseProfile(hProfileFromMem);
        }
      }
      free(buffer);
    }
  }

  cmsCloseProfile(hProfile);


  /*
   * ANALYSIS: The function cmsSmoothToneCurve has several missed branches,
   *           especially in its error handling and parameter checking.
   * IMPLEMENTATION: Create a tone curve with fuzzer data and then attempt
   *                 to smooth it, providing a fuzzer-driven parameter to
   *                 explore different smoothing behaviors.
   */
  if (size > sizeof(cmsUInt16Number) * 2) {
      int num_points = data[0] % 256;
      if (num_points > 1 && size > (sizeof(cmsUInt16Number) * num_points)) {
          cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(ctx, num_points, (cmsUInt16Number*)data);
          if (curve) {
              // Use a byte from the input to influence the smoothing parameter
              double smoothing_param = (double)data[1] / 255.0 * 10.0;
              cmsToneCurve* smoothed = cmsSmoothToneCurve(curve, smoothing_param);
              if (smoothed) {
                  cmsFreeToneCurve(smoothed);
              }
              cmsFreeToneCurve(curve);
          }
      }
  }


  cmsDeleteContext(ctx);
  return 0;
}