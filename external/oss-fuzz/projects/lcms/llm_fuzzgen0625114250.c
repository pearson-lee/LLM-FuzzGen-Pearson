#include <stdint.h>
#include <stdlib.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 12) {
    return 0;
  }

  // Use the input data to drive the fuzzer's behavior
  uint32_t intent = data[0] % 15;
  uint32_t flags = ((uint32_t *)data)[1];
  data += 8;
  size -= 8;

  // Create a placeholder profile
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (!hProfile) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectDestinationBlackPoint
   *           had very low coverage. The line-level report confirmed that the function
   *           was returning early because the profile did not have a CLUT.
   * IMPLEMENTATION: The following code block sets the color space to CMYK and writes
   *                 a clut tag to the profile, which allows the fuzzer to get past
   *                 the initial checks in cmsDetectDestinationBlackPoint.
   */
  cmsSetColorSpace(hProfile, cmsSigCmykData);
  cmsSetPCS(hProfile, cmsSigLabData);
  cmsSetDeviceClass(hProfile, cmsSigOutputClass);
  
  // Create a valid, empty Pipeline object to be written as a CLUT tag.
  // Passing raw fuzzer data to cmsWriteTag caused a heap-buffer-overflow.
  // Using an empty pipeline is safe and avoids linker errors for unavailable functions.
  cmsPipeline* Lut = cmsPipelineAlloc(NULL, 3, 3);
  if (Lut) {
      // Write the pipeline to the profile. cmsWriteTag duplicates the data.
      cmsWriteTag(hProfile, cmsSigAToB0Tag, Lut);
      cmsPipelineFree(Lut);
  }

  cmsCIEXYZ blackPoint;
  cmsDetectDestinationBlackPoint(&blackPoint, hProfile, intent, flags);

  /*
   * ANALYSIS: The function _cmsBuildKToneCurve had low coverage because it requires
   *           a CMYK output profile.
   * IMPLEMENTATION: The profile created above is a CMYK output profile, so it can be
   *                 used to call _cmsBuildKToneCurve.
   */
  cmsHPROFILE profiles[] = {hProfile, hProfile};
  cmsUInt32Number intents[] = {intent, intent};
  cmsBool bpcs[] = {0, 0};
  cmsFloat64Number adaptation_states[] = {1.0, 1.0};
  cmsToneCurve *k_tone_curve =
      _cmsBuildKToneCurve(NULL, 256, 2, intents, profiles, bpcs,
                          adaptation_states, flags);
  if (k_tone_curve) {
    cmsFreeToneCurve(k_tone_curve);
  }

  /*
   * ANALYSIS: The function _cmsChain2Lab was completely uncovered.
   * IMPLEMENTATION: Call _cmsChain2Lab with the created profiles to exercise its
   *                 functionality.
   */
  cmsHTRANSFORM transform =
      _cmsChain2Lab(NULL, 2, 2, 2, intents, profiles, bpcs, adaptation_states, flags);
  if (transform) {
    cmsDeleteTransform(transform);
  }

  // Clean up the created profile
  cmsCloseProfile(hProfile);

  return 0;
}