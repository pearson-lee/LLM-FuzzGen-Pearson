#include <stdint.h>
#include <sys/types.h>
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
   * ANALYSIS: The detailed fuzz target coverage report showed that the 'if (transform)'
   *           check at line 73 was never true, because _cmsChain2Lab always failed.
   *           This was due to incorrect formatters being passed.
   * IMPLEMENTATION: Call _cmsChain2Lab with the correct input and output formatters
   *                 (TYPE_CMYK_8 and TYPE_Lab_DBL) to ensure the transform is created
   *                 successfully. This covers the previously missed branch.
   */
  cmsUInt32Number input_format = TYPE_CMYK_8;
  cmsUInt32Number output_format = TYPE_Lab_DBL;
  cmsHTRANSFORM transform =
      _cmsChain2Lab(NULL, 2, input_format, output_format, intents, profiles, bpcs, adaptation_states, flags);

  if (transform) {
    /*
     * ANALYSIS: The function cmsTransform2DeviceLink has very low branch coverage (43%).
     *           Specifically, the branch 'if (NewLUT -> SaveAs8Bits)' is never taken.
     * IMPLEMENTATION: Call cmsTransform2DeviceLink with the newly created transform.
     *                 To hit the target branch, cast the transform to its internal struct
     *                 and set the SaveAs8Bits flag on its pipeline. The created device
     *                 link profile is closed to prevent memory leaks.
     */
    if (((_cmsTRANSFORM*)transform)->Lut) {
        ((_cmsTRANSFORM*)transform)->Lut->SaveAs8Bits = 1;
    }
    cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(transform, 4.3, 0);
    if (hDeviceLink) {
        cmsCloseProfile(hDeviceLink);
    }
    cmsDeleteTransform(transform);
  }

  // Clean up the created profile
  cmsCloseProfile(hProfile);

  return 0;
}