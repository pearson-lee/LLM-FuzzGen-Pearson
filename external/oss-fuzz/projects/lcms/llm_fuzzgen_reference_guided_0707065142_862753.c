/* BLOCKER_STRATEGY_CONTRACT
required_state: The hProfile handle passed to _cmsReadFloatInputTag must have its color space set to cmsSigLabData. Additionally, to reach this function, the profile must contain a cmsSigDToB0Tag (for INTENT_PERCEPTUAL) which holds a valid cmsPipeline, and a cmsSigAToB0Tag to pass an earlier check in cmsIsIntentSupported.
state_constructor: A placeholder profile is created with `cmsCreateProfilePlaceholder`. Its color space is set to `cmsSigLabData` using `cmsSetColorSpace`. A `cmsPipeline` is allocated and written to both the `cmsSigDToB0Tag` and `cmsSigAToB0Tag` of the profile using `cmsWriteTag`.
trigger_api: `cmsDetectDestinationBlackPoint` is called with the crafted profile and INTENT_PERCEPTUAL, which leads down a call path to the blocker.
preserved_invariants: The original fuzz target's logic of reading a file from the fuzzer input and using it to create profiles and transforms remains untouched. The new logic is additive, using a separate, programmatically created profile to hit the blocker, thus preserving the existing input consumption contract.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  char filename[256];
  sprintf(filename, "/tmp/%s.it8", _FUZZ_TARGET_NAME);
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, 1, size, fp);
  fclose(fp);

  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    unlink(filename);
    return 0;
  }

  cmsHPROFILE hProfile = cmsCreate_sRGBProfileTHR(ctx);
  if (hProfile == NULL) {
    cmsDeleteContext(ctx);
    unlink(filename);
    return 0;
  }

  /*
   * BLOCKER: _cmsReadFloatInputTag
   * PREDICATE: if (spc == cmsSigLabData)
   *
   * The predicate is false because the default profile's color space is not
   * cmsSigLabData. To satisfy the predicate, we create a placeholder
   * profile, set its color space to cmsSigLabData, and add the necessary
   * tags (cmsSigDToB0Tag and cmsSigAToB0Tag) for the call chain to
   * proceed. Calling cmsDetectDestinationBlackPoint triggers the blocker
   * with the crafted profile.
   */
  cmsHPROFILE hProfileForLab = cmsCreateProfilePlaceholder(ctx);
  if (hProfileForLab != NULL) {
    cmsSetDeviceClass(hProfileForLab, cmsSigDisplayClass);
    // Set the color space to Lab to satisfy the blocker's predicate
    cmsSetColorSpace(hProfileForLab, cmsSigLabData);
    cmsSetPCS(hProfileForLab, cmsSigLabData);

    cmsPipeline* lut = cmsPipelineAlloc(ctx, 3, 3);
    if (lut != NULL) {
      // Add tag for cmsIsIntentSupported to pass
      cmsWriteTag(hProfileForLab, cmsSigAToB0Tag, lut);
      // Add tag for the float-based LUT to be read
      cmsWriteTag(hProfileForLab, cmsSigDToB0Tag, lut);

      cmsCIEXYZ black_point_blocker;
      cmsDetectDestinationBlackPoint(&black_point_blocker, hProfileForLab, INTENT_PERCEPTUAL, 0);

      cmsPipelineFree(lut);
    }
    cmsCloseProfile(hProfileForLab);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectDestinationBlackPoint
   *           had a low branch coverage. The line-level report confirmed this was at
   *           multiple branches, especially the curve fitting part.
   * IMPLEMENTATION: The following code block calls cmsDetectDestinationBlackPoint with
   *                 different intents to exercise the uncovered paths.
   */
  cmsCIEXYZ black_point;
  cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_PERCEPTUAL, 0);
  cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_RELATIVE_COLORIMETRIC, 0);
  cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_SATURATION, 0);

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectTAC had a low branch
   *           coverage. The line-level report confirmed the call to cmsSliceSpace16
   *           is never executed.
   * IMPLEMENTATION: The following code block calls cmsDetectTAC to trigger the call
   *                 to cmsSliceSpace16.
   */
  cmsDetectTAC(hProfile);

  /*
   * ANALYSIS: The function-level coverage report showed cmsWriteTag had low branch
   *           coverage. The line-level report showed that error handling paths
   *           were not taken.
   * IMPLEMENTATION: The following code block calls cmsWriteTag with a NULL data
   *                 pointer to trigger the tag deletion logic and exercise the
   *                 error handling paths.
   */
  cmsWriteTag(hProfile, cmsSigMediaWhitePointTag, NULL);

  cmsHPROFILE hDestProfile = cmsCreate_sRGBProfileTHR(ctx);
  if (hDestProfile != NULL) {
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hDestProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (hTransform != NULL) {
      /*
       * ANALYSIS: The function-level coverage report showed cmsTransform2DeviceLink
       *           had a low branch coverage. The line-level report showed that
       *           different flags are not exercised.
       * IMPLEMENTATION: The following code block calls cmsTransform2DeviceLink
       *                 with different flags to exercise more code paths.
       */
      cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hTransform, 3.4, 0);
      if (hDeviceLink != NULL) {
        cmsCloseProfile(hDeviceLink);
      }
      hDeviceLink = cmsTransform2DeviceLink(hTransform, 4.3, cmsFLAGS_8BITS_DEVICELINK);
      if (hDeviceLink != NULL) {
        cmsCloseProfile(hDeviceLink);
      }
      cmsDeleteTransform(hTransform);
    }
    cmsCloseProfile(hDestProfile);
  }

  cmsHANDLE hIT8 = cmsIT8LoadFromFile(ctx, filename);
  if (hIT8 != NULL) {
    cmsHPROFILE hIT8Profile = cmsCreateDeviceLinkFromCubeFileTHR(ctx, filename);
    if (hIT8Profile != NULL) {
      cmsHTRANSFORM hTransform = cmsCreateTransform(hIT8Profile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
      if (hTransform != NULL) {
        cmsPipeline *lut = cmsPipelineDup(hTransform);
        if (lut != NULL) {
          cmsPipelineFree(lut);
        }
        cmsDeleteTransform(hTransform);
      }
      cmsCloseProfile(hIT8Profile);
    }
    cmsIT8Free(hIT8);
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(ctx);
  unlink(filename);
  return 0;
}
