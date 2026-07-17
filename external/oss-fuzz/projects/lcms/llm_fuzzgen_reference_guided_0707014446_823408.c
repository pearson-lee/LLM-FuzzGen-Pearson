/* BLOCKER_STRATEGY_CONTRACT
required_state: The hProfile handle passed to _cmsReadInputLUT must contain a tag that corresponds to the `tagFloat` variable for the given intent. For INTENT_PERCEPTUAL, this is `cmsSigDToB0Tag`. The data for this tag must be a valid cmsPipeline. Additionally, the calling function `cmsIsIntentSupported` requires the presence of the `cmsSigAToB0Tag` to proceed down the intended path.
state_constructor: A placeholder profile is created using `cmsCreateProfilePlaceholder`. A `cmsPipeline` is allocated with `cmsPipelineAlloc`. This pipeline is then written to the profile twice: once for the `cmsSigAToB0Tag` to satisfy `cmsIsIntentSupported`, and a second time for `cmsSigDToB0Tag` to satisfy the blocker's predicate `cmsIsTag(hProfile, tagFloat)`.
trigger_api: `cmsDetectDestinationBlackPoint` is called with the crafted profile and `INTENT_PERCEPTUAL`. This function's call chain leads to `_cmsReadInputLUT`, triggering the blocker with the profile that now satisfies the predicate.
preserved_invariants: The original fuzz target's logic of reading a file from the fuzzer input and using it to create profiles and transforms remains untouched. The new logic is additive and uses a separate, programmatically created profile, thus preserving the existing input consumption contract.
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
   * BLOCKER: _cmsReadInputLUT
   * PREDICATE: if (cmsIsTag(hProfile, tagFloat))
   *
   * The predicate is false because the default sRGB profile does not contain
   * the float-based LUT tag (`cmsSigDToB*Tag`) that `_cmsReadInputLUT`
   * searches for. To ensure this tag exists, we create a placeholder profile,
   * allocate a pipeline, and write it to the `cmsSigDToB0Tag` which corresponds
   * to `INTENT_PERCEPTUAL`. We also need to write `cmsSigAToB0Tag` to pass
   * the `cmsIsIntentSupported` check in the call chain. Calling
   * `cmsDetectDestinationBlackPoint` then triggers the desired code path.
   */
  cmsHPROFILE hProfileWithTag = cmsCreateProfilePlaceholder(ctx);
  if (hProfileWithTag != NULL) {
    cmsSetDeviceClass(hProfileWithTag, cmsSigDisplayClass);
    cmsSetColorSpace(hProfileWithTag, cmsSigRgbData);
    cmsSetPCS(hProfileWithTag, cmsSigLabData);

    cmsPipeline* lut = cmsPipelineAlloc(ctx, 3, 3);
    if (lut != NULL) {
      // Add tag for cmsIsIntentSupported to pass
      cmsWriteTag(hProfileWithTag, cmsSigAToB0Tag, lut);
      // Add tag for the blocker predicate to pass
      cmsWriteTag(hProfileWithTag, cmsSigDToB0Tag, lut);

      cmsCIEXYZ black_point_blocker;
      cmsDetectDestinationBlackPoint(&black_point_blocker, hProfileWithTag, INTENT_PERCEPTUAL, 0);

      cmsPipelineFree(lut);
    }
    cmsCloseProfile(hProfileWithTag);
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
