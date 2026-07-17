/* BLOCKER_STRATEGY_CONTRACT
required_state: The _cmsTRANSFORM object's EntryColorSpace must be cmsSigLabData, and the Version argument passed to cmsTransform2DeviceLink must be less than 4.0.
state_constructor: A Lab profile is created using cmsCreateLab2ProfileTHR. This profile is then used as the input profile in a call to cmsCreateTransform, with TYPE_Lab_8 as the input format. This ensures the resulting transform object has cmsSigLabData as its entry color space.
trigger_api: cmsTransform2DeviceLink is called with the specially crafted transform handle and a version number of 3.4, which is less than 4.0.
preserved_invariants: The original fuzz target's logic, including file operations and existing API call sequences, is maintained. The new logic is added without altering the original input consumption, ensuring that existing seeds remain valid.
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

  /*
   * BLOCKER-SPECIFIC IMPLEMENTATION: The following code is added to cross the
   * blocker at cmsvirt.c:1219. The condition requires the transform's entry
   * colorspace to be Lab and the version to be less than 4.0.
   * This is achieved by creating a Lab profile and using it as the input to
   * cmsCreateTransform, then calling cmsTransform2DeviceLink with version 3.4.
   */
  cmsHPROFILE hLabProfile = cmsCreateLab2ProfileTHR(ctx, NULL);
  if (hLabProfile) {
    cmsHPROFILE hDestProfileForLab = cmsCreate_sRGBProfileTHR(ctx);
    if (hDestProfileForLab) {
      cmsHTRANSFORM hLabTransform = cmsCreateTransform(hLabProfile, TYPE_Lab_8, hDestProfileForLab, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
      if (hLabTransform) {
        // This call should hit the target predicate with the correct state.
        // Version is < 4.0 and EntryColorSpace should be Lab.
        cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hLabTransform, 3.4, 0);
        if (hDeviceLink) {
          cmsCloseProfile(hDeviceLink);
        }
        cmsDeleteTransform(hLabTransform);
      }
      cmsCloseProfile(hDestProfileForLab);
    }
    cmsCloseProfile(hLabProfile);
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