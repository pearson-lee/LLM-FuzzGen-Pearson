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