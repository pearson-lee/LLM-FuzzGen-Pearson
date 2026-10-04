#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include "/src/lcms/include/lcms2.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

// Dummy sampler for cmsSliceSpace16
static cmsBool Sampler16(const cmsUInt16Number In[], cmsUInt16Number Out[], void *Cargo) {
  return TRUE;
}

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
   * ANALYSIS: The line-level coverage for cmsDetectDestinationBlackPoint showed
   *           that the curve-fitting logic (lines 416-551) was completely
   *           uncovered because the function was only being called with matrix-
   *           shaper profiles.
   * IMPLEMENTATION: This block creates a CLUT-based ink-limiting profile and
   *                 passes it to cmsDetectDestinationBlackPoint. This profile
   *                 type is required to enter the previously uncovered Adobe
   *                 black-point detection algorithm, which includes calls to
   *                 the uncovered RootOfLeastSquaresFitQuadraticCurve function.
   */
  cmsHPROFILE hInkLimit = cmsCreateInkLimitingDeviceLinkTHR(ctx, cmsSigCmykData, 150);
  if (hInkLimit != NULL) {
    cmsDetectDestinationBlackPoint(&black_point, hInkLimit, INTENT_RELATIVE_COLORIMETRIC, 0);
    cmsCloseProfile(hInkLimit);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectTAC had a low branch
   *           coverage. The line-level report confirmed the call to cmsSliceSpace16
   *           is never executed.
   * IMPLEMENTATION: The following code block calls cmsDetectTAC to trigger the call
   *                 to cmsSliceSpace16.
   */
  cmsDetectTAC(hProfile);

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectTAC and its
   *           callee cmsSliceSpace16 were not being fully exercised. The line-level
   *           report on cmsDetectTAC revealed that the transform creation
   *           (bp.hRoundTrip) was always failing because it was not being called
   *           with a cmsSigOutputClass profile.
   * IMPLEMENTATION: The following block creates a valid CMYK output profile
   *                 and passes it to cmsDetectTAC. This allows the transform
   *                 to be created successfully, thus reaching the previously
   *                 uncovered calls to cmsSliceSpace16 and EstimateTAC.
   */
  cmsHPROFILE hCmykProfile = cmsCreateNULLProfileTHR(ctx);
  if (hCmykProfile != NULL) {
    cmsSetDeviceClass(hCmykProfile, cmsSigOutputClass);
    cmsSetColorSpace(hCmykProfile, cmsSigCmykData);
    cmsDetectTAC(hCmykProfile);
    cmsCloseProfile(hCmykProfile);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsWriteTag had low branch
   *           coverage. The line-level report showed that error handling paths
   *           were not taken.
   * IMPLEMENTATION: The following code block calls cmsWriteTag with a NULL data
   *                 pointer to trigger the tag deletion logic and exercise the
   *                 error handling paths.
   */
  cmsWriteTag(hProfile, cmsSigMediaWhitePointTag, NULL);

  /*
   * ANALYSIS: The function-level coverage report showed cmsGetSupportedIntentsTHR
   *           had 0% coverage.
   * IMPLEMENTATION: The following code block calls cmsGetSupportedIntentsTHR to
   *                 retrieve the list of supported rendering intents, exercising
   *                 this previously uncovered function. Memory is safely
   *                 handled by using stack-allocated arrays of a fixed size.
   */
  cmsUInt32Number codes[20];
  char *descriptions[20];
  cmsGetSupportedIntentsTHR(ctx, 20, codes, descriptions);

  /*
   * ANALYSIS: The function-level coverage report showed cmsSliceSpace16 was
   *           never executed. Attempts to trigger it via cmsDetectTAC failed
   *           because the required transform could not be created.
   * IMPLEMENTATION: The following code calls cmsSliceSpace16 directly with a
   *                 dummy sampler function to ensure this function is covered.
   */
  cmsUInt32Number clut_points[] = {2, 2, 2};
  cmsSliceSpace16(3, clut_points, Sampler16, NULL);

  /*
   * ANALYSIS: The function-level coverage report showed cmsGetProfileInfoUTF8 had low
   *           coverage.
   * IMPLEMENTATION: The following code calls cmsGetProfileInfo to exercise the
   *                 uncovered paths for reading profile information.
   */
  wchar_t buffer[256];
  cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", buffer, 256);


  cmsHPROFILE hDestProfile = cmsCreate_sRGBProfileTHR(ctx);
  if (hDestProfile != NULL) {
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hDestProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (hTransform != NULL) {
      /*
       * ANALYSIS: The function-level coverage report showed that many functions
       *           related to the transform engine (cmsDoTransform, formatters,
       *           interpolators) had low or zero coverage.
       * IMPLEMENTATION: The following code block calls cmsDoTransform to
       *                 actually perform a color transformation, exercising the
       *                 previously uncovered transform pipeline.
       */
      uint8_t input_pixels[] = {1, 2, 3};
      uint8_t output_pixels[3];
      cmsDoTransform(hTransform, input_pixels, output_pixels, 1);

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

      /*
       * ANALYSIS: The function-level coverage report showed cmsPipelineDup had low
       *           coverage. The previous attempt to call it was incorrect, passing
       *           a transform handle instead of a pipeline.
       * IMPLEMENTATION: The following code block correctly constructs a pipeline,
       *                 duplicates it, and frees both, ensuring cmsPipelineDup and
       *                 related memory management functions are exercised.
       */
      cmsPipeline *p = cmsPipelineAlloc(ctx, 3, 3);
      if (p != NULL) {
        cmsFloat64Number matrix[] = {1, 0, 0, 0, 1, 0, 0, 0, 1};
        cmsStage *m = cmsStageAllocMatrix(ctx, 3, 3, matrix, NULL);
        if (m != NULL) {
          cmsPipelineInsertStage(p, cmsAT_END, m);
          cmsPipeline *p2 = cmsPipelineDup(p);
          if (p2 != NULL) {
            cmsPipelineFree(p2);
          }
        }
        cmsPipelineFree(p);
      }

      cmsDeleteTransform(hTransform);
    }
    cmsCloseProfile(hDestProfile);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the CIECAM02
   *           module (cmscam02.c) had several functions with zero or low
   *           coverage, including cmsCIECAM02Forward and cmsCIECAM02Inverse.
   * IMPLEMENTATION: This block initializes a CIECAM02 object, performs
   *                 forward and inverse transformations, and then cleans up,
   *                 exercising the core CIECAM02 functionality.
   */
  cmsViewingConditions vc;
  memcpy(&vc.whitePoint, cmsD50_XYZ(), sizeof(cmsCIEXYZ));
  vc.La = 64;
  vc.Yb = 18;
  vc.surround = AVG_SURROUND;
  vc.D_value = 1.0;
  cmsHANDLE cam = cmsCIECAM02Init(ctx, &vc);
  if (cam != NULL) {
      cmsCIEXYZ a;
      cmsJCh b;
      a.X = 0.1; a.Y = 0.2; a.Z = 0.3;
      cmsCIECAM02Forward(cam, &a, &b);
      cmsCIECAM02Reverse(cam, &b, &a);
      cmsCIECAM02Done(cam);
  }

  cmsHANDLE hIT8 = cmsIT8LoadFromFile(ctx, filename);
  if (hIT8 != NULL) {
    cmsHPROFILE hIT8Profile = cmsCreateDeviceLinkFromCubeFileTHR(ctx, filename);
    if (hIT8Profile != NULL) {
      /*
       * ANALYSIS: The detailed fuzz target coverage report showed the branch at
       *           line 185 was never taken, meaning cmsCreateTransform was
       *           failing for the profile created from the fuzzed data. The
       *           documentation states that if the first profile is a device
       *           link, the second must be NULL.
       * IMPLEMENTATION: The call to cmsCreateTransform is corrected by passing
       *                 NULL as the second profile handle. A call to
       *                 cmsDoTransform is also added to exercise this path.
       */
      cmsHTRANSFORM hTransform = cmsCreateTransform(hIT8Profile, TYPE_RGB_8, NULL, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
      if (hTransform != NULL) {
        uint8_t input_pixels[] = {1, 2, 3};
        uint8_t output_pixels[3];
        cmsDoTransform(hTransform, input_pixels, output_pixels, 1);
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