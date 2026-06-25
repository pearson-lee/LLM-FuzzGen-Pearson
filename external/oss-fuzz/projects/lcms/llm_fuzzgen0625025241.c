#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (context == NULL) {
    return 0;
  }

  cmsHPROFILE hProfile = cmsCreate_sRGBProfileTHR(context);
  if (hProfile == NULL) {
    cmsDeleteContext(context);
    return 0;
  }

  cmsCIEXYZ blackPoint;
  int intent = data[0] % 4;
  cmsDetectDestinationBlackPoint(&blackPoint, hProfile, intent, 0);

  cmsHPROFILE hPlaceholder = cmsCreateProfilePlaceholder(context);
  if (hPlaceholder) {
    cmsSetDeviceClass(hPlaceholder, cmsSigLinkClass);
    cmsDetectDestinationBlackPoint(&blackPoint, hPlaceholder, intent, 0);
    cmsCloseProfile(hPlaceholder);
  }

  cmsHTRANSFORM hTransform = cmsCreateTransformTHR(context, hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, intent, cmsFLAGS_CAN_CHANGE_FORMATTER);
  if (hTransform) {
    uint32_t inputFormat = TYPE_BGR_8;
    uint32_t outputFormat = TYPE_BGR_8;
    cmsChangeBuffersFormat(hTransform, inputFormat, outputFormat);

    cmsDeleteTransform(hTransform);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectDestinationBlackPoint
   *           had very low coverage (30%). The line-level report confirmed this was
   *           because the check `cmsIsCLUT` at line 403 in cmssamp.c always returned
   *           false, preventing a large block of code from being executed. The existing
   *           fuzzer uses `cmsCreate_sRGBProfileTHR`, which creates a matrix-shaper profile.
   * IMPLEMENTATION: The following code block creates a Lab profile using
   *                 `cmsCreateLab4ProfileTHR`. Lab profiles are LUT-based, which will cause
   *                 `cmsIsCLUT` to return true, exercising the previously uncovered code paths
   *                 for LUT-based black point detection.
   */
  cmsHPROFILE hLabProfile = cmsCreateLab4ProfileTHR(context, NULL);
  if (hLabProfile) {
    cmsDetectDestinationBlackPoint(&blackPoint, hLabProfile, intent, 0);
    cmsCloseProfile(hLabProfile);
  }

  /*
   * ANALYSIS: The line-level coverage report for `cmsDeleteTransform` showed that
   *           the branch checking for `p->GamutCheck` at line 153 in cmsxform.c was
   *           never taken. This field is populated when a gamut checking transform
   *           is created.
   * IMPLEMENTATION: The following code block creates a proofing transform using
   *                 `cmsCreateProofingTransformTHR` with the `cmsFLAGS_GAMUTCHECK` flag.
   *                 This ensures the `GamutCheck` pipeline is created within the transform
   *                 object. Deleting this transform will then exercise the previously
   *                 uncovered branch in `cmsDeleteTransform`.
   */
  cmsHPROFILE hProofProfile = cmsCreate_sRGBProfileTHR(context);
  if (hProofProfile) {
    cmsHTRANSFORM hProofTransform = cmsCreateProofingTransformTHR(context, hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, hProofProfile, intent, intent, cmsFLAGS_GAMUTCHECK);
    if (hProofTransform) {
      cmsDeleteTransform(hProofTransform);
    }
    cmsCloseProfile(hProofProfile);
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(context);
  return 0;
}