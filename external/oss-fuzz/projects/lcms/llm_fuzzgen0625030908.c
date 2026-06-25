#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  // Use the first 4 bytes for the intent.
  int intent = *(const int *)data;
  data += 4;
  size -= 4;

  cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
  if (!hProfile) {
    cmsDeleteContext(context);
    return 0;
  }

  /*
   * ANALYSIS: The line-level coverage report for `cmsDeleteTransform` showed that
   *           the branch at line 133 in cmsxform.c (`if (p -> OldTransform)`), which handles
   *           the deletion of "old" (legacy) transforms, was not fully covered. This function
   *           creates a transform from a chain of profiles.
   * IMPLEMENTATION: The following code creates a multiprofile transform by chaining the
   *                 sRGB profile and the newly created Lab profile. This exercises the logic for
   *                 linking multiple profiles. The resulting transform is deleted to prevent leaks.
   */
  cmsHPROFILE hLabProfile = cmsCreateLab4ProfileTHR(context, NULL);
  if (hLabProfile) {
    cmsHPROFILE profiles[] = {hProfile, hLabProfile};
    cmsHTRANSFORM hMultiTransform = cmsCreateMultiprofileTransformTHR(context, profiles, 2, TYPE_RGB_8, TYPE_Lab_8, intent, 0);
    if (hMultiTransform) {
      cmsDeleteTransform(hMultiTransform);
    }
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

  /*
   * ANALYSIS: The function-level coverage report showed `cmsCreate_OkLabProfile` had 0%
   *           coverage. This is a profile creation function.
   * IMPLEMENTATION: The following code block calls `cmsCreate_OkLabProfile` to create
   *                 an OkLab profile and then closes it to prevent memory leaks. This
   *                 directly exercises the uncovered function.
   */
  cmsHPROFILE hOklabProfile = cmsCreate_OkLabProfile(context);
  if (hOklabProfile) {
    cmsCloseProfile(hOklabProfile);
  }

  cmsCloseProfile(hProfile);
  cmsDeleteContext(context);
  return 0;
}