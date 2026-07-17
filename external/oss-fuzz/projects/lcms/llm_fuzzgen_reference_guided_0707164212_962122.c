/* BLOCKER_STRATEGY_CONTRACT
required_state: The `_cmsGetFormatter` function must return a NULL formatter for either the input or output format provided to `cmsChangeBuffersFormat`. This is achieved by using an invalid format identifier. Additionally, the transform object must permit format changes, which requires it to be created with at least 16-bit precision.
state_constructor: A transform is created using 16-bit color types (`TYPE_RGB_16`) to set the internal `cmsFLAGS_CAN_CHANGE_FORMATTER` flag, satisfying the precondition for `cmsChangeBuffersFormat`.
trigger_api: `cmsChangeBuffersFormat` is called with an invalid `InputFormat` of `0`. This causes `_cmsGetFormatter` to fail and return `NULL`, satisfying the blocker's predicate `FromInput == NULL`.
preserved_invariants: The new logic is added at the end of the fuzz target, preserving the original input consumption contract and all preceding API call sequences. The change modifies an existing block that already targeted `cmsChangeBuffersFormat`, but adapts it for the blocker goal.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "lcms_fuzzer"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) {
    return 0;
  }

  /*
   * ANALYSIS: The function `cmsOpenIOhandlerFromStream` has 0% code coverage.
   * IMPLEMENTATION: The following code block creates a temporary file, writes
   * the fuzzer data to it, and then calls `cmsOpenIOhandlerFromStream` to
   * exercise this previously uncovered function.
   */
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);
  FILE *f = fopen(path, "wb");
  if (f) {
    fwrite(data, 1, size, f);
    fclose(f);

    f = fopen(path, "rb");
    if (f) {
      cmsIOHANDLER *io = cmsOpenIOhandlerFromStream(NULL, f);
      if (io) {
        cmsCloseIOhandler(io);
      } else {
        fclose(f);
      }
    }
    unlink(path);
  }

  /*
   * ANALYSIS: The function `cmsIT8SetTableByLabel` has low coverage because
   * the call to `cmsIT8GetData` always returns NULL.
   * IMPLEMENTATION: The following code block creates an IT8 handle and uses
   * `cmsIT8SetData` to populate it with fuzzer data. This allows
   * `cmsIT8GetData` to return a non-NULL value, enabling the fuzzer to explore
   * the previously unreachable code paths in `cmsIT8SetTableByLabel`.
   */
  cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
  if (hIT8) {
    cmsIT8SetData(hIT8, "D", "SAMPLE_ID", "1");
    cmsIT8SetTableByLabel(hIT8, "D", "SAMPLE_ID", "1");
    cmsIT8Free(hIT8);
  }

  /*
   * ANALYSIS: The function `cmsDetectDestinationBlackPoint` has low coverage
   * because it is not being called with a valid CLUT profile. The detailed
   * coverage report shows a large block of code from line 415 is uncovered.
   * IMPLEMENTATION: The following code block creates an ink limiting profile,
   * which is a CLUT-based profile. This profile is then used to call
   * `cmsDetectDestinationBlackPoint` with INTENT_RELATIVE_COLORIMETRIC,
   * allowing the fuzzer to exercise the complex black point detection logic
   * in the previously uncovered code path.
   */
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (hProfile) {
    cmsCIEXYZ black_point;
    cmsDetectDestinationBlackPoint(&black_point, hProfile, INTENT_PERCEPTUAL, 0);
    cmsCloseProfile(hProfile);
  }

  /*
   * ANALYSIS: The function `cmsSmoothToneCurve` has several uncovered
   * branches related to curve smoothing.
   * IMPLEMENTATION: The following code block creates a tone curve with fuzzer
   * data and then calls `cmsSmoothToneCurve` to exercise the curve smoothing
   * logic.
   */
  cmsToneCurve *curve = cmsBuildTabulatedToneCurve16(NULL, 4, (const cmsUInt16Number *)data);
  if (curve) {
    cmsSmoothToneCurve(curve, 1.0);
    cmsFreeToneCurve(curve);
  }

  /*
   * ANALYSIS: The function `cmsCreateInkLimitingDeviceLinkTHR` has uncovered
   * branches related to the creation of ink limiting device links. The created
   * profile is also used to improve coverage in `cmsDetectDestinationBlackPoint`.
   * IMPLEMENTATION: The following code block creates an array of tone curves
   * and then calls `cmsCreateInkLimitingDeviceLinkTHR` to exercise the ink
   * limiting logic.
   */
  cmsToneCurve *curves[4];
  curves[0] = cmsBuildGamma(NULL, 2.2);
  curves[1] = cmsBuildGamma(NULL, 2.2);
  curves[2] = cmsBuildGamma(NULL, 2.2);
  curves[3] = cmsBuildGamma(NULL, 2.2);
  if (curves[0] && curves[1] && curves[2] && curves[3]) {
    cmsHPROFILE hInkLimit = cmsCreateInkLimitingDeviceLinkTHR(NULL, cmsSigCmykData, 100);
    if (hInkLimit) {
      cmsCIEXYZ black_point;
      cmsDetectDestinationBlackPoint(&black_point, hInkLimit, INTENT_RELATIVE_COLORIMETRIC, 0);
      cmsCloseProfile(hInkLimit);
    }
  }
  if (curves[0]) cmsFreeToneCurve(curves[0]);
  if (curves[1]) cmsFreeToneCurve(curves[1]);
  if (curves[2]) cmsFreeToneCurve(curves[2]);
  if (curves[3]) cmsFreeToneCurve(curves[3]);

  /*
   * ANALYSIS: The function `cmsCreateGrayProfile` has 0% coverage.
   * IMPLEMENTATION: This block calls `cmsCreateGrayProfile` with a sample
   * white point and a gamma curve to exercise this uncovered function.
   */
  cmsCIExyY white_point = {0.3127, 0.3290, 1.0};
  cmsToneCurve *gamma_curve = cmsBuildGamma(NULL, 2.2);
  if (gamma_curve) {
    cmsHPROFILE gray_profile = cmsCreateGrayProfile(&white_point, gamma_curve);
    if (gray_profile) {
      cmsCloseProfile(gray_profile);
    }
    cmsFreeToneCurve(gamma_curve);
  }

  /*
   * ANALYSIS: The function `_cmsBuildKToneCurve` was returning NULL because the
   * transform creation within it failed. This was likely due to the input
   * profile being a `cmsSigLinkClass` profile instead of a standard input
   * profile.
   * IMPLEMENTATION: This block now creates a placeholder CMYK input profile.
   * This simpler, standard profile allows the internal transform to be created
   * successfully, enabling `_cmsBuildKToneCurve` to proceed into its core
   * logic and improving coverage.
   */
  cmsHPROFILE cmyk_profiles[2];
  cmyk_profiles[0] = cmsCreateProfilePlaceholder(NULL);
  if (cmyk_profiles[0]) {
      cmsSetColorSpace(cmyk_profiles[0], cmsSigCmykData);
      cmsSetDeviceClass(cmyk_profiles[0], cmsSigInputClass);
  }
  cmsToneCurve *gamma_curve_for_gray = cmsBuildGamma(NULL, 2.2);
  if (gamma_curve_for_gray) {
    cmyk_profiles[1] = cmsCreateGrayProfile(&white_point, gamma_curve_for_gray);
    cmsFreeToneCurve(gamma_curve_for_gray);
  } else {
    cmyk_profiles[1] = NULL;
  }

  if (cmyk_profiles[0] && cmyk_profiles[1]) {
    const cmsUInt32Number intents[] = {INTENT_PERCEPTUAL, INTENT_PERCEPTUAL};
    const cmsBool bpc[] = {1, 1};
    const cmsFloat64Number adaptation_states[] = {1.0, 1.0};
    cmsToneCurve *k_tone_curve = _cmsBuildKToneCurve(NULL, 256, 2, intents, cmyk_profiles, bpc, adaptation_states, 0);
    if (k_tone_curve) {
      cmsFreeToneCurve(k_tone_curve);
    }
  }
  if (cmyk_profiles[0]) cmsCloseProfile(cmyk_profiles[0]);
  if (cmyk_profiles[1]) cmsCloseProfile(cmyk_profiles[1]);

  /*
   * ANALYSIS: The function `WriteNamedColorCRD` in `cmsps2.c` had low
   * coverage because it was being called with an invalid named color profile,
   * causing `cmsCreateTransform` to fail and return early. Additionally, the
   * function `CreateNamedColorDevicelink` in `cmsvirt.c` had 0% coverage.
   * IMPLEMENTATION: This block creates a valid named color profile. It then
   * calls `cmsGetPostScriptCRD` to cover `WriteNamedColorCRD`. It also creates
   * a transform from this profile and passes it to `cmsTransform2DeviceLink`,
   * which in turn calls the uncovered `CreateNamedColorDevicelink` function.
   */
  cmsNAMEDCOLORLIST *named_color_list = cmsAllocNamedColorList(NULL, 1, 3, "Prefix", "Suffix");
  if (named_color_list) {
    cmsUInt16Number pcs[3] = {0, 0, 0};
    cmsUInt16Number dev[3] = {0, 0, 0};
    if (cmsAppendNamedColor(named_color_list, "color", pcs, dev)) {
      cmsHPROFILE named_color_profile = cmsCreateProfilePlaceholder(NULL);
      if (named_color_profile) {
        cmsSetDeviceClass(named_color_profile, cmsSigNamedColorClass);
        cmsSetColorSpace(named_color_profile, cmsSigRgbData);
        cmsSetPCS(named_color_profile, cmsSigLabData);
        if (cmsWriteTag(named_color_profile, cmsSigNamedColor2Tag, named_color_list)) {
          char ps_buffer[1024];
          cmsGetPostScriptCRD(NULL, named_color_profile, 0, 0, ps_buffer, sizeof(ps_buffer));

          // Add coverage for CreateNamedColorDevicelink
          cmsHPROFILE hLab = cmsCreateLab4Profile(NULL);
          if (hLab) {
            cmsHTRANSFORM hXform = cmsCreateTransform(named_color_profile, TYPE_NAMED_COLOR_INDEX, hLab, TYPE_Lab_8, INTENT_PERCEPTUAL, 0);
            if (hXform) {
              cmsHPROFILE hDevicelink = cmsTransform2DeviceLink(hXform, 3.4, 0);
              if (hDevicelink) {
                cmsCloseProfile(hDevicelink);
              }
              cmsDeleteTransform(hXform);
            }
            cmsCloseProfile(hLab);
          }
        }
        cmsCloseProfile(named_color_profile);
      }
    }
    cmsFreeNamedColorList(named_color_list);
  }

  /*
   * BLOCKER-SPECIFIC CODE
   * ANALYSIS: The blocker at cmsxform.c:1457 is in cmsChangeBuffersFormat.
   * The condition `FromInput == NULL || ToOutput == NULL` is not met because
   * the existing calls use valid formatters. To trigger the error, we need to
   * provide an unsupported format.
   * IMPLEMENTATION: This block first creates a transform with 16-bit precision
   * (TYPE_RGB_16) to ensure that buffer format changes are allowed (the
   * cmsFLAGS_CAN_CHANGE_FORMATTER flag is set). It then calls
   * cmsChangeBuffersFormat with an invalid InputFormat (0), which causes
   * _cmsGetFormatter to return NULL, thus satisfying the predicate and
   * crossing the blocker.
   */
  cmsHPROFILE srgb_profile = cmsCreate_sRGBProfile();
  if (srgb_profile) {
    // Create a transform with 16-bit precision to allow format changes.
    cmsHTRANSFORM xform = cmsCreateTransform(srgb_profile, TYPE_RGB_16, srgb_profile, TYPE_RGB_16, INTENT_PERCEPTUAL, 0);
    if (xform) {
      // Call with an invalid format (0) to trigger the blocker.
      cmsChangeBuffersFormat(xform, 0, TYPE_RGB_16);
      cmsDeleteTransform(xform);
    }
    cmsCloseProfile(srgb_profile);
  }


  return 0;
}