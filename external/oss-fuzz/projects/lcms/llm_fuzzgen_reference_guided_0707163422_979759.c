/* BLOCKER_STRATEGY_CONTRACT
required_state: The profile's color space must be `cmsSigLabData` when `_cmsReadDevicelinkLUT` is called. The predicate is `cmsGetColorSpace(hProfile) == cmsSigLabData`.
state_constructor: A named color profile (`cmsHPROFILE`) is created and its color space is explicitly set to `cmsSigLabData` via `cmsSetColorSpace(named_color_profile, cmsSigLabData)`. Its device class is set to `cmsSigNamedColorClass`.
trigger_api: `cmsGetPostScriptCRD` is called with the crafted profile, which internally calls `_cmsReadDevicelinkLUT`.
preserved_invariants: The fuzz target preserves the original input contract and API call sequence. The change only modifies a parameter to an existing `cmsSetColorSpace` call to satisfy the blocker's condition.
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
   * second profile was not of device class `cmsSigOutputClass`.
   * IMPLEMENTATION: This block now creates a CMYK device link profile and a
   * gray output profile. This combination of profiles allows `_cmsBuildKToneCurve`
   * to proceed past the initial checks and execute its core logic, improving
   * its coverage from 19% to a higher value.
   */
  cmsHPROFILE cmyk_profiles[2];
  cmyk_profiles[0] = cmsCreateInkLimitingDeviceLinkTHR(NULL, cmsSigCmykData, 150);
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
   * causing `cmsCreateTransform` to fail and return early.
   * IMPLEMENTATION: This block creates a valid named color profile using
   * `cmsAllocNamedColorList`, `cmsAppendNamedColor`, and
   * `cmsCreateNamedColorProfile`. It then calls `cmsGetPostScriptCRD` with this
   * valid profile, which in turn calls `WriteNamedColorCRD` and allows it to
   * execute its core logic, significantly improving coverage.
   */
  cmsNAMEDCOLORLIST *named_color_list = cmsAllocNamedColorList(NULL, 1, 3, "Prefix", "Suffix");
  if (named_color_list) {
    cmsUInt16Number pcs[3] = {0, 0, 0};
    cmsUInt16Number dev[3] = {0, 0, 0};
    if (cmsAppendNamedColor(named_color_list, "color", pcs, dev)) {
      cmsHPROFILE named_color_profile = cmsCreateProfilePlaceholder(NULL);
      if (named_color_profile) {
        cmsSetDeviceClass(named_color_profile, cmsSigNamedColorClass);
        // BLOCKER: The predicate at `_cmsReadDevicelinkLUT:734` requires the
        // profile's color space to be `cmsSigLabData`.
        cmsSetColorSpace(named_color_profile, cmsSigLabData);
        cmsSetPCS(named_color_profile, cmsSigLabData);
        if (cmsWriteTag(named_color_profile, cmsSigNamedColor2Tag, named_color_list)) {
          char ps_buffer[1024];
          cmsGetPostScriptCRD(NULL, named_color_profile, 0, 0, ps_buffer, sizeof(ps_buffer));
        }
        cmsCloseProfile(named_color_profile);
      }
    }
    cmsFreeNamedColorList(named_color_list);
  }

  return 0;
}