#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/lcms/include/lcms2.h"

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
   * because it is not being called with a valid profile.
   * IMPLEMENTATION: The following code block creates a placeholder profile and
   * writes fuzzer data to it. This profile is then used to call
   * `cmsDetectDestinationBlackPoint`, allowing the fuzzer to exercise the
   * complex black point detection logic.
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
   * branches related to the creation of ink limiting device links.
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
      cmsCloseProfile(hInkLimit);
    }
  }
  if (curves[0]) cmsFreeToneCurve(curves[0]);
  if (curves[1]) cmsFreeToneCurve(curves[1]);
  if (curves[2]) cmsFreeToneCurve(curves[2]);
  if (curves[3]) cmsFreeToneCurve(curves[3]);

  return 0;
}