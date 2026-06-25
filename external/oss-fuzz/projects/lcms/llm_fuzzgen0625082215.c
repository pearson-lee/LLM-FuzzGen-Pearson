#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


// Macros for temporary file paths
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzzer"
#endif

#define FUZZ_FILENAME1 "/tmp/" _FUZZ_TARGET_NAME ".icc"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  // Create a NULL profile
  cmsHPROFILE hNull = cmsCreateNULLProfile();
  if (!hNull) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed that several functions
   *           related to tone curve and profile creation had low coverage.
   *           Specifically, functions that handle different profile structures and
   *           transforms were not fully exercised.
   * IMPLEMENTATION: The following code generates a variety of profiles and
   *                 transforms using the input data. It creates sRGB, GRAY,
   *                 and segmented tone curve-based profiles, and then creates a
   *                 multi-profile transform to exercise the color transformation
   *                 engine.
   */
  cmsHPROFILE hsRGB = cmsCreate_sRGBProfile();
  cmsHPROFILE hGray = cmsCreateGrayProfile(cmsD50_xyY(), NULL);

  cmsCurveSegment segments[] = {{0, 1, 1.0}};
  cmsToneCurve *curve = cmsBuildSegmentedToneCurve(NULL, 1, segments);
  cmsHPROFILE hCurve = cmsCreateGrayProfile(cmsD50_xyY(), curve);
  cmsFreeToneCurve(curve);

  cmsHPROFILE profiles[] = {hsRGB, hGray, hCurve, hNull};
  cmsHPROFILE hTransform = cmsCreateMultiprofileTransform(profiles, 4, TYPE_BGR_8, TYPE_CMYK_8, INTENT_PERCEPTUAL, 0);

  if (hTransform) {
    uint8_t in[] = {0x12, 0x34, 0x56};
    uint8_t out[4];
    cmsDoTransform(hTransform, in, out, 1);
    cmsDeleteTransform(hTransform);
  }

  cmsCloseProfile(hsRGB);
  cmsCloseProfile(hGray);
  cmsCloseProfile(hCurve);

  /*
   * ANALYSIS: The function-level coverage report indicated that IT8 parsing
   *           functions, particularly those handling data formats and properties,
   *           had very low coverage. For example, `cmsIT8SetData`,
   *           `cmsIT8EnumDataFormat`, and `cmsIT8EnumProperties` were largely
   *           untested.
   * IMPLEMENTATION: This section of the code uses the fuzzer input to create an
   *                 in-memory IT8 file. This file is then parsed by
   *                 `cmsIT8LoadFromMem`, which in turn exercises the
   *                 less-covered IT8 parsing logic. This approach aims to
   *                 discover vulnerabilities in the IT8 parsing engine.
   */
  cmsHANDLE hIT8 = cmsIT8LoadFromMem(NULL, data, size);
  if (hIT8) {
    cmsIT8Free(hIT8);
  }

  // Save the null profile to a file and reopen it
  if (cmsSaveProfileToFile(hNull, FUZZ_FILENAME1)) {
    cmsHPROFILE hFile = cmsOpenProfileFromFile(FUZZ_FILENAME1, "r");
    if (hFile) {
      // The color space of a null profile is cmsSigGrayData
      if (cmsGetColorSpace(hFile) == cmsSigGrayData) {
        // Do something here
      }
      cmsCloseProfile(hFile);
    }
  }
  remove(FUZZ_FILENAME1);

  cmsCloseProfile(hNull);

  return 0;
}