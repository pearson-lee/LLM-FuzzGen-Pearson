/* BLOCKER_STRATEGY_CONTRACT
required_state: The hProfile argument passed to BuildGrayOutputPipeline must contain a cmsSigGrayTRCTag so that cmsReadTag returns a non-NULL cmsToneCurve*.
state_constructor: The gray output profile (hGray) is created using cmsCreateGrayProfile with a valid cmsToneCurve* as the TransferFunction argument. The tone curve is built with cmsBuildSegmentedToneCurve.
trigger_api: cmsCreateTransform(hsRGB, TYPE_RGB_8, hGray, TYPE_GRAY_8, INTENT_PERCEPTUAL, 0) which internally calls BuildGrayOutputPipeline with hGray as the profile.
preserved_invariants: The overall structure of the fuzzer, including the consumption of the fuzzer input (data, size) and the sequence of API calls, is maintained. The change only affects the parameters used to create an intermediate profile handle.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
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

  cmsCurveSegment segments[] = {{0, 1, 1.0}};
  cmsToneCurve *curve = cmsBuildSegmentedToneCurve(NULL, 1, segments);

  // BLOCKER-ORIENTED CHANGE: The original code created a gray profile with a
  // NULL tone curve, causing cmsReadTag(hProfile, cmsSigGrayTRCTag) to fail
  // inside BuildGrayOutputPipeline. By passing a valid tone curve, we ensure
  // the profile contains the required tag, allowing execution to proceed past
  // the blocker.
  cmsHPROFILE hGray = cmsCreateGrayProfile(cmsD50_xyY(), curve);

  cmsHPROFILE hCurve = cmsCreateGrayProfile(cmsD50_xyY(), curve);
  cmsFreeToneCurve(curve);

  /*
   * ANALYSIS: The detailed fuzz target coverage report showed the branch at line 48
   *           was never taken, meaning cmsCreateMultiprofileTransform always failed.
   *           This prevented cmsDoTransform and other functions from being called.
   * IMPLEMENTATION: Replaced the complex and failing multiprofile transform with a
   *                 simple, robust transform from sRGB to Gray. This ensures the
   *                 transform creation succeeds and the transformation path is executed.
   */
  cmsHPROFILE hTransform = cmsCreateTransform(hsRGB, TYPE_RGB_8, hGray, TYPE_GRAY_8, INTENT_PERCEPTUAL, 0);

  if (hTransform) {
    uint8_t in[] = {0x12, 0x34, 0x56};
    uint8_t out[1]; // Gray8 is 1 byte
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

  /*
   * ANALYSIS: The function-level coverage report for cmscgats.c showed that
   *           many IT8 manipulation functions like cmsIT8SetPropertyStr,
   *           cmsIT8EnumProperties, and cmsIT8EnumDataFormat were not covered.
   * IMPLEMENTATION: This block creates a new cmsContext and an IT8 handle to
   *                 programmatically exercise the uncovered IT8 API functions.
   *                 Using a context and calling cmsDeleteContext at the end ensures
   *                 all allocated memory, including the results from enumeration
   *                 functions, is safely freed.
   */
  if (size > 16) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHANDLE hIT8_alloc = cmsIT8Alloc(context);
    if (hIT8_alloc) {
      char key[9];
      char value[9];
      memcpy(key, data, 8);
      key[8] = '\0';
      memcpy(value, data + 8, 8);
      value[8] = '\0';

      cmsIT8SetPropertyStr(hIT8_alloc, key, value);

      // These calls exercise the enumeration functions. The returned lists are
      // managed by the context and will be freed by cmsDeleteContext.
      char **propertyNames = NULL;
      cmsIT8EnumProperties(hIT8_alloc, &propertyNames);
      char **sampleNames = NULL;
      cmsIT8EnumDataFormat(hIT8_alloc, &sampleNames);

      cmsIT8Free(hIT8_alloc);
    }
    cmsDeleteContext(context);
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