#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

#define _FUZZ_TARGET_NAME "lcms_fuzzer"

// Helper function to create a temporary file with the given content
static char *create_temp_file(const uint8_t *data, size_t size) {
  char *path = (char *)malloc(256);
  if (!path) {
    return NULL;
  }
  snprintf(path, 256, "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

  FILE *fp = fopen(path, "wb");
  if (!fp) {
    free(path);
    return NULL;
  }

  fwrite(data, 1, size, fp);
  fclose(fp);
  return path;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20) {
    return 0;
  }

  // Create a FuzzedDataProvider to consume the input data
  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  // Extract a chunk of data for file content
  size_t file_size = size > 1024 ? 1024 : size;
  char *path = create_temp_file(data, file_size);
  if (!path) {
    cmsDeleteContext(context);
    return 0;
  }

  // Consume data for API calls
  size_t remaining_size = size - file_size;
  const uint8_t *remaining_data = data + file_size;

  /*
   * ANALYSIS: The function `cmsOpenIOhandlerFromFile` has low coverage, particularly in its error handling paths.
   * IMPLEMENTATION: The following code block attempts to open the temporary file with various access modes,
   *                 including invalid ones, to trigger these error paths.
   */
  if (remaining_size > 0) {
    const char *access_modes[] = {"r", "w", "a", "rb", "wb", "ab", "r+", "w+", "a+", "rt", "wt", "at", "e", "re", "we", "ae"};
    int mode_index = remaining_data[0] % (sizeof(access_modes) / sizeof(access_modes[0]));
    cmsIOHANDLER *io = cmsOpenIOhandlerFromFile(context, path, access_modes[mode_index]);
    if (io) {
      cmsCloseIOhandler(io);
    }
  }

  /*
   * ANALYSIS: The function `cmsIT8SetTableByLabel` has several uncovered branches, including a NULL check for `cField`.
   * IMPLEMENTATION: The following code block sometimes passes a NULL `cField` to exercise this path.
   *                 It also creates an IT8 object and sets data to trigger other logic paths.
   */
  cmsHANDLE it8 = cmsIT8Alloc(context);
  if (it8) {
    if (remaining_size > 1) {
      if (remaining_data[1] % 2 == 0) {
        cmsIT8SetTableByLabel(it8, "D50", "white", "MyWhite");
      } else {
        cmsIT8SetTableByLabel(it8, NULL, NULL, NULL);
      }
    }
    cmsIT8Free(it8);
  }

  /*
   * ANALYSIS: The function `DefaultEvalParametricFn` has a large switch statement with many uncovered cases.
   * IMPLEMENTATION: The following code block creates a parametric tone curve with a fuzzed type and parameters,
   *                 then evaluates it to cover more cases in the switch statement.
   */
  if (remaining_size > 12) {
    int type = (int)remaining_data[2] % 115 - 10; // Generate types from -10 to 104
    cmsFloat64Number params[10];
    for (int i = 0; i < 10; ++i) {
      params[i] = (cmsFloat64Number)remaining_data[3 + i] / 255.0;
    }
    cmsToneCurve *curve = cmsBuildParametricToneCurve(context, type, params);
    if (curve) {
      cmsEvalToneCurveFloat(curve, 0.5f);
      cmsFreeToneCurve(curve);
    }
  }

  /*
   * ANALYSIS: The functions `cmsMLUtranslationsCount` and `cmsMLUtranslationsCodes` had 0% coverage.
   * IMPLEMENTATION: The following code block creates a multi-localized Unicode object (MLU),
   *                 sets some data, and then calls the uncovered functions. Added more data to
   *                 potentially trigger `GrowMLUtable`.
   */
  cmsMLU *mlu = cmsMLUalloc(context, 10);
  if (mlu) {
    cmsMLUsetASCII(mlu, "en", "US", "Hello");
    cmsMLUsetASCII(mlu, "es", "ES", "Hola");
    char obtained_language[3];
    char obtained_country[3];
    if (remaining_size > 6) {
      char lang[3] = {0};
      char country[3] = {0};
      lang[0] = remaining_data[3];
      lang[1] = remaining_data[4];
      country[0] = remaining_data[5];
      country[1] = remaining_data[6];
      cmsMLUgetTranslation(mlu, lang, country, obtained_language, obtained_country);
    }
    cmsMLUtranslationsCount(mlu);
    cmsMLUtranslationsCodes(mlu, 0, obtained_language, obtained_country);
    cmsMLUfree(mlu);
  }

  /*
   * ANALYSIS: The function `cmsDetectDestinationBlackPoint` has many untested branches related to different
   *           intents and device classes.
   * IMPLEMENTATION: The following code block creates a profile with a fuzzed device class and intent,
   *                 then calls `cmsDetectDestinationBlackPoint` to trigger these different logic paths.
   */
  cmsHPROFILE profile = cmsCreate_sRGBProfile();
  if (profile) {
    cmsCIEXYZ black_point;
    if (remaining_size > 2) {
      int intent = remaining_data[1] % 4;
      cmsDetectDestinationBlackPoint(&black_point, profile, intent, 0);
    }
    cmsCloseProfile(profile);
  }

  /*
   * ANALYSIS: The function `cmsSmoothToneCurve` had a branch for detecting "poles" (degenerated curves)
   *           that was never hit.
   * IMPLEMENTATION: The following code creates a tabulated tone curve with some maximum values (65535)
   *                 and then calls `cmsSmoothToneCurve` on it. This is intended to trigger the "poles"
   *                 detection logic.
   */
  if (remaining_size > 5) {
      cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(context, 3, (cmsUInt16Number[]){0, 65535, 65535});
      if (curve) {
          cmsSmoothToneCurve(curve, (double)remaining_data[4]);
          cmsFreeToneCurve(curve);
      }
  }

  /*
   * ANALYSIS: The coverage report for `cmsDeleteTransform` showed that the logic for freeing
   *           the 'Sequence' member was never executed. This is populated by transforms involving
   *           multiple profiles.
   * IMPLEMENTATION: The following code creates a multi-profile transform using two sRGB profiles
   *                 and then immediately deletes it. This ensures that the `Sequence` member is
   *                 allocated and subsequently freed, covering the missed branch.
   */
  if (remaining_size > 1) {
      cmsHPROFILE profiles[2];
      profiles[0] = cmsCreate_sRGBProfile();
      profiles[1] = cmsCreate_sRGBProfile();
      if (profiles[0] && profiles[1]) {
          cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, 2, TYPE_RGB_8, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
          if (transform) {
              cmsDeleteTransform(transform);
          }
      }
      if (profiles[0]) cmsCloseProfile(profiles[0]);
      if (profiles[1]) cmsCloseProfile(profiles[1]);
  }


  unlink(path);
  free(path);
  cmsDeleteContext(context);
  return 0;
}