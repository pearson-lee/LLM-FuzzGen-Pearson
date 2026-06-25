#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "/src/lcms/include/lcms2.h"

// The _FUZZ_TARGET_NAME macro is provided by the build system.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzzer"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char FUZZ_FILENAME1[256];
  snprintf(FUZZ_FILENAME1, sizeof(FUZZ_FILENAME1), "/tmp/%s.icc", _FUZZ_TARGET_NAME);

  // Create some profiles
  cmsHPROFILE hsRGB = cmsCreate_sRGBProfile();
  cmsHPROFILE hGray = cmsCreateGrayProfile(NULL, NULL);
  cmsToneCurve *gamma_curve = cmsBuildGamma(NULL, 2.2);
  cmsHPROFILE hCurve = NULL;
  if (gamma_curve != NULL) {
    cmsToneCurve *curves[] = {gamma_curve};
    hCurve = cmsCreateLinearizationDeviceLink(cmsSigGrayData, curves);
    cmsFreeToneCurve(gamma_curve);
  }
  cmsHPROFILE hNull = cmsCreateNULLProfile();

  // Create and use a transform if possible
  if (hsRGB != NULL && hCurve != NULL && hGray != NULL) {
    cmsHPROFILE hProfiles[] = {hsRGB, hCurve, hGray};
    cmsHPROFILE hTransform = cmsCreateMultiprofileTransform(hProfiles, 3, TYPE_RGB_8, TYPE_GRAY_8, INTENT_PERCEPTUAL, cmsFLAGS_GAMUTCHECK);
    if (hTransform != NULL) {
      uint8_t in[] = {0x12, 0x34, 0x56};
      uint8_t out[1]; // Gray8 is 1 byte
      cmsDoTransform(hTransform, in, out, 1);
      cmsDeleteTransform(hTransform);
    }
  }

  // Exercise black point detection
  if (hGray != NULL) {
    cmsCIEXYZ black_point;
    cmsDetectDestinationBlackPoint(&black_point, hGray, INTENT_ABSOLUTE_COLORIMETRIC, 0);
  }

  // Close profiles used in the transform
  if (hsRGB != NULL) {
    cmsCloseProfile(hsRGB);
  }
  if (hGray != NULL) {
    cmsCloseProfile(hGray);
  }
  if (hCurve != NULL) {
    cmsCloseProfile(hCurve);
  }

  // Exercise IT8 parsing from memory
  if (size > 0) {
    cmsHANDLE hIT8 = cmsIT8LoadFromMem(NULL, data, size);
    if (hIT8 != NULL) {
      cmsIT8Free(hIT8);
    }
  }

  // Exercise IT8 property manipulation
  if (size >= 16) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHANDLE hIT8_alloc = cmsIT8Alloc(context);
    if (hIT8_alloc != NULL) {
      char key[9];
      char value[9];
      memcpy(key, data, 8);
      key[8] = '\0';
      memcpy(value, data + 8, 8);
      value[8] = '\0';

      cmsIT8SetPropertyStr(hIT8_alloc, key, value);

      char **propertyNames = NULL;
      cmsIT8EnumProperties(hIT8_alloc, &propertyNames);
      char **sampleNames = NULL;
      cmsIT8EnumDataFormat(hIT8_alloc, &sampleNames);

      cmsIT8Free(hIT8_alloc);
    }
    cmsDeleteContext(context);
  }

  // Exercise profile saving and loading
  if (hNull != NULL) {
    if (cmsSaveProfileToFile(hNull, FUZZ_FILENAME1)) {
      cmsHPROFILE hFile = cmsOpenProfileFromFile(FUZZ_FILENAME1, "r");
      if (hFile != NULL) {
        if (cmsGetColorSpace(hFile) == cmsSigGrayData) {
          // Do something here
        }
        cmsCloseProfile(hFile);
      }
    }
    remove(FUZZ_FILENAME1);
    cmsCloseProfile(hNull);
  }

  return 0;
}