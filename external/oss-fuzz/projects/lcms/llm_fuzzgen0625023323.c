#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "lcms_fuzzer"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /*
   * ANALYSIS: The detailed fuzz target coverage report showed several branches
   *           dependent on the input size were never taken, such as those for
   *           populating cmsCIExyY and cmsCIELab structures.
   * IMPLEMENTATION: The minimum size is increased from 12 to 64 bytes to make
   *                 it more likely that larger data structures can be populated
   *                 from the fuzzer input, thus reaching more code paths.
   */
  if (size < 64) {
    return 0;
  }

  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

  FILE *fp = fopen(path, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, 1, size, fp);
  fclose(fp);

  /*
   * ANALYSIS: The function-level coverage report showed
   * cmsCreateDeviceLinkFromCubeFileTHR had zero hits. The line-level report
   * confirmed this.
   * IMPLEMENTATION: The following code block calls
   * cmsCreateDeviceLinkFromCubeFile to exercise this previously uncovered
   * function.
   */
  cmsHPROFILE hCube = cmsCreateDeviceLinkFromCubeFile(path);
  if (hCube) {
    cmsCloseProfile(hCube);
  }

  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (!hProfile) {
    unlink(path);
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   * cmsDetectDestinationBlackPoint had low branch coverage. The line-level
   * report confirmed this was in the initial checks for device class and intent.
   * IMPLEMENTATION: The following code block calls
   * cmsDetectDestinationBlackPoint with a fuzzed intent and device class to
   * exercise these uncovered branches.
   */
  cmsCIEXYZ black_point;
  cmsSetDeviceClass(hProfile, data[0]);
  cmsDetectDestinationBlackPoint(&black_point, hProfile, data[1], 0);

  /*
   * ANALYSIS: The function-level coverage report showed cmsOpenIOhandlerFromMem
   * had low branch coverage. The line-level report confirmed this was in the
   * error handling paths.
   * IMPLEMENTATION: The following code block calls cmsOpenIOhandlerFromMem with
   * a fuzzed access mode to exercise these uncovered error handling paths.
   */
  char mode_char = (data[2] % 2 == 0) ? 'r' : 'w';
  char access_mode[2] = {mode_char, '\0'};
  cmsIOHANDLER *io = cmsOpenIOhandlerFromMem(NULL, (void *)data, size, access_mode);
  if (io) {
    cmsCloseIOhandler(io);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsWriteTag had low
   * branch coverage. The line-level report confirmed this was in the error
   * handling paths.
   * IMPLEMENTATION: The following code block calls cmsWriteTag with a fuzzed
   * signature to exercise these uncovered error handling paths.
   */
  cmsTagSignature sig = (cmsTagSignature)data[3];
  cmsWriteTag(hProfile, sig, (void *)data);

  /*
   * ANALYSIS: The function-level coverage report showed many Type_*_Read functions
   *           in cmstypes.c with zero coverage, for example Type_S15Fixed16_Read.
   *           This is because the fuzzer was not creating profiles with these specific
   *           tag types.
   * IMPLEMENTATION: The following code block explicitly writes a tag of type
   *                 cmsSigS15Fixed16ArrayType containing fuzzer data to the profile
   *                 and then reads it back. This directly targets the uncovered cmsReadTag
   *                 path for this type, improving coverage in cmstypes.c.
   */
  if (size >= 8) {
    cmsFloat64Number data_double;
    memcpy(&data_double, data, sizeof(cmsFloat64Number));
    if (cmsWriteTag(hProfile, cmsSigS15Fixed16ArrayType, &data_double)) {
      cmsReadTag(hProfile, cmsSigS15Fixed16ArrayType);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsSmoothToneCurve had
   * low branch coverage. The line-level report confirmed this was in the lambda
   * < 0 check.
   * IMPLEMENTATION: The following code block calls cmsSmoothToneCurve with a
   * fuzzed lambda value to exercise this uncovered branch.
   */
  cmsToneCurve *tc = cmsBuildTabulatedToneCurve16(NULL, 256, NULL);
  if (tc) {
    double lambda;
    if (size >= sizeof(double) + 4) {
      memcpy(&lambda, data + 4, sizeof(lambda));
      cmsSmoothToneCurve(tc, lambda);
    }
    cmsFreeToneCurve(tc);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsDetectTAC had low
   * branch coverage. The line-level report confirmed this was because the
   * device class was not cmsSigOutputClass.
   * IMPLEMENTATION: The following code block creates a gray profile, sets its
   * device class to cmsSigOutputClass, and then calls cmsDetectTAC to
   * exercise this previously uncovered function.
   */
  cmsCIExyY whitePoint;
  if (size >= sizeof(whitePoint)) {
    memcpy(&whitePoint, data, sizeof(whitePoint));
    cmsHPROFILE grayProfile = cmsCreateGrayProfileTHR(NULL, &whitePoint, NULL);
    if (grayProfile) {
      cmsSetDeviceClass(grayProfile, cmsSigOutputClass);
      cmsDetectTAC(grayProfile);
      cmsCloseProfile(grayProfile);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsGetPostScriptCRD
   * and cmsGetPostScriptCSA had zero hits.
   * IMPLEMENTATION: The following code block calls these functions to exercise
   * them. An sRGB profile is created as a suitable input.
   */
  cmsHPROFILE srgbProfile = cmsCreate_sRGBProfile();
  if (srgbProfile) {
    char buffer[1024];
    cmsGetPostScriptCRD(NULL, srgbProfile, 0, 0, buffer, sizeof(buffer));
    cmsGetPostScriptCSA(NULL, srgbProfile, 0, 0, buffer, sizeof(buffer));
    cmsCloseProfile(srgbProfile);
  }

  /*
   * ANALYSIS: The detailed coverage report for the fuzz target showed that the
   *           'if (hLink)' check on line 139 was never true, meaning
   *           cmsCreateLinearizationDeviceLinkTHR always failed. The function signature is
   *           cmsCreateLinearizationDeviceLinkTHR(cmsContext, cmsColorSpaceSignature, const cmsToneCurve **).
   *           The existing code was calling it with (NULL, curves, 1), passing the curves array
   *           as the color space and the integer 1 as the curves array.
   * IMPLEMENTATION: The following code block corrects the call by passing a valid
   *                 colorspace (cmsSigGrayData) and the array of tone curves correctly.
   *                 This allows the function to succeed, covering its intended logic.
   */
  cmsToneCurve *curve = cmsBuildGamma(NULL, 2.2);
  if (curve) {
    cmsToneCurve *curves[1] = {curve};
    cmsHPROFILE hLink = cmsCreateLinearizationDeviceLinkTHR(NULL, cmsSigGrayData, (const cmsToneCurve **)curves);
    if (hLink) {
      cmsCloseProfile(hLink);
    }
    cmsFreeToneCurve(curve);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   *           cmsCreateBCHSWabstractProfileTHR was completely uncovered.
   * IMPLEMENTATION: The following code block calls this function with fuzzer-
   *                 derived data to exercise its logic. It creates an abstract
   *                 profile for Brightness/Contrast/Hue/Saturation adjustment.
   */
  if (size >= 44) {
    cmsFloat64Number bright, contrast, hue, saturation;
    memcpy(&bright, data + 12, sizeof(cmsFloat64Number));
    memcpy(&contrast, data + 20, sizeof(cmsFloat64Number));
    memcpy(&hue, data + 28, sizeof(cmsFloat64Number));
    memcpy(&saturation, data + 36, sizeof(cmsFloat64Number));
    cmsHPROFILE bchsProfile = cmsCreateBCHSWabstractProfileTHR(NULL, 16, bright, contrast, hue, saturation, 5000, 5000);
    if (bchsProfile) {
      cmsCloseProfile(bchsProfile);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed several functions in cmssm.c
   * related to Gamut Boundary Description (GBD) had zero hits, including cmsGBDAlloc
   * and cmsGDBAddPoint.
   * IMPLEMENTATION: The following code block allocates a GBD, adds a point to it
   * using fuzzer data, and then frees it to improve coverage in cmssm.c.
   */
  if (size >= sizeof(cmsCIELab)) {
    cmsHANDLE hGDB = cmsGBDAlloc(NULL);
    if (hGDB) {
      cmsCIELab Lab;
      memcpy(&Lab, data, sizeof(cmsCIELab));
      cmsGDBAddPoint(hGDB, &Lab);
      cmsGBDFree(hGDB);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed many functions in cmscgats.c
   * related to IT8 table handling were uncovered, including cmsIT8LoadFromFile and
   * cmsIT8GetPropertyDbl.
   * IMPLEMENTATION: The following code block attempts to load an IT8 table from the
   * temporary file created by the fuzzer and calls related functions to improve coverage.
   */
  cmsHANDLE hIT8 = cmsIT8LoadFromFile(NULL, path);
  if (hIT8) {
    cmsIT8GetPropertyDbl(hIT8, "some_property");
    if (size > 2) {
      cmsIT8GetDataRowColDbl(hIT8, data[0], data[1]);
    }
    cmsIT8Free(hIT8);
  }

  cmsCloseProfile(hProfile);
  unlink(path);

  return 0;
}