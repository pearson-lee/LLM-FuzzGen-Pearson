#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "lcms_fuzzer"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 12) {
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

  unlink(path);

  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (!hProfile) {
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

  cmsCloseProfile(hProfile);

  return 0;
}