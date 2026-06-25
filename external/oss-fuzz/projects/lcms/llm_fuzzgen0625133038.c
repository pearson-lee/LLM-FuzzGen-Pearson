#include "lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "lcms_fuzzer"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(cmsViewingConditions) + 10) {
    return 0;
  }

  cmsContext ContextID = cmsCreateContext(NULL, NULL);
  if (ContextID == NULL) {
    return 0;
  }

  // Use a portion of the data for profile creation
  size_t profileDataSize = Size / 2;
  const uint8_t *profileData = Data;

  // Use the other half for other operations
  const uint8_t *otherData = Data + profileDataSize;
  size_t otherDataSize = Size - profileDataSize;

  /*
   * ANALYSIS: The function cmsDupContext has several uncovered branches related
   *           to plugin handling. While we can't cover those without plugins,
   *           calling it ensures basic functionality is tested.
   * IMPLEMENTATION: Call cmsDupContext and immediately delete the duplicate
   *                 to ensure the duplication and deletion paths are exercised.
   */
  cmsContext DupContextID = cmsDupContext(ContextID, NULL);
  if (DupContextID) {
    cmsDeleteContext(DupContextID);
  }

  /*
   * ANALYSIS: The cmscam02.c file has functions with low coverage.
   *           Specifically, cmsCIECAM02Init has untested paths.
   * IMPLEMENTATION: Create a cmsViewingConditions struct populated with fuzzer
   *                 data and use it to initialize a CIECAM02 object. This
   *                 exercises the initialization and cleanup functions.
   */
  cmsViewingConditions vc;
  if (otherDataSize >= sizeof(cmsViewingConditions)) {
    memcpy(&vc, otherData, sizeof(cmsViewingConditions));
    cmsHANDLE hCIECAM02 = cmsCIECAM02Init(ContextID, &vc);
    if (hCIECAM02) {
      cmsCIECAM02Done(hCIECAM02);
    }
  }

  /*
   * ANALYSIS: The original fuzzer failed to create a valid profile from memory,
   *           blocking a large part of the test. Creating profiles
   *           programmatically is more reliable. The transform-related functions
   *           in cmsxform.c are largely uncovered.
   * IMPLEMENTATION: Create an sRGB and a Lab profile. Then, create a transform
   *                 between them. This allows exercising the core color
   *                 transformation pipeline, which is a critical part of lcms.
   */
  cmsHPROFILE hInProfile = cmsCreate_sRGBProfileTHR(ContextID);
  cmsHPROFILE hOutProfile = cmsCreateLab4ProfileTHR(ContextID, NULL);

  if (hInProfile && hOutProfile) {
    uint32_t intent = 0;
    if (otherDataSize > 0) {
      intent = otherData[0] % 5;
    }
    cmsHPROFILE hProfiles[] = {hInProfile, hOutProfile};
    cmsHTRANSFORM hTransform = cmsCreateMultiprofileTransformTHR(ContextID, hProfiles, 2, TYPE_RGB_8, TYPE_Lab_DBL, intent, 0);

    if (hTransform) {
      if (otherDataSize >= 3) {
        uint8_t rgb[3];
        memcpy(rgb, otherData, sizeof(rgb));
        cmsCIELab lab_out;
        cmsDoTransform(hTransform, rgb, &lab_out, 1);
      }
      cmsDeleteTransform(hTransform);
    }

    // Existing logic, now unblocked with a valid profile
    cmsCIEXYZ BlackPoint;
    cmsDetectDestinationBlackPoint(&BlackPoint, hInProfile, intent, 0);
  }

  if (hInProfile) {
    cmsCloseProfile(hInProfile);
  }
  if (hOutProfile) {
    cmsCloseProfile(hOutProfile);
  }

  // Create and exercise a tone curve
  if (otherDataSize > 4) {
    cmsToneCurve *curve = cmsBuildTabulatedToneCurve16(ContextID, 256, NULL);
    if (curve) {
      double lambda = 0;
      if (otherDataSize >= sizeof(double)) {
        memcpy(&lambda, otherData, sizeof(double));
      }
      cmsSmoothToneCurve(curve, lambda);
      cmsFreeToneCurve(curve);
    }
    cmsSmoothToneCurve(NULL, 1.0);
  }

  // Create a temporary file to test file-based APIs
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);
  FILE *fp = fopen(path, "wb");
  if (fp) {
    fwrite(otherData, 1, otherDataSize, fp);
    fclose(fp);

    cmsHANDLE hIT8 = cmsIT8LoadFromFile(ContextID, path);
    if (hIT8) {
      cmsHPROFILE hCube = cmsCreateDeviceLinkFromCubeFileTHR(ContextID, path);
      if (hCube) {
        cmsCloseProfile(hCube);
      }
      cmsIT8Free(hIT8);
    }
    unlink(path);
  }

  cmsIT8LoadFromFile(ContextID, "/tmp/nonexistentfile12345.tmp");

  cmsDeleteContext(ContextID);
  return 0;
}