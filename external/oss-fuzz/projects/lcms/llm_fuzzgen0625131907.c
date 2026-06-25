#include "lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _FUZZ_TARGET_NAME "lcms_fuzzer"

// Forward declaration
static cmsHPROFILE CreateProfileFromData(cmsContext ContextID, const uint8_t *Data, size_t Size);

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 10) {
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

  // Create a profile from the first half of the data
  cmsHPROFILE hProfile = CreateProfileFromData(ContextID, profileData, profileDataSize);

  if (hProfile) {
    /*
     * ANALYSIS: The function cmsDetectDestinationBlackPoint has very low coverage (34.45%).
     *           The line-level report shows that the main logic is often skipped due to
     *           initial checks on the profile's device class and the rendering intent.
     * IMPLEMENTATION: Call cmsDetectDestinationBlackPoint with the created profile.
     *                 The intent is determined by the fuzzer input to explore different paths.
     */
    cmsCIEXYZ BlackPoint;
    uint32_t intent = otherData[0] % 5; // Use fuzzer data to select an intent
    cmsDetectDestinationBlackPoint(&BlackPoint, hProfile, intent, 0);

    cmsCloseProfile(hProfile);
  }

  // Create and exercise a tone curve
  if (otherDataSize > 4) {
    /*
     * ANALYSIS: The function cmsSmoothToneCurve has uncovered branches related to NULL input
     *           and when the number of entries is too large.
     * IMPLEMENTATION: Create a tone curve and call cmsSmoothToneCurve. Also, call it with
     *                 NULL to exercise the uncovered error-handling path. The lambda value
     *                 is derived from the fuzzer input.
     */
    cmsToneCurve *curve = cmsBuildTabulatedToneCurve16(ContextID, 256, NULL);
    if (curve) {
      double lambda = *(double *)(otherData);
      cmsSmoothToneCurve(curve, lambda);
      cmsFreeToneCurve(curve);
    }
    // Test the NULL case.
    cmsSmoothToneCurve(NULL, 1.0);
  }

  // Create a temporary file to test file-based APIs
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);
  FILE *fp = fopen(path, "wb");
  if (fp) {
    fwrite(otherData, 1, otherDataSize, fp);
    fclose(fp);

    /*
     * ANALYSIS: The function cmsIT8LoadFromFile has uncovered error paths, particularly
     *           when fopen fails.
     * IMPLEMENTATION: Call cmsIT8LoadFromFile with the path to the temporary file created
     *                 from fuzzer data. This will test the file parsing logic.
     */
    cmsHANDLE hIT8 = cmsIT8LoadFromFile(ContextID, path);
    if (hIT8) {
      /*
       * ANALYSIS: The function cmsCreateDeviceLinkFromCubeFileTHR has several uncovered
       *           branches.
       * IMPLEMENTATION: If cmsIT8LoadFromFile is successful, use the resulting handle
       *                 to call cmsCreateDeviceLinkFromCubeFileTHR to maximize coverage.
       */
      cmsHPROFILE hCube = cmsCreateDeviceLinkFromCubeFileTHR(ContextID, path);
      if (hCube) {
        cmsCloseProfile(hCube);
      }
      cmsIT8Free(hIT8);
    }
    unlink(path);
  }

  // Test the error path for cmsIT8LoadFromFile with a non-existent file
  cmsIT8LoadFromFile(ContextID, "/tmp/nonexistentfile12345.tmp");

  cmsDeleteContext(ContextID);
  return 0;
}

// Helper function to create a profile from data
static cmsHPROFILE CreateProfileFromData(cmsContext ContextID, const uint8_t *Data, size_t Size) {
  /*
   * ANALYSIS: Creating profiles from memory is a good way to start exercising the library.
   *           The function cmsOpenProfileFromMem has some uncovered error paths.
   * IMPLEMENTATION: Use cmsOpenProfileFromMem to create a profile that can be used
   *                 by other APIs.
   */
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(Data, Size);
  return hProfile;
}