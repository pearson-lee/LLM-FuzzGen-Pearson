#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

// This flag is used in the cmsTransform2DeviceLink function but not exposed in headers.
#define cmsFLAGS_GUID 0x04000000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed _cmsReadCHAD had low
   *           coverage. The line-level report confirmed the branch at line 102
   *           where Tag is NULL is never taken.
   * IMPLEMENTATION: Create a placeholder profile without a
   *                 cmsSigChromaticAdaptationTag and call _cmsReadCHAD on it
   *                 to exercise the uncovered error-handling path.
   */
  cmsHPROFILE hProfile_empty = cmsCreateProfilePlaceholder(ctx);
  if (hProfile_empty) {
    cmsMAT3 chad;
    // This will call the uncovered part of _cmsReadCHAD
    _cmsReadCHAD(&chad, hProfile_empty);
    cmsCloseProfile(hProfile_empty);
  }

  /*
   * ANALYSIS: The function-level coverage report showed
   *           cmsDetectDestinationBlackPoint has low coverage (34%). The
   *           line-level report shows that many paths, especially the main
   *           loops for curve fitting, are not taken. This is often because the
   *           profile is not suitable for the operation.
   * IMPLEMENTATION: Create a standard sRGB profile, which is a well-behaved
   *                 and common profile type. Then call
   *                 cmsDetectDestinationBlackPoint with various intents to
   *                 trigger the complex internal logic.
   */
  cmsHPROFILE hProfile_srgb = cmsCreate_sRGBProfileTHR(ctx);
  if (hProfile_srgb) {
    if (size >= sizeof(cmsUInt32Number)) {
        cmsCIEXYZ black_point;
        cmsUInt32Number intent;
        memcpy(&intent, data, sizeof(cmsUInt32Number));
        data += sizeof(cmsUInt32Number);
        size -= sizeof(cmsUInt32Number);
        intent = INTENT_PERCEPTUAL + (intent % (INTENT_ABSOLUTE_COLORIMETRIC - INTENT_PERCEPTUAL + 1));
        cmsDetectDestinationBlackPoint(&black_point, hProfile_srgb, intent, 0);
    }
    cmsCloseProfile(hProfile_srgb);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsIT8SetData has very
   *           low coverage (29%). The line-level report shows that the
   *           function returns early because `LocateSample` fails, and many
   *           branches for allocating and writing data are never hit.
   * IMPLEMENTATION: Create a valid IT8 object, define properties and data
   *                 formats, and then call cmsIT8SetData to populate it. This
   *                 exercises the data allocation and writing paths.
   */
  cmsHANDLE hIT8 = cmsIT8Alloc(ctx);
  if (hIT8) {
    cmsIT8SetPropertyStr(hIT8, "ORIGINATOR", "fuzzer");
    cmsIT8SetDataFormat(hIT8, 0, "SAMPLE_ID");
    cmsIT8SetDataFormat(hIT8, 1, "RGB_R");

    if (size > 0) {
        uint8_t choice = data[0];
        data++;
        size--;

        if (choice % 2) {
            char patch[11] = {0};
            char sample[11] = {0};
            char val[11] = {0};

            size_t len1 = size > 10 ? 10 : size;
            memcpy(patch, data, len1);
            data += len1;
            size -= len1;

            size_t len2 = size > 10 ? 10 : size;
            memcpy(sample, data, len2);
            data += len2;
            size -= len2;

            size_t len3 = size > 10 ? 10 : size;
            memcpy(val, data, len3);
            data += len3;
            size -= len3;
            
            cmsIT8SetData(hIT8, patch, sample, val);
        } else {
            cmsIT8SetData(hIT8, "A1", "SAMPLE_ID", "A1");
            cmsIT8SetData(hIT8, "A1", "RGB_R", "0.4");
        }
    }
    cmsIT8Free(hIT8);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsGDBCheckPoint with
   *           0% coverage. This function checks if a color is within a gamut
   *           boundary description (GBD). It requires a GBD to be populated first.
   * IMPLEMENTATION: Create a GBD object using cmsGBDAlloc, add several points
   *                 to it using cmsGDBAddPoint, and then call cmsGDBCheckPoint
   *                 to test if a fuzzer-generated point is inside the gamut.
   *                 This covers both the creation and checking of GBDs.
   */
  cmsHANDLE hGDB = cmsGBDAlloc(ctx);
  if (hGDB) {
    if (size >= sizeof(int)) {
        int num_points;
        memcpy(&num_points, data, sizeof(int));
        data += sizeof(int);
        size -= sizeof(int);
        num_points = 1 + (abs(num_points) % 10);

        for (int i = 0; i < num_points; ++i) {
            if (size < sizeof(cmsCIELab)) {
                break;
            }
            cmsCIELab lab;
            memcpy(&lab, data, sizeof(cmsCIELab));
            data += sizeof(cmsCIELab);
            size -= sizeof(cmsCIELab);
            
            lab.L = fmod(lab.L, 100.0);
            if (lab.L < 0) lab.L += 100.0;
            lab.a = fmod(lab.a, 255.0) - 128.0;
            lab.b = fmod(lab.b, 255.0) - 128.0;

            cmsGDBAddPoint(hGDB, &lab);
        }
    }

    if (size >= sizeof(cmsCIELab)) {
        cmsCIELab check_lab;
        memcpy(&check_lab, data, sizeof(cmsCIELab));
        data += sizeof(cmsCIELab);
        size -= sizeof(cmsCIELab);
        
        check_lab.L = fmod(check_lab.L, 100.0);
        if (check_lab.L < 0) check_lab.L += 100.0;
        check_lab.a = fmod(check_lab.a, 255.0) - 128.0;
        check_lab.b = fmod(check_lab.b, 255.0) - 128.0;
        
        cmsGDBCheckPoint(hGDB, &check_lab);
    }

    cmsGBDFree(hGDB);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsTransform2DeviceLink
   *           has multiple uncovered branches, particularly those handling
   *           floating-point pipelines (e.g., line 2090) and the cmsFLAGS_GUID
   *           flag (line 2114).
   * IMPLEMENTATION: Create a multi-profile transform using sRGB and Lab
   *                 profiles, explicitly enabling the floating-point pipeline
   *                 via cmsFLAGS_NOCACHE and exercising the GUID generation
   *                 path via cmsFLAGS_GUID. This directly targets the
   *                 uncovered logic within cmsTransform2DeviceLink.
   */
  cmsHPROFILE hProfiles[2];
  hProfiles[0] = cmsCreate_sRGBProfileTHR(ctx);
  hProfiles[1] = cmsCreateLab4ProfileTHR(ctx, NULL);
  if (hProfiles[0] != NULL && hProfiles[1] != NULL) {
    cmsHTRANSFORM hTransform = cmsCreateMultiprofileTransformTHR(
        ctx, hProfiles, 2, TYPE_RGB_8, TYPE_Lab_DBL,
        INTENT_PERCEPTUAL, cmsFLAGS_NOCACHE);
    if (hTransform != NULL) {
      cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hTransform, 4.3, cmsFLAGS_GUID);
      if (hDeviceLink != NULL) {
        cmsCloseProfile(hDeviceLink);
      }
      cmsDeleteTransform(hTransform);
    }
  }
  if (hProfiles[0] != NULL) {
    cmsCloseProfile(hProfiles[0]);
  }
  if (hProfiles[1] != NULL) {
    cmsCloseProfile(hProfiles[1]);
  }

  cmsDeleteContext(ctx);
  return 0;
}