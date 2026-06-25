#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "lcms_fuzzer"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  int selector = data[0] % 7;
  data++;
  size--;

  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  switch (selector) {
  case 0: {
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(ctx);
    if (hProfile) {
      cmsPipeline *p = cmsPipelineAlloc(ctx, 3, 3);
      if (p) {
        cmsStage *clut_stage = cmsStageAllocCLut16bit(ctx, 2, 3, 3, NULL);
        if (clut_stage) {
          cmsPipelineInsertStage(p, cmsAT_BEGIN, clut_stage);
          cmsWriteTag(hProfile, cmsSigBToA0Tag, p);
        }
        cmsPipelineFree(p);
      }

      cmsCIEXYZ BlackPoint;
      cmsDetectDestinationBlackPoint(&BlackPoint, hProfile, INTENT_PERCEPTUAL, 0);
      cmsCloseProfile(hProfile);
    }
    break;
  }

  case 1: {
    cmsHANDLE hIT8 = cmsIT8Alloc(ctx);
    if (hIT8) {
      if (size > 0) {
        char *table = (char *)malloc(size + 1);
        if (table) {
          memcpy(table, data, size);
          table[size] = 0;
          cmsIT8SetTable(hIT8, table);
          free(table);
        }
      }
      cmsIT8Free(hIT8);
    }
    break;
  }

  case 2: {
    if (size > 0) {
      char path[256];
      snprintf(path, sizeof(path), "/tmp/%s.cube", _FUZZ_TARGET_NAME);

      FILE *fp = fopen(path, "wb");
      if (fp) {
        fwrite(data, 1, size, fp);
        fclose(fp);

        cmsHPROFILE h = cmsCreateDeviceLinkFromCubeFileTHR(ctx, path);
        if (h) {
          cmsCloseProfile(h);
        }
        unlink(path);
      }
    }
    break;
  }

  case 3: {
    if (size >= (sizeof(cmsFloat64Number) * 6)) {
      cmsCurveSegment Segments[2];
      memset(Segments, 0, sizeof(Segments));

      Segments[0].x0 = 0.0f;
      Segments[0].x1 = 0.5f;
      Segments[0].Type = 6;
      memcpy(Segments[0].Params, data, sizeof(cmsFloat64Number) * 3);

      Segments[1].x0 = 0.5f;
      Segments[1].x1 = 1.0f;
      Segments[1].Type = 6;
      memcpy(Segments[1].Params, data + sizeof(cmsFloat64Number) * 3, sizeof(cmsFloat64Number) * 3);

      cmsToneCurve *tc = cmsBuildSegmentedToneCurve(ctx, 2, Segments);
      if (tc) {
        cmsSmoothToneCurve(tc, 0.1);
        cmsFreeToneCurve(tc);
      }
    }
    break;
  }

  case 4: {
    if (size >= (sizeof(cmsFloat64Number) * 4 + sizeof(cmsUInt32Number) * 2)) {
      cmsFloat64Number Bright, Contrast, Hue, Saturation;
      cmsUInt32Number TempSrc, TempDest;
      size_t offset = 0;

      memcpy(&Bright, data + offset, sizeof(cmsFloat64Number));
      offset += sizeof(cmsFloat64Number);
      memcpy(&Contrast, data + offset, sizeof(cmsFloat64Number));
      offset += sizeof(cmsFloat64Number);
      memcpy(&Hue, data + offset, sizeof(cmsFloat64Number));
      offset += sizeof(cmsFloat64Number);
      memcpy(&Saturation, data + offset, sizeof(cmsFloat64Number));
      offset += sizeof(cmsFloat64Number);
      memcpy(&TempSrc, data + offset, sizeof(cmsUInt32Number));
      offset += sizeof(cmsUInt32Number);
      memcpy(&TempDest, data + offset, sizeof(cmsUInt32Number));

      cmsHPROFILE h = cmsCreateBCHSWabstractProfileTHR(ctx, 16, Bright, Contrast, Hue, Saturation, TempSrc, TempDest);
      if (h) {
        cmsCloseProfile(h);
      }
    }
    break;
  }
  /*
   * ANALYSIS: The line-level coverage report for `cmsDetectDestinationBlackPoint`
   *           showed that a large portion of the function was uncovered. This was
   *           because it was only being called with `INTENT_PERCEPTUAL` and on a
   *           limited variety of profile types.
   * IMPLEMENTATION: This new case creates various types of profiles (RGB, Gray, Lab)
   *                 and calls `cmsDetectDestinationBlackPoint` with
   *                 `INTENT_RELATIVE_COLORIMETRIC` and `INTENT_SATURATION` to
   *                 exercise the uncovered code paths related to curve fitting and
   *                 black point estimation for those intents and color spaces.
   */
  case 5: {
    if (size < 1) {
      break;
    }
    cmsHPROFILE hProfile = NULL;
    int profile_type = data[0] % 3;
    data++;
    size--;

    switch (profile_type) {
    case 0: {
      cmsCIExyYTRIPLE primaries = {{0.64, 0.33, 1.0}, {0.21, 0.71, 1.0}, {0.15, 0.06, 1.0}};
      cmsToneCurve *gamma[3];
      gamma[0] = cmsBuildGamma(ctx, 2.2);
      gamma[1] = cmsBuildGamma(ctx, 2.2);
      gamma[2] = cmsBuildGamma(ctx, 2.2);
      if (gamma[0] && gamma[1] && gamma[2]) {
        hProfile = cmsCreateRGBProfileTHR(ctx, NULL, &primaries, gamma);
      }
      if (gamma[0])
        cmsFreeToneCurve(gamma[0]);
      if (gamma[1])
        cmsFreeToneCurve(gamma[1]);
      if (gamma[2])
        cmsFreeToneCurve(gamma[2]);
      break;
    }
    case 1: {
      cmsToneCurve *gamma = cmsBuildGamma(ctx, 2.2);
      if (gamma) {
        hProfile = cmsCreateGrayProfileTHR(ctx, NULL, gamma);
        cmsFreeToneCurve(gamma);
      }
      break;
    }
    case 2: {
      hProfile = cmsCreateLab4ProfileTHR(ctx, NULL);
      break;
    }
    }

    if (hProfile) {
      cmsCIEXYZ BlackPoint;
      cmsDetectDestinationBlackPoint(&BlackPoint, hProfile, INTENT_RELATIVE_COLORIMETRIC, 0);
      cmsDetectDestinationBlackPoint(&BlackPoint, hProfile, INTENT_SATURATION, 0);
      cmsCloseProfile(hProfile);
    }
    break;
  }
  /*
   * ANALYSIS: The function-level coverage report showed that `cmsSetEncodedICCversion`
   *           and `cmsGetHeaderCreationDateTime` in `cmsio0.c` had zero coverage.
   * IMPLEMENTATION: This new case creates a placeholder profile and directly calls
   *                 these previously uncovered header-related functions to improve
   *                 coverage.
   */
  case 6: {
    cmsHPROFILE h = cmsCreateProfilePlaceholder(ctx);
    if (h) {
      cmsSetEncodedICCversion(h, 0x04030201);
      struct tm ctm;
      cmsGetHeaderCreationDateTime(h, &ctm);
      cmsSetHeaderRenderingIntent(h, INTENT_SATURATION);
      cmsCloseProfile(h);
    }
    break;
  }
  }

  cmsDeleteContext(ctx);
  return 0;
}