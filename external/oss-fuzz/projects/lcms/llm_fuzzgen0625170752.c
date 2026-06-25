#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static cmsBool PatchLUT(cmsStage *CLUT, const cmsUInt16Number At[], const cmsUInt16Number Value[], cmsUInt32Number nChannelsIn, cmsUInt32Number nChannelsOut) {
  _cmsStageCLutData *Grid = (_cmsStageCLutData *)CLUT->Data;
  cmsInterpParams *p16 = Grid->Params;
  cmsFloat64Number px, py, pz, pw;
  int x0, y0, z0, w0;
  int i, index;

  if (CLUT->Type != cmsSigCLutElemType) {
    cmsSignalError(CLUT->ContextID, cmsERROR_INTERNAL, "(internal) Attempt to PatchLUT on non-lut stage");
    return FALSE;
  }

  if (nChannelsIn == 4) {

    px = ((cmsFloat64Number)At[0] * (p16->Domain[0])) / 65535.0;
    py = ((cmsFloat64Number)At[1] * (p16->Domain[1])) / 65535.0;
    pz = ((cmsFloat64Number)At[2] * (p16->Domain[2])) / 65535.0;
    pw = ((cmsFloat64Number)At[3] * (p16->Domain[3])) / 65535.0;

    x0 = (int)floor(px);
    y0 = (int)floor(py);
    z0 = (int)floor(pz);
    w0 = (int)floor(pw);

    if (((px - x0) != 0) || ((py - y0) != 0) || ((pz - z0) != 0) || ((pw - w0) != 0))
      return FALSE; // Not on exact node

    index = (int)p16->opta[3] * x0 + (int)p16->opta[2] * y0 + (int)p16->opta[1] * z0 + (int)p16->opta[0] * w0;
  } else if (nChannelsIn == 3) {

    px = ((cmsFloat64Number)At[0] * (p16->Domain[0])) / 65535.0;
    py = ((cmsFloat64Number)At[1] * (p16->Domain[1])) / 65535.0;
    pz = ((cmsFloat64Number)At[2] * (p16->Domain[2])) / 65535.0;

    x0 = (int)floor(px);
    y0 = (int)floor(py);
    z0 = (int)floor(pz);

    if (((px - x0) != 0) || ((py - y0) != 0) || ((pz - z0) != 0))
      return FALSE; // Not on exact node

    index = (int)p16->opta[2] * x0 + (int)p16->opta[1] * y0 + (int)p16->opta[0] * z0;
  } else if (nChannelsIn == 1) {

    px = ((cmsFloat64Number)At[0] * (p16->Domain[0])) / 65535.0;

    x0 = (int)floor(px);

    if (((px - x0) != 0))
      return FALSE; // Not on exact node

    index = (int)p16->opta[0] * x0;
  } else {
    cmsSignalError(CLUT->ContextID, cmsERROR_INTERNAL, "(internal) %d Channels are not supported on PatchLUT", nChannelsIn);
    return FALSE;
  }

  for (i = 0; i < (int)nChannelsOut; i++)
    Grid->Tab.T[index + i] = Value[i];

  return TRUE;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  cmsHPROFILE profile_from_mem = cmsOpenProfileFromMemTHR(ctx, data, size);
  if (profile_from_mem) {
    cmsCloseProfile(profile_from_mem);
  }

  char *it8_data = malloc(size + 5);
  if (it8_data) {
    memcpy(it8_data, "CGAT", 4);
    memcpy(it8_data + 4, data, size);
    it8_data[size + 4] = 0;
    cmsHANDLE it8_handle = cmsIT8LoadFromMem(ctx, (const void *)it8_data, size + 4);
    if (it8_handle) {
      cmsIT8Free(it8_handle);
    }
    free(it8_data);
  }

  cmsHPROFILE profiles[3];
  profiles[0] = cmsCreate_sRGBProfileTHR(ctx);

  cmsToneCurve *tone_curve = cmsBuildGamma(ctx, 2.2);
  profiles[1] = cmsCreateGrayProfileTHR(ctx, NULL, tone_curve);
  if (tone_curve) {
    cmsFreeToneCurve(tone_curve);
  }

  profiles[2] = cmsOpenProfileFromMemTHR(ctx, data, size);

  if (profiles[0] && profiles[1] && profiles[2]) {
    cmsUInt32Number intents[] = {INTENT_PERCEPTUAL, INTENT_RELATIVE_COLORIMETRIC, INTENT_SATURATION, INTENT_ABSOLUTE_COLORIMETRIC};
    cmsFloat64Number adaptation_states[] = {0.0, 1.0};
    cmsBool bpc[] = {0, 1, 0};
    cmsUInt32Number flags = data[0];

    cmsHPROFILE gamut_profile = cmsCreateGrayProfileTHR(ctx, NULL, NULL);
    if (gamut_profile) {
      cmsHTRANSFORM transform = cmsCreateExtendedTransform(ctx, 3, profiles, bpc, intents, adaptation_states, gamut_profile, 0, 0, 0, flags);
      if (transform) {
        cmsDeleteTransform(transform);
      }
      cmsCloseProfile(gamut_profile);
    }
  }

  if (profiles[2]) {
    cmsCIEXYZ black_point;
    cmsDetectDestinationBlackPoint(&black_point, profiles[2], INTENT_PERCEPTUAL, 0);
  }

  if (profiles[0])
    cmsCloseProfile(profiles[0]);
  if (profiles[1])
    cmsCloseProfile(profiles[1]);
  if (profiles[2])
    cmsCloseProfile(profiles[2]);

  cmsPipeline *pipeline = cmsPipelineAlloc(ctx, 3, 3);
  if (pipeline) {
    cmsStage *clut_stage = cmsStageAllocCLut16bit(ctx, 2, 3, 3, NULL);
    if (clut_stage) {
      cmsPipelineInsertStage(pipeline, cmsAT_END, clut_stage);
      if (size > 16) {
        cmsUInt16Number at[4];
        cmsUInt16Number value[4];
        memcpy(at, data, sizeof(at));
        memcpy(value, data + sizeof(at), sizeof(value));
        PatchLUT(clut_stage, at, value, 3, 3);
      }
    }
    cmsPipelineFree(pipeline);
  }

  cmsDeleteContext(ctx);
  return 0;
}