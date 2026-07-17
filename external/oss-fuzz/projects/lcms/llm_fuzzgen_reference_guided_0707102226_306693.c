/* BLOCKER_STRATEGY_CONTRACT
required_state: The `inputChan` parameter for `cmsStageAllocCLut16bitGranular` must be greater than `MAX_INPUT_DIMENSIONS` (15).
state_constructor: The public API `cmsStageAllocCLut16bit` is called with `inputChan` set to 16. This function serves as a wrapper and passes the value down to `cmsStageAllocCLut16bitGranular`.
trigger_api: `cmsStageAllocCLut16bit` is called, which internally calls the blocker function `cmsStageAllocCLut16bitGranular` with the oversized `inputChan`.
preserved_invariants: The original fuzz target's logic is maintained. The new logic is purely additive, ensuring that the existing input contract and seed compatibility are not disturbed.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

// Define the missing macro used in the original fuzzer
#define _FUZZ_TARGET_NAME "llm_fuzzgen0625033853"

// Dummy transform plugin
static cmsBool MyTransformFactory(
    cmsContext ContextID,
    cmsUInt32Number InputFormat,
    cmsUInt32Number OutputFormat,
    cmsUInt32Number dwFlags) {
  return TRUE;
}

static cmsPluginTransform MyTransformPlugin = {
    .base = {
        .Magic = cmsPluginMagicNumber,
        .ExpectedVersion = 2080,
        .Type = cmsPluginTransformSig,
        .Next = NULL,
    },
    .factories = {
        .xform = MyTransformFactory,
    },
};

static void MyFree(cmsContext ContextID, void* Ptr)
{
    free(Ptr);
}

// Main fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (context == NULL) {
    return 0;
  }

  /*
   * ANALYSIS: The function _cmsRegisterTransformPlugin had a branch that was
   *           never hit because the 'Data' argument was always NULL.
   * IMPLEMENTATION: The following code registers a dummy transform plugin
   *                 to exercise the code path where 'Data' is not NULL.
   */
  cmsPluginTHR(context, &MyTransformPlugin);

  cmsHPROFILE hInProfile = cmsCreate_sRGBProfileTHR(context);
  cmsHPROFILE hOutProfile = cmsCreate_sRGBProfileTHR(context);
  if (hInProfile == NULL || hOutProfile == NULL) {
    if (hInProfile) cmsCloseProfile(hInProfile);
    if (hOutProfile) cmsCloseProfile(hOutProfile);
    cmsDeleteContext(context);
    return 0;
  }

  /*
   * ANALYSIS: The function cmsDetectDestinationBlackPoint has very low
   *           coverage, with many untested branches.
   * IMPLEMENTATION: The following code calls cmsDetectDestinationBlackPoint
   *                 with different intents to cover more branches.
   */
  cmsCIEXYZ BlackPoint;
  cmsDetectDestinationBlackPoint(&BlackPoint, hInProfile, INTENT_PERCEPTUAL, 0);
  cmsDetectDestinationBlackPoint(&BlackPoint, hInProfile, INTENT_RELATIVE_COLORIMETRIC, 0);
  cmsDetectDestinationBlackPoint(&BlackPoint, hInProfile, INTENT_SATURATION, 0);

  cmsHTRANSFORM hTransform = cmsCreateTransformTHR(context, hInProfile, TYPE_RGB_8,
                                                   hOutProfile, TYPE_RGB_8,
                                                   INTENT_PERCEPTUAL, 0);
  if (hTransform != NULL) {
    /*
     * ANALYSIS: The functions _cmsSetTransformUserData and
     *           _cmsGetTransformUserData had 0% coverage.
     * IMPLEMENTATION: The following code creates a transform, sets user data
     *                 on it, and then retrieves it to cover these functions.
     *                 A custom free function is provided to ensure no memory leaks.
     */
    void *userData = malloc(1);
    if (userData != NULL) {
      _cmsSetTransformUserData(hTransform, userData, MyFree);
      void *retrievedUserData = _cmsGetTransformUserData(hTransform);
      if (retrievedUserData != userData) {
        // This should not happen
        free(userData);
      }
    }
    /*
     * ANALYSIS: The functions cmsGetTransformInputFormat and cmsGetTransformOutputFormat
     *           had 0% coverage.
     * IMPLEMENTATION: The following code calls these getter functions on the created
     *                 transform to ensure they are covered.
     */
    cmsGetTransformInputFormat(hTransform);
    cmsGetTransformOutputFormat(hTransform);

    cmsDeleteTransform(hTransform);
  }

  /*
   * ANALYSIS: The function OptimizeByComputingLinearization has extremely low
   *           coverage. The initial checks for non-float RGB to RGB formats
   *           were preventing the main logic from being executed.
   * IMPLEMENTATION: The following code creates a pipeline with a matrix and a
   *                 CLUT stage, which is a suitable candidate for this
   *                 optimization. It then calls _cmsOptimizePipeline with the
   *                 cmsFLAGS_CLUT_PRE_LINEARIZATION flag to trigger the
   *                 optimization.
   */
  cmsPipeline *p = cmsPipelineAlloc(context, 3, 3);
  if (p != NULL) {
    double matrix[9] = {1, 0, 0, 0, 1, 0, 0, 0, 1};
    cmsStage *m = cmsStageAllocMatrix(context, 3, 3, matrix, NULL);
    cmsStage *c = cmsStageAllocCLut16bit(context, 2, 3, 3, NULL);

    if (m != NULL && c != NULL) {
      cmsPipelineInsertStage(p, cmsAT_BEGIN, m);
      cmsPipelineInsertStage(p, cmsAT_END, c);

      uint32_t In = TYPE_RGB_8;
      uint32_t Out = TYPE_RGB_8;
      uint32_t dwFlags = cmsFLAGS_CLUT_PRE_LINEARIZATION;
      _cmsOptimizePipeline(context, &p, INTENT_PERCEPTUAL, &In, &Out, &dwFlags);
    } else {
      if (m) cmsStageFree(m);
      if (c) cmsStageFree(c);
    }
    cmsPipelineFree(p);
  }

  /*
   * ANALYSIS: The function cmsCreateDeviceLinkFromCubeFileTHR was covered, but its
   *           underlying file parsing logic in cmscgats.c:ParseCube had low coverage.
   * IMPLEMENTATION: The following code writes the fuzzer input to a temporary .cube file
   *                 and passes it to cmsCreateDeviceLinkFromCubeFileTHR. This will
   *                 exercise the file parsing and error handling paths of the function.
   */
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/%s.cube", _FUZZ_TARGET_NAME);
  FILE* f = fopen(filename, "wb");
  if (f) {
      fwrite(data, 1, size, f);
      fclose(f);
      cmsHPROFILE cube_profile = cmsCreateDeviceLinkFromCubeFileTHR(context, filename);
      if (cube_profile) {
          cmsCloseProfile(cube_profile);
      }
      unlink(filename);
  }

  /*
   * ANALYSIS: Functions in cmscgats.c related to the IT8 API, such as
   *           cmsIT8GetSheetType and cmsIT8SetComment, had 0% coverage.
   * IMPLEMENTATION: The following code loads the fuzzer data into an IT8 handle
   *                 and calls several uncovered API functions to improve coverage.
   *                 The handle is freed to prevent memory leaks.
   */
  cmsHANDLE it8 = cmsIT8LoadFromMem(context, data, size);
  if (it8 != NULL) {
      cmsIT8GetSheetType(it8);
      cmsIT8SetComment(it8, "fuzz comment");
      cmsIT8SetPropertyDbl(it8, "fuzz_prop", 1.23);
      cmsIT8Free(it8);
  }

  /*
   * ANALYSIS: Functions related to profile sequence descriptions in cmsnamed.c,
   *           like cmsAllocProfileSequenceDescription, had 0% coverage.
   * IMPLEMENTATION: The following code calls the allocation, duplication, and
   *                 freeing functions for profile sequence descriptions to cover
   *                 these APIs. All allocated resources are freed.
   */
  cmsSEQ* seq = cmsAllocProfileSequenceDescription(context, 1);
  if (seq != NULL) {
      cmsSEQ* seq_dup = cmsDupProfileSequenceDescription(seq);
      if (seq_dup != NULL) {
          cmsFreeProfileSequenceDescription(seq_dup);
      }
      cmsFreeProfileSequenceDescription(seq);
  }

  /*
   * ANALYSIS: The functions cmsGetPostScriptCSA and cmsGetPostScriptCRD had
   *           uncovered branches where the Buffer argument was NULL.
   * IMPLEMENTATION: The following code calls these functions with both NULL and
   *                 non-NULL buffers to exercise these paths.
   */
  char ps_buffer[1024];
  cmsGetPostScriptCSA(context, hInProfile, INTENT_PERCEPTUAL, 0, ps_buffer, sizeof(ps_buffer));
  cmsGetPostScriptCRD(context, hInProfile, INTENT_PERCEPTUAL, 0, ps_buffer, sizeof(ps_buffer));
  cmsGetPostScriptCSA(context, hInProfile, INTENT_PERCEPTUAL, 0, NULL, 0);
  cmsGetPostScriptCRD(context, hInProfile, INTENT_PERCEPTUAL, 0, NULL, 0);

  /*
   * ANALYSIS: The functions GenerateCSA and GenerateCRD in cmsps2.c had low
   *           coverage because they were not tested with named color profiles.
   * IMPLEMENTATION: The following code creates a named color profile and calls
   *                 cmsGetPostScriptCSA and cmsGetPostScriptCRD with it to
   *                 exercise the named color code paths.
   */
  cmsHPROFILE hNamedColor = cmsCreateNULLProfileTHR(context);
  if (hNamedColor != NULL) {
      cmsSetDeviceClass(hNamedColor, cmsSigNamedColorClass);
      cmsGetPostScriptCSA(context, hNamedColor, INTENT_PERCEPTUAL, 0, NULL, 0);
      cmsGetPostScriptCRD(context, hNamedColor, INTENT_PERCEPTUAL, 0, NULL, 0);
      cmsCloseProfile(hNamedColor);
  }

  /*
   * BLOCKER-SPECIFIC ADDITION: The following code is designed to cross the
   * blocker in `WriteInputMatrixShaper` by creating a valid gray profile.
   * The predicate `ColorSpace == cmsSigGrayData` fails with the default sRGB
   * profile. The previous attempt used `cmsCreateNULLProfileTHR` and manually
   * added a tag, which was insufficient for the internal pipeline construction.
   * This version uses `cmsCreateGrayProfileTHR` to create a complete profile
   * that lcms can properly process.
   */
  cmsToneCurve* curve = cmsBuildGamma(context, 2.2);
  if (curve) {
    // Use a standard D50 white point.
    cmsCIExyY D50_WhitePoint = { 0.34567, 0.35850, 1.0 };
    cmsHPROFILE hGrayProfile = cmsCreateGrayProfileTHR(context, &D50_WhitePoint, curve);
    if (hGrayProfile) {
      // This call will trigger the execution path leading to the blocker with a
      // profile that has the cmsSigGrayData color space.
      cmsGetPostScriptCSA(context, hGrayProfile, INTENT_RELATIVE_COLORIMETRIC, 0, NULL, 0);
      cmsCloseProfile(hGrayProfile);
    }
    cmsFreeToneCurve(curve);
  }

  /*
   * BLOCKER-SPECIFIC ADDITION: The following code is designed to cross the
   * blocker in `cmsStageAllocCLut16bitGranular` by calling its wrapper
   * `cmsStageAllocCLut16bit` with an `inputChan` value greater than
   * MAX_INPUT_DIMENSIONS (15).
   */
  cmsStage* stage_to_trigger_blocker = cmsStageAllocCLut16bit(context, 2, 16, 3, NULL);
  if (stage_to_trigger_blocker != NULL) {
      cmsStageFree(stage_to_trigger_blocker);
  }

  cmsCloseProfile(hInProfile);
  cmsCloseProfile(hOutProfile);
  cmsDeleteContext(context);

  return 0;
}
