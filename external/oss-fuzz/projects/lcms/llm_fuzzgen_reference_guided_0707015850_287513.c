/* BLOCKER_STRATEGY_CONTRACT
required_state: `cmsIsTag(hProfile, tagFloat)` must evaluate to true in `_cmsReadDevicelinkLUT`. For `INTENT_PERCEPTUAL`, `tagFloat` is `cmsSigDToB0Tag`.
state_constructor: A new profile `hDevicelink` is created with `cmsCreateProfilePlaceholder`. Its class is set to `cmsSigLinkClass` and colorspace to `cmsSigRgbData`. A floating-point `cmsPipeline` is created and written to the profile with the tag `cmsSigDToB0Tag` using `cmsWriteTag`. This ensures the profile is a devicelink with the required floating-point tag.
trigger_api: `cmsCreateTransformTHR` is called with `hDevicelink` as the input profile and `INTENT_PERCEPTUAL`. This triggers `_cmsReadDevicelinkLUT` on `hDevicelink` through the internal transform creation logic.
preserved_invariants: The original fuzzer's input consumption via `data` and `size` is untouched. The new logic is additive and does not modify the existing API call sequence or semantics.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

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
   * BLOCKER: The function _cmsReadDevicelinkLUT has a predicate at line 745
   *          (cmsIsTag(hProfile, tagFloat)) that is never true. The tag being
   *          checked for is a floating-point devicelink tag (e.g., cmsSigDToB0Tag).
   * STRATEGY: Create a placeholder devicelink profile. Set its class to
   *           cmsSigLinkClass. Create a floating-point pipeline and write it to
   *           the profile using the cmsSigDToB0Tag. Then, create a transform
   *           with this profile to trigger the call to _cmsReadDevicelinkLUT
   *           and satisfy the predicate.
   */
  cmsHPROFILE hDevicelink = cmsCreateProfilePlaceholder(context);
  if (hDevicelink != NULL) {
    cmsSetDeviceClass(hDevicelink, cmsSigLinkClass);
    cmsSetColorSpace(hDevicelink, cmsSigRgbData);
    cmsSetPCS(hDevicelink, cmsSigLabData);

    cmsPipeline* p = cmsPipelineAlloc(context, 3, 3);
    if (p != NULL) {
      cmsStage* clut = cmsStageAllocCLutFloat(context, 2, 3, 3, NULL);
      if (clut != NULL) {
        cmsPipelineInsertStage(p, cmsAT_BEGIN, clut);
        
        // Write the float pipeline to the DToB0 tag to satisfy cmsIsTag(..., cmsSigDToB0Tag)
        if (cmsWriteTag(hDevicelink, cmsSigDToB0Tag, p)) {
          // Create a transform with our custom devicelink profile to hit the blocker
          cmsHTRANSFORM hTransformFuzz = cmsCreateTransformTHR(context, hDevicelink, TYPE_RGB_8,
                                                               hOutProfile, TYPE_RGB_8,
                                                               INTENT_PERCEPTUAL, 0);
          if (hTransformFuzz != NULL) {
            cmsDeleteTransform(hTransformFuzz);
          }
        }
      }
      cmsPipelineFree(p);
    }
    cmsCloseProfile(hDevicelink);
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
  cmsPipeline *p_opt = cmsPipelineAlloc(context, 3, 3);
  if (p_opt != NULL) {
    double matrix[9] = {1, 0, 0, 0, 1, 0, 0, 0, 1};
    cmsStage *m = cmsStageAllocMatrix(context, 3, 3, matrix, NULL);
    cmsStage *c = cmsStageAllocCLut16bit(context, 2, 3, 3, NULL);

    if (m != NULL && c != NULL) {
      cmsPipelineInsertStage(p_opt, cmsAT_BEGIN, m);
      cmsPipelineInsertStage(p_opt, cmsAT_END, c);

      uint32_t In = TYPE_RGB_8;
      uint32_t Out = TYPE_RGB_8;
      uint32_t dwFlags = cmsFLAGS_CLUT_PRE_LINEARIZATION;
      _cmsOptimizePipeline(context, &p_opt, INTENT_PERCEPTUAL, &In, &Out, &dwFlags);
    } else {
      if (m) cmsStageFree(m);
      if (c) cmsStageFree(c);
    }
    cmsPipelineFree(p_opt);
  }

  /*
   * ANALYSIS: The function cmsCreateDeviceLinkFromCubeFileTHR was covered, but its
   *           underlying file parsing logic in cmscgats.c:ParseCube had low coverage.
   * IMPLEMENTATION: The following code writes the fuzzer input to a temporary .cube file
   *                 and passes it to cmsCreateDeviceLinkFromCubeFileTHR. This will
   *                 exercise the file parsing and error handling paths of the function.
   */
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/%s.cube", "llm_fuzzgen0625033853");
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

  cmsCloseProfile(hInProfile);
  cmsCloseProfile(hOutProfile);
  cmsDeleteContext(context);

  return 0;
}
