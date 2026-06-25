#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

  cmsCloseProfile(hInProfile);
  cmsCloseProfile(hOutProfile);
  cmsDeleteContext(context);

  return 0;
}