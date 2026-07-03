/* BLOCKER_STRATEGY_CONTRACT
required_state: The hProfile object passed to the blocker function WriteInputMatrixShaper must have its color space set to cmsSigGrayData. Additionally, to ensure the call chain leading to the blocker is followed, the profile's Profile Connection Space (PCS) must be set to a valid value (e.g., cmsSigXYZData), and it must contain a BToA0 tag so that _cmsReadInputLUT can successfully construct a pipeline.
state_constructor: A new null profile is created using cmsCreateNULLProfileTHR. Its color space is explicitly set to cmsSigGrayData using cmsSetColorSpace, and its PCS is set using cmsSetPCS. A gamma curve is created with cmsBuildGamma and written to the profile's cmsSigBToA0Tag using cmsWriteTag.
trigger_api: cmsGetPostScriptCSA is called with the specially crafted gray profile, which internally triggers the call to WriteInputMatrixShaper with the required state.
preserved_invariants: The original fuzz target's logic, including all API calls and the consumption of the fuzzer input buffer, is kept intact. The new logic is added towards the end of the function to avoid interfering with existing operations and to maintain seed compatibility. END_BLOCKER_STRATEGIES_CONTRACT
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
   * ANALYSIS: The functions in cmsalpha.c, which handle extra channels (like alpha),
   *           had very low or 0% coverage. This was because the existing transforms
   *           only used opaque formats like TYPE_RGB_8.
   * IMPLEMENTATION: The following code creates a transform between RGBA formats
   *                 (TYPE_RGBA_8), which contain an alpha channel. This specifically
   *                 targets the uncovered code paths in _cmsHandleExtraChannels and
   *                 related formatter functions.
   */
  cmsHTRANSFORM hAlphaTransform = cmsCreateTransformTHR(context, hInProfile, TYPE_RGBA_8,
                                                        hOutProfile, TYPE_RGBA_8,
                                                        INTENT_PERCEPTUAL, 0);
  if (hAlphaTransform != NULL) {
    cmsDeleteTransform(hAlphaTransform);
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
   * ANALYSIS: Many tag handler functions in cmstypes.c, such as those for UcrBg
   *           (Type_UcrBg_Read/Write) and NamedColor (Type_NamedColor_Read/Write),
   *           had 0% coverage. These are triggered when reading/writing profiles
   *           containing these specific tag types.
   * IMPLEMENTATION: The following code creates a new profile, writes a UcrBg tag
   *                 and a NamedColor tag to it, saves the profile to a memory
   *                 buffer, and then re-opens it. This round-trip forces the
   *                 execution of both the tag writing and tag reading handlers,
   *                 significantly improving their coverage.
   */
  cmsHPROFILE hTagProfile = cmsCreateNULLProfileTHR(context);
  if (hTagProfile != NULL) {
    // Write UcrBg Tag
    cmsUcrBg ucrbg;
    ucrbg.Ucr = cmsBuildTabulatedToneCurve16(context, 1, NULL);
    ucrbg.Bg = cmsBuildTabulatedToneCurve16(context, 1, NULL);
    ucrbg.Desc = NULL; 
    if (ucrbg.Ucr != NULL && ucrbg.Bg != NULL) {
        cmsWriteTag(hTagProfile, cmsSigUcrBgTag, &ucrbg);
    }
    if (ucrbg.Ucr) cmsFreeToneCurve(ucrbg.Ucr);
    if (ucrbg.Bg) cmsFreeToneCurve(ucrbg.Bg);

    // Write Named Color Tag
    cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(context, 1, 3, "prefix", "suffix");
    if (nc != NULL) {
        uint16_t PCS[3] = {1,2,3};
        uint16_t Device[3] = {4,5,6};
        cmsAppendNamedColor(nc, "name", PCS, Device);
        cmsWriteTag(hTagProfile, cmsSigNamedColor2Tag, nc);
        cmsFreeNamedColorList(nc);
    }

    // Save and load to trigger read handlers
    unsigned char* buffer = NULL;
    cmsUInt32Number bytes_needed = 0;
    if (cmsSaveProfileToMem(hTagProfile, NULL, &bytes_needed)) {
        buffer = (unsigned char*)malloc(bytes_needed);
        if (buffer != NULL) {
            if (cmsSaveProfileToMem(hTagProfile, buffer, &bytes_needed)) {
                cmsHPROFILE hReadProfile = cmsOpenProfileFromMem(buffer, bytes_needed);
                if (hReadProfile != NULL) {
                    cmsCloseProfile(hReadProfile);
                }
            }
            free(buffer);
        }
    }
    cmsCloseProfile(hTagProfile);
  }

  /*
   * ANALYSIS: The function cmsCreateDeviceLinkFromCubeFileTHR was covered, but its
   *           underlying file parsing logic in cmscgats.c:ParseCube had low coverage.
   * IMPLEMENTATION: The following code writes the fuzzer input to a temporary .cube file
   *                 and passes it to cmsCreateDeviceLinkFromCubeFileTHR. This will
   *                 exercise the file parsing and error handling paths of the function.
   */
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/%s.cube", "llm_fuzzgen0625034646");
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
   * ANALYSIS: The function WriteInputMatrixShaper has a branch on line 947
   *           that is not taken because the color space of the profile is
   *           always RGB. To reach the branch, we need a profile with a
   *           Gray color space.
   * IMPLEMENTATION: The following code creates a new NULL profile, sets its
   *                 color space to cmsSigGrayData and its PCS to cmsSigXYZData,
   *                 and then calls cmsGetPostScriptCSA with it. This will
   *                 trigger the desired code path in WriteInputMatrixShaper.
   */
  cmsHPROFILE hGrayProfile = cmsCreateNULLProfileTHR(context);
  if (hGrayProfile != NULL) {
    cmsSetColorSpace(hGrayProfile, cmsSigGrayData);
    cmsSetPCS(hGrayProfile, cmsSigXYZData); // Required by GenerateCSA

    // A BToA0 tag is needed for _cmsReadInputLUT to succeed.
    // The tag expects a pipeline, not just a tone curve.
    cmsToneCurve* gamma = cmsBuildGamma(context, 2.2);
    if (gamma != NULL) {
        cmsPipeline* lut = cmsPipelineAlloc(context, 1, 1);
        if (lut != NULL) {
            cmsStage* stage = cmsStageAllocToneCurves(context, 1, (cmsToneCurve* const*)&gamma);
            if (stage != NULL) {
                cmsPipelineInsertStage(lut, cmsAT_BEGIN, stage);
                cmsWriteTag(hGrayProfile, cmsSigBToA0Tag, lut);
            }
            cmsPipelineFree(lut);
        }
        cmsFreeToneCurve(gamma);
    }

    cmsGetPostScriptCSA(context, hGrayProfile, INTENT_PERCEPTUAL, 0, NULL, 0);
    cmsCloseProfile(hGrayProfile);
  }

  cmsCloseProfile(hInProfile);
  cmsCloseProfile(hOutProfile);
  cmsDeleteContext(context);

  return 0;
}