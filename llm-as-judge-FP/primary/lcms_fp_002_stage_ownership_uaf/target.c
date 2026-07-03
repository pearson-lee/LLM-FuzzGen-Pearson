/* BLOCKER_STRATEGY_CONTRACT
required_state: The `CLUT` variable in `Type_LUTB2A_Write` must not be `NULL`. This is achieved when the `cmsPipeline` object being written contains a stage of type `cmsSigCLutElemType` in a supported sequence.
state_constructor: A `cmsPipeline` is explicitly constructed with a sequence of stages: `cmsSigCurveSetElemType` -> `cmsSigCLutElemType` -> `cmsSigCurveSetElemType`. This is done by allocating a pipeline with `cmsPipelineAlloc`, creating curve and CLUT stages with `cmsStageAllocToneCurves` and `cmsStageAllocCLut16bit` respectively, and inserting them in the correct order using `cmsPipelineInsertStage`.
trigger_api: The crafted pipeline is written as a `cmsSigBToA0Tag` to a new profile using `cmsWriteTag`. The subsequent call to `cmsSaveProfileToMem` triggers the internal `Type_LUTB2A_Write` function to process this tag, which then finds the non-NULL `CLUT` stage.
preserved_invariants: The pipeline must contain a CLUT stage, and it must be written to a tag that uses the `lutBToAType` handler (e.g., `cmsSigBToA0Tag`). The sequence of stages in the pipeline must match one of the configurations checked by `cmsPipelineCheckAndRetreiveStages` in the blocker function.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // We need at least 48 bytes for a 2-grid-point, 3-channel CLUT
  if (size < 48) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (context == NULL) {
    return 0;
  }

  // Allocate a pipeline that will hold the B->CLUT->A structure
  cmsPipeline *lut = cmsPipelineAlloc(context, 3, 3);
  if (lut == NULL) {
    cmsDeleteContext(context);
    return 0;
  }

  // Create and insert the 'B' curve set stage
  cmsToneCurve *curve_b[3];
  curve_b[0] = cmsBuildGamma(context, 1.0);
  curve_b[1] = cmsBuildGamma(context, 1.0);
  curve_b[2] = cmsBuildGamma(context, 1.0);

  if (curve_b[0] == NULL || curve_b[1] == NULL || curve_b[2] == NULL) {
    if (curve_b[0]) cmsFreeToneCurve(curve_b[0]);
    if (curve_b[1]) cmsFreeToneCurve(curve_b[1]);
    if (curve_b[2]) cmsFreeToneCurve(curve_b[2]);
    cmsPipelineFree(lut);
    cmsDeleteContext(context);
    return 0;
  }
  
  cmsStage *stage_b = cmsStageAllocToneCurves(context, 3, (cmsToneCurve* const*) curve_b);
  cmsFreeToneCurve(curve_b[0]);
  cmsFreeToneCurve(curve_b[1]);
  cmsFreeToneCurve(curve_b[2]);

  if (stage_b == NULL) {
    cmsPipelineFree(lut);
    cmsDeleteContext(context);
    return 0;
  }
  cmsPipelineInsertStage(lut, cmsAT_BEGIN, stage_b);
  cmsStageFree(stage_b);

  // Create and insert the CLUT stage using fuzzer data
  const cmsUInt16Number *clut_table = (const cmsUInt16Number *)data;
  cmsStage *stage_clut = cmsStageAllocCLut16bit(context, 2, 3, 3, clut_table);
  if (stage_clut == NULL) {
    cmsPipelineFree(lut);
    cmsDeleteContext(context);
    return 0;
  }
  cmsPipelineInsertStage(lut, cmsAT_END, stage_clut);
  cmsStageFree(stage_clut);

  // Create and insert the 'A' curve set stage
  cmsToneCurve *curve_a[3];
  curve_a[0] = cmsBuildGamma(context, 1.0);
  curve_a[1] = cmsBuildGamma(context, 1.0);
  curve_a[2] = cmsBuildGamma(context, 1.0);

  if (curve_a[0] == NULL || curve_a[1] == NULL || curve_a[2] == NULL) {
    if (curve_a[0]) cmsFreeToneCurve(curve_a[0]);
    if (curve_a[1]) cmsFreeToneCurve(curve_a[1]);
    if (curve_a[2]) cmsFreeToneCurve(curve_a[2]);
    cmsPipelineFree(lut);
    cmsDeleteContext(context);
    return 0;
  }

  cmsStage *stage_a = cmsStageAllocToneCurves(context, 3, (cmsToneCurve* const*) curve_a);
  cmsFreeToneCurve(curve_a[0]);
  cmsFreeToneCurve(curve_a[1]);
  cmsFreeToneCurve(curve_a[2]);

  if (stage_a == NULL) {
    cmsPipelineFree(lut);
    cmsDeleteContext(context);
    return 0;
  }
  cmsPipelineInsertStage(lut, cmsAT_END, stage_a);
  cmsStageFree(stage_a);

  // Create a profile to hold the tag
  cmsHPROFILE profile = cmsCreateRGBProfile(NULL, NULL, NULL);
  if (profile == NULL) {
    cmsPipelineFree(lut);
    cmsDeleteContext(context);
    return 0;
  }

  // Write the pipeline to the BToA0 tag. This tag type is handled by
  // Type_LUTB2A_Write.
  cmsWriteTag(profile, cmsSigBToA0Tag, lut);

  // Trigger the write operation by saving the profile.
  // Saving to a NULL buffer just calculates the size, but it is enough to
  // trigger the tag writing logic and hit our blocker.
  cmsUInt32Number profile_size = 0;
  cmsSaveProfileToMem(profile, NULL, &profile_size);

  // Clean up all allocated resources
  cmsCloseProfile(profile);
  cmsPipelineFree(lut);
  cmsDeleteContext(context);

  return 0;
}