#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/lcms/include/lcms2.h"

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need enough data for some values and a profile
    if (size < 32) {
        return 0;
    }

    // Create a context. All lcms operations are done on a context.
    // We will delete it at the end to exercise cmsDeleteContext.
    cmsContext ctx = cmsCreateContext(NULL, NULL);
    if (ctx == NULL) {
        return 0;
    }

    // Use the fuzzer data to create a profile in memory.
    // This profile will be used by several target functions.
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        cmsDeleteContext(ctx);
        return 0;
    }

    // Target 1: cmsDetectTAC
    // This function has low coverage (10.71%). Calling it on a fuzzer-generated
    // profile might exercise new paths. It returns the Total Area Coverage.
    cmsDetectTAC(hProfile);

    // Added calls to simple uncovered functions to improve coverage.
    cmsGetHeaderRenderingIntent(hProfile);
    cmsGetHeaderFlags(hProfile);
    // Added call to cmsGetContextUserData which was previously uncovered (0% coverage).
    cmsGetContextUserData(ctx);

    // Added calls to PostScript generation functions to improve coverage in cmsps2.c
    cmsGetPostScriptCSA(ctx, hProfile, 0, 0, NULL, 0);
    cmsGetPostScriptCRD(ctx, hProfile, 0, 0, NULL, 0);

    // Added call to cmsDetectDestinationBlackPoint to improve coverage in cmssamp.c.
    // This requires a second profile, so we create a standard sRGB profile.
    cmsHPROFILE sRGB = cmsCreate_sRGBProfileTHR(ctx);
    if (sRGB != NULL) {
        cmsDetectDestinationBlackPoint(hProfile, sRGB, INTENT_PERCEPTUAL, 0);
        // The created sRGB profile must be closed to avoid memory leaks.
        cmsCloseProfile(sRGB);
    }


    // Create some tone curves from the data to use later
    // We consume some data for gamma values and other parameters.
    const uint8_t* current_data = data;
    size_t remaining_size = size;

    double gamma1 = 2.2;
    if (remaining_size >= sizeof(double)) {
        gamma1 = *(const double*)current_data;
        current_data += sizeof(double);
        remaining_size -= sizeof(double);
    }
    // Clamp gamma to a reasonable range to avoid long computations or errors.
    if (gamma1 < 0.1 || gamma1 > 10.0) gamma1 = 2.2;
    cmsToneCurve *curve1 = cmsBuildGamma(ctx, gamma1);

    double gamma2 = 1.8;
    if (remaining_size >= sizeof(double)) {
        gamma2 = *(const double*)current_data;
        current_data += sizeof(double);
        remaining_size -= sizeof(double);
    }
    if (gamma2 < 0.1 || gamma2 > 10.0) gamma2 = 1.8;
    cmsToneCurve *curve2 = cmsBuildGamma(ctx, gamma2);

    unsigned int join_points = 256;
    if (remaining_size >= sizeof(unsigned int)) {
        join_points = *(const unsigned int*)current_data;
        current_data += sizeof(unsigned int);
        remaining_size -= sizeof(unsigned int);
        // Limit points to avoid excessive memory allocation
        join_points = (join_points % 4096) + 1;
    }

    if (curve1 != NULL && curve2 != NULL) {
        // Target 2: cmsJoinToneCurve
        // This function has some uncovered branches. We use a fuzzer-
        // controlled number of points.
        cmsToneCurve *joinedCurve = cmsJoinToneCurve(ctx, curve1, curve2, join_points);

        if (joinedCurve != NULL) {
            // Target 3: cmsPipelineEvalReverseFloat
            // This function has 0% coverage. We need to build a pipeline first.
            cmsPipeline *pipeline = cmsPipelineAlloc(ctx, 1, 1);
            if (pipeline != NULL) {
                cmsStage *stage = cmsStageAllocToneCurves(ctx, 1, &joinedCurve);
                if (stage != NULL) {
                    if(cmsPipelineInsertStage(pipeline, cmsAT_END, stage)) {
                        // Insertion succeeded, pipeline owns the stage.
                        
                        // Added matrix stage to exercise new branches in cmsPipelineEvalReverseFloat.
                        // The existing fuzzer only exercises the curve set stage.
                        if (remaining_size >= sizeof(double) * 2) {
                            double matrix_data[1];
                            double offset_data[1];
                            matrix_data[0] = ((const double*)current_data)[0];
                            offset_data[0] = ((const double*)current_data)[1];
                            current_data += sizeof(double) * 2;
                            remaining_size -= sizeof(double) * 2;

                            cmsStage* matrix_stage = cmsStageAllocMatrix(ctx, 1, 1, matrix_data, offset_data);
                            if (matrix_stage) {
                                if (!cmsPipelineInsertStage(pipeline, cmsAT_END, matrix_stage)) {
                                    cmsStageFree(matrix_stage);
                                }
                            }
                        }

                        float in = 0.5f, out;
                        if (remaining_size >= sizeof(float)) {
                            in = *(const float*)current_data;
                        }
                        // The hint parameter can be NULL. This function does not take a context.
                        cmsPipelineEvalReverseFloat(&in, &out, NULL, pipeline);
                    } else {
                        // Insertion failed, we need to free the stage ourselves.
                        cmsStageFree(stage);
                    }
                }
                cmsPipelineFree(pipeline);
            }
            cmsFreeToneCurve(joinedCurve);
        }
    }

    // Write a tag to the profile so that the cmsReadTag call below succeeds.
    // This covers the previously-unreached cmsMLUfree call in the fuzz target.
    cmsMLU* mlu = cmsMLUalloc(ctx, 1);
    if (mlu != NULL) {
        cmsMLUsetASCII(mlu, "en", "US", "Fuzzer-generated profile");
        cmsWriteTag(hProfile, cmsSigProfileDescriptionTag, mlu);
        // The MLU object must be freed after being written to the profile.
        cmsMLUfree(mlu);
    }

    // Target 4: Read a common tag to exercise tag reading logic.
    // The original target cmsSigCurveType was never found. Reading cmsSigProfileDescriptionTag
    // is more likely to succeed and exercises the Type_Text_Description_Read handler.
    void* tagData = cmsReadTag(hProfile, cmsSigProfileDescriptionTag);
    if (tagData != NULL) {
        // The returned object is owned by the profile and should not be freed here.
        // It will be freed when cmsCloseProfile is called.
    }

    // Cleanup all allocated resources.
    if (curve1 != NULL) {
        cmsFreeToneCurve(curve1);
    }
    if (curve2 != NULL) {
        cmsFreeToneCurve(curve2);
    }

    cmsCloseProfile(hProfile);

    // Target 5: cmsDeleteContext
    // This function has low coverage (43.75%). Calling it at the end ensures we test
    // the cleanup of all resources associated with the context created at the beginning.
    cmsDeleteContext(ctx);

    return 0;
}