#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

// A simple sampler callback for cmsStageSampleCLutFloat.
// It copies the input to the output. The number of channels is passed via the cargo pointer.
static int sampler_float(const cmsFloat32Number in[], cmsFloat32Number out[], void *cargo) {
    int n_channels = *(int*)cargo;
    memcpy(out, in, sizeof(cmsFloat32Number) * n_channels);
    return 1;
}

// The main fuzzing entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require a minimum amount of data to be useful.
    if (size < 100) {
        return 0;
    }

    // All lcms operations are done on a context.
    cmsContext context = cmsCreateContext(NULL, NULL);

    // --- Create and Fuzz Tone Curves ---

    // Consume data to determine the number of entries for the tone curve.
    uint16_t num_entries = *(uint16_t*)data;
    data += 2;
    size -= 2;
    num_entries = (num_entries % 4096) + 2; // Keep it within a reasonable size.

    // Ensure there is enough data to build the tone curve table.
    if (size < num_entries * sizeof(cmsFloat32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a tone curve from a table of floats.
    cmsToneCurve *curve = cmsBuildTabulatedToneCurveFloat(context, num_entries, (const cmsFloat32Number*)data);
    data += num_entries * sizeof(cmsFloat32Number);
    size -= num_entries * sizeof(cmsFloat32Number);

    if (!curve) {
        cmsDeleteContext(context);
        return 0;
    }

    // Fuzz several functions that operate on tone curves.
    cmsIsToneCurveLinear(curve);
    cmsGetToneCurveParams(curve);
    cmsGetToneCurveEstimatedTableEntries(curve);
    cmsGetToneCurveEstimatedTable(curve);
    if (size >= sizeof(double)) {
        cmsSmoothToneCurve(curve, *(double*)data);
        data += sizeof(double);
        size -= sizeof(double);
    }

    // --- Fuzz Profile Creation and Inspection ---

    // Duplicate the curve for use in an RGB profile.
    cmsToneCurve *gamma_curves[3] = { cmsDupToneCurve(curve), cmsDupToneCurve(curve), cmsDupToneCurve(curve) };
    if (gamma_curves[0] && gamma_curves[1] && gamma_curves[2]) {
        cmsCIExyY white_point;
        if (size >= sizeof(white_point)) {
            memcpy(&white_point, data, sizeof(white_point));
            data += sizeof(white_point);
            size -= sizeof(white_point);
        }
        cmsCIExyYTRIPLE primaries;
        if (size >= sizeof(primaries)) {
            memcpy(&primaries, data, sizeof(primaries));
            data += sizeof(primaries);
            size -= sizeof(primaries);
        }

        // Create an RGB profile.
        cmsHPROFILE profile = cmsCreateRGBProfile(&white_point, &primaries, gamma_curves);
        if (profile) {
            // Fuzz the gamma detection function.
            cmsDetectRGBProfileGamma(profile, 0.1);

            // Added to target PostScript generation functions in cmsps2.c
            // The cmsGetPostScriptCSA/CRD functions write to a buffer, not an IO handler.
            // We can allocate a small buffer to exercise the code path without trying to generate full output.
            char ps_buffer[256];
            cmsGetPostScriptCSA(context, profile, INTENT_PERCEPTUAL, 0, ps_buffer, sizeof(ps_buffer));
            cmsGetPostScriptCRD(context, profile, INTENT_PERCEPTUAL, 0, ps_buffer, sizeof(ps_buffer));

            // Added to target transform, formatter, and alpha-handling code.
            cmsHPROFILE srgb_profile = cmsCreate_sRGBProfileTHR(context);
            if (srgb_profile) {
                // Use RGBA/BGRA formats and COPY_ALPHA to target cmsalpha.c
                cmsHTRANSFORM transform = cmsCreateTransform(profile, TYPE_RGBA_FLT, srgb_profile, TYPE_BGRA_8, INTENT_PERCEPTUAL, cmsFLAGS_COPY_ALPHA);
                if (transform) {
                    float in[4] = { 0.1f, 0.2f, 0.3f, 0.9f };
                    uint8_t out[4];
                    cmsDoTransform(transform, in, out, 1);
                    cmsDeleteTransform(transform);
                }
                cmsCloseProfile(srgb_profile);
            }

            cmsCloseProfile(profile);
        }
    }
    // Free the duplicated curves.
    if(gamma_curves[0]) cmsFreeToneCurve(gamma_curves[0]);
    if(gamma_curves[1]) cmsFreeToneCurve(gamma_curves[1]);
    if(gamma_curves[2]) cmsFreeToneCurve(gamma_curves[2]);


    // --- Fuzz Pipeline and Stage Functions ---
    if (size < 4) {
        cmsFreeToneCurve(curve);
        cmsDeleteContext(context);
        return 0;
    }

    // Added to target cmsCreateInkLimitingDeviceLink in cmsvirt.c
    if (size >= sizeof(double)) {
        cmsHPROFILE ink_limit_profile = cmsCreateInkLimitingDeviceLink(cmsSigCmykData, *(double*)data);
        if (ink_limit_profile) {
            cmsCloseProfile(ink_limit_profile);
        }
    }


    uint8_t num_channels = (data[0] % cmsMAXCHANNELS) + 1;
    data += 1;
    size -= 1;

    // Create a tone curve stage.
    cmsToneCurve* curves_for_stage[num_channels];
    for (int i = 0; i < num_channels; i++) {
        curves_for_stage[i] = cmsDupToneCurve(curve);
    }
    cmsStage *stage1 = cmsStageAllocToneCurves(context, num_channels, (cmsToneCurve* const*)curves_for_stage);
    for (int i = 0; i < num_channels; i++) {
        if(curves_for_stage[i]) cmsFreeToneCurve(curves_for_stage[i]);
    }

    // Create a Lab prelinearization stage.
    cmsStage *stage2 = _cmsStageAllocLabPrelin(context);

    // Create a CLUT stage.
    uint8_t num_grid_points = (data[0] % 15) + 2;
    uint8_t input_chan = (data[1] % 3) + 1;
    uint8_t output_chan = (data[2] % 3) + 1;
    data += 3;
    size -= 3;

    // Safely calculate the table size to avoid integer overflow.
    uint32_t table_size = 1;
    int overflow = 0;
    for(int i=0; i < input_chan; i++) {
        if (__builtin_mul_overflow(table_size, num_grid_points, &table_size)) {
            overflow = 1;
            break;
        }
    }
    if (!overflow && __builtin_mul_overflow(table_size, output_chan, &table_size)) {
        overflow = 1;
    }

    cmsStage *stage3 = NULL;
    if (!overflow && size >= table_size * sizeof(float)) {
        stage3 = cmsStageAllocCLutFloat(context, num_grid_points, input_chan, output_chan, (const cmsFloat32Number*)data);
        if (stage3) {
            // Fuzz the CLUT sampling function.
            // The cargo for sampler_float is the number of output channels.
            // It must be an int, not a uint8_t, to avoid a stack read overflow inside the sampler.
            int n_output_chan_for_sampler = output_chan;
            cmsStageSampleCLutFloat(stage3, sampler_float, &n_output_chan_for_sampler, 0);
        }
    }

    // Create a pipeline and add the stages.
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline) {
        if (stage1) cmsPipelineInsertStage(pipeline, cmsAT_END, stage1);
        if (stage2) cmsPipelineInsertStage(pipeline, cmsAT_END, stage2);
        if (stage3) cmsPipelineInsertStage(pipeline, cmsAT_END, stage3);

        // Added to target cmsPipelineUnlinkStage in cmslut.c
        cmsStage* unlinked_stage = NULL;
        if (cmsPipelineStageCount(pipeline) > 0) {
            cmsPipelineUnlinkStage(pipeline, cmsAT_BEGIN, &unlinked_stage);
            if (unlinked_stage) {
                cmsStageFree(unlinked_stage);
            }
        }

        // Fuzz simple pipeline inspection functions.
        cmsGetPipelineContextID(pipeline);
        cmsPipelineStageCount(pipeline);

        // Free the pipeline and all its stages.
        cmsPipelineFree(pipeline);
    } else {
        // If pipeline allocation fails, free stages manually.
        if (stage1) cmsStageFree(stage1);
        if (stage2) cmsStageFree(stage2);
        if (stage3) cmsStageFree(stage3);
    }

    // Final cleanup.
    cmsFreeToneCurve(curve);
    cmsDeleteContext(context);

    return 0;
}