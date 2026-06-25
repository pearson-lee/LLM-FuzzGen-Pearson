#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// Define a simple parametric curve evaluator function for the plugin.
static cmsFloat64Number TestParametricCurve(cmsInt32Number Type, const cmsFloat64Number Params[], cmsFloat64Number R) {
    return R * Params[0];
}

// Define the plugin structure.
static cmsPluginParametricCurves MyParametricCurves = {
    .nFunctions = 1,
    .FunctionTypes = {10},
    .ParameterCount = {1},
    .Evaluator = (cmsParametricCurveEvaluator)TestParametricCurve
};

// Helper function to consume data from the fuzzing input buffer.
static int ConsumeData(const uint8_t **data, size_t *size, void *dest, size_t dest_size) {
    if (*size < dest_size) {
        return 0;
    }
    memcpy(dest, *data, dest_size);
    *data += dest_size;
    *size -= dest_size;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 100) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    /*
     * ANALYSIS: The function cmsCIECAM02Init has uncovered branches for different
     *           surround conditions (CUTSHEET_SURROUND, DARK_SURROUND) and for
     *           when D_value is D_CALCULATE.
     * IMPLEMENTATION: The following code creates a cmsViewingConditions struct,
     *                 fuzzes the surround and D_value fields, and then calls
     *                 cmsCIECAM02Init to exercise these paths.
     */
    cmsViewingConditions vc;
    if (!ConsumeData(&data, &size, &vc.whitePoint, sizeof(vc.whitePoint)) ||
        !ConsumeData(&data, &size, &vc.La, sizeof(vc.La)) ||
        !ConsumeData(&data, &size, &vc.Yb, sizeof(vc.Yb))) {
        cmsDeleteContext(context);
        return 0;
    }
    uint8_t surround_choice;
    if (!ConsumeData(&data, &size, &surround_choice, sizeof(surround_choice))) {
        cmsDeleteContext(context);
        return 0;
    }
    vc.surround = (cmsInt32Number)(surround_choice % 4);

    uint8_t d_value_choice;
    if (!ConsumeData(&data, &size, &d_value_choice, sizeof(d_value_choice))) {
        cmsDeleteContext(context);
        return 0;
    }
    if (d_value_choice % 2) {
        if (!ConsumeData(&data, &size, &vc.D_value, sizeof(vc.D_value))) {
            cmsDeleteContext(context);
            return 0;
        }
    } else {
        vc.D_value = 1.0; // D_CALCULATE is not a public enum value, using a valid default
    }

    cmsHANDLE hCam = cmsCIECAM02Init(context, &vc);
    if (hCam) {
        cmsCIECAM02Done(hCam);
    }

    /*
     * ANALYSIS: The line coverage report shows that the code path for registering
     *           a non-NULL plugin in _cmsRegisterParametricCurvesPlugin is never taken.
     * IMPLEMENTATION: This code block registers a custom parametric curve plugin
     *                 to cover the plugin registration logic. It then unregisters
     *                 it to clean up.
     */
    uint8_t plugin_choice;
    if (ConsumeData(&data, &size, &plugin_choice, sizeof(plugin_choice))) {
        if (plugin_choice % 2) {
            _cmsRegisterParametricCurvesPlugin(context, &MyParametricCurves);
        } else {
            _cmsRegisterParametricCurvesPlugin(context, NULL);
        }
    }


    /*
     * ANALYSIS: The error handling paths in cmsOpenIOhandlerFromMem, such as when
     *           the buffer is NULL, are not covered.
     * IMPLEMENTATION: This block calls cmsOpenIOhandlerFromMem with fuzzed data.
     *                 It sometimes provides a NULL buffer to specifically target
     *                 the uncovered error-handling branches.
     */
    uint8_t io_choice;
    if (ConsumeData(&data, &size, &io_choice, sizeof(io_choice))) {
        cmsIOHANDLER *io;
        size_t data_size = size > 1024 ? 1024 : size;
        if (io_choice % 2) {
            io = cmsOpenIOhandlerFromMem(context, (void*)data, data_size, "r");
        } else {
            io = cmsOpenIOhandlerFromMem(context, NULL, 0, "w");
        }
        if (io) {
            cmsCloseIOhandler(io);
        }
    }

    /*
     * ANALYSIS: cmsDetectDestinationBlackPoint has very low coverage, with many
     *           paths related to different profile types and intents being missed.
     * IMPLEMENTATION: An sRGB profile is created, and cmsDetectDestinationBlackPoint
     *                 is called with a fuzzed intent. This aims to exercise the
     *                 logic for different rendering intents.
     */
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile) {
        cmsCIEXYZ black_point;
        uint8_t intent_choice;
        if (ConsumeData(&data, &size, &intent_choice, sizeof(intent_choice))) {
            cmsDetectDestinationBlackPoint(&black_point, hProfile, intent_choice % 4, 0);
        }
        cmsCloseProfile(hProfile);
    }

    /*
     * ANALYSIS: The code path in _cmsHandleExtraChannels for handling more than
     *           one extra channel (nExtra > 1) is never executed because cmsCreateTransform
     *           was always failing. The function coverage report also shows that
     *           ComputeIncrementsForPlanar in cmsalpha.c is uncovered.
     * IMPLEMENTATION: Switched from cmsCreateNULLProfileTHR to cmsCreate_sRGBProfileTHR,
     *                 adjusted the channel count, and added PLANAR_SH(1) to the format
     *                 to exercise planar handling logic. This creates a valid transform,
     *                 allowing the code paths that handle extra and planar channels to be executed.
     */
    cmsHPROFILE hInProfile = cmsCreate_sRGBProfileTHR(context);
    cmsHPROFILE hOutProfile = cmsCreate_sRGBProfileTHR(context);
    if (hInProfile && hOutProfile) {
        cmsUInt32Number inFormat = (CHANNELS_SH(3) | BYTES_SH(2) | EXTRA_SH(2) | PLANAR_SH(1));
        cmsUInt32Number outFormat = (CHANNELS_SH(3) | BYTES_SH(2) | EXTRA_SH(2) | PLANAR_SH(1));
        cmsHTRANSFORM hTransform = cmsCreateTransform(hInProfile, inFormat, hOutProfile, outFormat,
                                                      INTENT_PERCEPTUAL, cmsFLAGS_COPY_ALPHA);
        if (hTransform) {
            size_t num_pixels = size > 10 ? 10 : size;
            size_t in_bpc = (((inFormat)>>7)&7);
            size_t out_bpc = (((outFormat)>>7)&7);
            size_t in_channels = cmsChannelsOf(cmsGetColorSpace(hInProfile)) + (((inFormat)>>10)&7);
            size_t out_channels = cmsChannelsOf(cmsGetColorSpace(hOutProfile)) + (((outFormat)>>10)&7);
            size_t in_size = num_pixels * in_bpc * in_channels;
            size_t out_size = num_pixels * out_bpc * out_channels;
            
            if (size >= in_size) {
                void *in_buf = malloc(in_size);
                void *out_buf = malloc(out_size);
                if (in_buf && out_buf) {
                    memcpy(in_buf, data, in_size);
                    cmsDoTransform(hTransform, in_buf, out_buf, num_pixels);
                }
                free(in_buf);
                free(out_buf);
            }
            cmsDeleteTransform(hTransform);
        }
    }
    if (hInProfile) cmsCloseProfile(hInProfile);
    if (hOutProfile) cmsCloseProfile(hOutProfile);

    /*
     * ANALYSIS: The function-level coverage report indicates that functions in
     *           cmsps2.c related to PostScript generation (e.g., GenerateCSA,
     *           GenerateCRD, WriteNamedColorCRD) have low or no coverage.
     * IMPLEMENTATION: This block creates a memory-based IO handler and calls
     *                 cmsGetPostScriptCSA and cmsGetPostScriptCRD to generate
     *                 PostScript resources, exercising these uncovered code paths.
     */
    uint8_t ps_intent;
    if (ConsumeData(&data, &size, &ps_intent, sizeof(ps_intent))) {
        cmsHPROFILE psProfile = cmsCreate_sRGBProfileTHR(context);
        if (psProfile) {
            char buffer[2048];
            cmsGetPostScriptCSA(context, psProfile, ps_intent % 4, 0, buffer, sizeof(buffer));
            cmsGetPostScriptCRD(context, psProfile, ps_intent % 4, 0, buffer, sizeof(buffer));
            cmsCloseProfile(psProfile);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows that the entire CGATS
     *           parsing functionality in cmscgats.c is uncovered because cmsIT8LoadFromMem
     *           always fails on raw fuzzer data.
     * IMPLEMENTATION: This block prepends a minimal valid IT8 header to the fuzzer
     *                 data. This allows the initial file type check to pass,
     *                 enabling the fuzzer to penetrate the actual parsing logic.
     */
    if (size > 0) {
        const char* header = "IT8.7/2\n";
        size_t header_len = strlen(header);
        size_t new_size = size + header_len;
        uint8_t* new_data = (uint8_t*) malloc(new_size);
        if (new_data) {
            memcpy(new_data, header, header_len);
            memcpy(new_data + header_len, data, size);
            cmsHANDLE hIT8 = cmsIT8LoadFromMem(context, new_data, new_size);
            if (hIT8) {
                cmsIT8Free(hIT8);
            }
            free(new_data);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows that cmsDictGetEntryList
     *           and cmsDictNextEntry are never called.
     * IMPLEMENTATION: This block creates a dictionary, adds a static entry, and
     *                 then iterates through the dictionary to cover these functions.
     *                 This ensures the list traversal logic is exercised.
     */
    cmsHANDLE hDict = cmsDictAlloc(context);
    if (hDict) {
        cmsDictAddEntry(hDict, L"Name", L"Value", NULL, NULL);
        const cmsDICTentry* entry = cmsDictGetEntryList(hDict);
        while (entry != NULL) {
            entry = cmsDictNextEntry(entry);
        }
        cmsDictFree(hDict);
    }

    /*
     * ANALYSIS: The function-level coverage report shows that cmsDesaturateLab
     *           in cmsgmt.c is completely uncovered.
     * IMPLEMENTATION: This block calls cmsDesaturateLab with fuzzed values
     *                 to exercise this function and related gamut mapping logic.
     */
    if (size >= sizeof(cmsCIELab) + (4 * sizeof(double))) {
        cmsCIELab lab;
        double a, b, La, Lb;
        ConsumeData(&data, &size, &lab, sizeof(cmsCIELab));
        ConsumeData(&data, &size, &a, sizeof(double));
        ConsumeData(&data, &size, &b, sizeof(double));
        ConsumeData(&data, &size, &La, sizeof(double));
        ConsumeData(&data, &size, &Lb, sizeof(double));
        cmsDesaturateLab(&lab, a, b, La, Lb);
    }

    /*
     * ANALYSIS: The original attempt to write a cmsSigLut16Type tag failed. To
     *           cover tag read/write handlers, this block now targets the simpler,
     *           also uncovered, S15Fixed16Array type.
     * IMPLEMENTATION: This block creates a placeholder profile and writes a
     *                 cmsSigS15Fixed16ArrayType to it with fuzzed data. The profile
     *                 is then saved to memory and re-read, forcing the execution
     *                 of the Type_S15Fixed16_Write and Type_S15Fixed16_Read handlers.
     */
    cmsHPROFILE hArrayProfile = cmsCreateProfilePlaceholder(context);
    if (hArrayProfile) {
        cmsS15Fixed16Number fuzzed_array[10];
        if (ConsumeData(&data, &size, fuzzed_array, sizeof(fuzzed_array))) {
            if (cmsWriteTag(hArrayProfile, cmsSigS15Fixed16ArrayType, fuzzed_array)) {
                cmsUInt32Number profile_len = 0;
                cmsSaveProfileToMem(hArrayProfile, NULL, &profile_len);
                if (profile_len > 0) {
                    void* profile_mem = malloc(profile_len);
                    if (profile_mem) {
                        if(cmsSaveProfileToMem(hArrayProfile, profile_mem, profile_len)) {
                            cmsHPROFILE hRead = cmsOpenProfileFromMem(profile_mem, profile_len);
                            if (hRead) {
                                cmsS15Fixed16Number* pRead = (cmsS15Fixed16Number*) cmsReadTag(hRead, cmsSigS15Fixed16ArrayType);
                                // The returned pointer is managed by the profile, no need to free directly.
                                cmsCloseProfile(hRead);
                            }
                        }
                        free(profile_mem);
                    }
                }
            }
        }
        cmsCloseProfile(hArrayProfile);
    }


    cmsDeleteContext(context);
    return 0;
}