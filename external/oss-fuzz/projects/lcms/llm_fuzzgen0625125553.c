#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzzer"
#endif

// Helper function to create a temporary file path
static char* GetTempPath(void) {
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);
    return path;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 20) {
        return 0;
    }

    // Consume data for fuzzing
    const cmsUInt32Number intent = data[0] % 4;
    cmsUInt32Number flags;
    // Use memcpy to avoid unaligned access, which is undefined behavior.
    memcpy(&flags, data + 1, sizeof(flags));
    double dbl_val;
    // Use memcpy to avoid unaligned access.
    memcpy(&dbl_val, data + 5, sizeof(dbl_val));

    const char *patch_name = (const char *)(data + 13);
    size_t remaining_size = size - 13;
    if (remaining_size > 50) {
      remaining_size = 50;
    }
    char sample_name[51];
    memcpy(sample_name, patch_name, remaining_size);
    sample_name[remaining_size] = '\0';


    // Create a context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    /*
     * ANALYSIS: The coverage report for cmsDetectDestinationBlackPoint shows that the
     *           main algorithm is never executed. This is because the profile used
     *           in testing does not pass the cmsIsCLUT() check, causing an early exit.
     * IMPLEMENTATION: Create a CMYK ink limiting profile, which is CLUT-based,
     *                 to ensure the main logic of cmsDetectDestinationBlackPoint is reached.
     *                 Fuzz the intent and flags to explore different paths within the algorithm.
     */
    cmsHPROFILE cmyk_profile = cmsCreateInkLimitingDeviceLink(cmsSigCmykData, 150);
    if (cmyk_profile) {
        cmsCIEXYZ black_point;
        cmsDetectDestinationBlackPoint(&black_point, cmyk_profile, intent, flags);
        cmsCloseProfile(cmyk_profile);
    }

    /*
     * ANALYSIS: The coverage for cmsIT8SaveToFile shows it always fails because the
     *           data section is NULL. This is because cmsIT8SetData is not correctly
     *           populating the data. The coverage for cmsIT8SetData reveals that the
     *           sample is never found because the data format is not initialized.
     * IMPLEMENTATION: Create an IT8 handle, define its data format using
     *                 cmsIT8SetDataFormat, and then populate it with data using
     *                 cmsIT8SetData. This ensures that when cmsIT8SaveToFile is called,
     *                 it has a valid, populated data structure to work with.
     */
    cmsHANDLE it8_handle = cmsIT8Alloc(context);
    if (it8_handle) {
        // Define the data format so that cmsIT8SetData can find the samples.
        cmsIT8SetDataFormat(it8_handle, 0, "SAMPLE_ID");
        cmsIT8SetDataFormat(it8_handle, 1, "RGB_R");
        cmsIT8SetDataFormat(it8_handle, 2, "RGB_G");

        /*
         * ANALYSIS: The function coverage report shows cmsIT8SetPropertyUncooked is
         *           never executed.
         * IMPLEMENTATION: Add a call to cmsIT8SetPropertyUncooked to provide
         *                 required metadata, which may also help cmsIT8SaveToFile
         *                 succeed and improve its coverage.
         */
        cmsIT8SetPropertyUncooked(it8_handle, "ORIGINATOR", "llm_fuzzer");
        /*
         * ANALYSIS: The line coverage for cmsIT8SaveToFile reveals that it fails because it cannot
         *           properly write the data. This is because the NUMBER_OF_FIELDS and NUMBER_OF_SETS
         *           properties are not set, or are set incorrectly. The original fuzzer set
         *           NUMBER_OF_SETS to 1, but added two patches ("A1", "A2"), and did not set
         *           NUMBER_OF_FIELDS at all.
         * IMPLEMENTATION: Set the "NUMBER_OF_FIELDS" to 3 to match the data format and
         *                 "NUMBER_OF_SETS" to 2 to match the number of patches being added.
         *                 This allows cmsIT8SetData to succeed in populating the data structure,
         *                 which in turn allows cmsIT8SaveToFile to correctly iterate and write the data.
         */
        cmsIT8SetPropertyDbl(it8_handle, "NUMBER_OF_FIELDS", 3);
        cmsIT8SetPropertyDbl(it8_handle, "NUMBER_OF_SETS", 2);


        // Populate with some data
        cmsIT8SetData(it8_handle, "A1", "SAMPLE_ID", "A1");
        cmsIT8SetDataDbl(it8_handle, "A1", "RGB_R", dbl_val);
        cmsIT8SetData(it8_handle, "A2", "SAMPLE_ID", "A2");
        cmsIT8SetData(it8_handle, "A2", "RGB_G", sample_name);

        // Save the IT8 data to a temporary file
        char *path = GetTempPath();
        if (cmsIT8SaveToFile(it8_handle, path)) {
            // The file is created, now we should clean it up.
            unlink(path);
        }
        cmsIT8Free(it8_handle);
    }

    /*
     * ANALYSIS: The function coverage report shows that functions in cmsps2.c,
     *           related to PostScript generation, are largely uncovered.
     * IMPLEMENTATION: Create an sRGB profile and call cmsGetPostScriptCSA and
     *                 cmsGetPostScriptCRD to generate PostScript data. This
     *                 targets the uncovered PostScript generation code paths.
     *                 The returned buffer is freed with cmsFree to prevent leaks.
     */
    cmsHPROFILE srgb_profile = cmsCreate_sRGBProfile();
    if (srgb_profile) {
        char* ps_buffer = NULL;
        cmsUInt32Number buffer_size;

        buffer_size = cmsGetPostScriptCSA(context, srgb_profile, intent, flags, NULL, 0);
        if (buffer_size > 0) {
            ps_buffer = (char*)malloc(buffer_size);
            if (ps_buffer) {
                cmsGetPostScriptCSA(context, srgb_profile, intent, flags, ps_buffer, buffer_size);
                free(ps_buffer);
            }
        }

        buffer_size = cmsGetPostScriptCRD(context, srgb_profile, intent, flags, NULL, 0);
        if (buffer_size > 0) {
            ps_buffer = (char*)malloc(buffer_size);
            if (ps_buffer) {
                cmsGetPostScriptCRD(context, srgb_profile, intent, flags, ps_buffer, buffer_size);
                free(ps_buffer);
            }
        }

        cmsCloseProfile(srgb_profile);
    }

    /*
     * ANALYSIS: The function-level coverage report shows that many core transform
     *           functions in cmsxform.c and formatters in cmsalpha.c are completely
     *           uncovered. This is because the fuzzer never creates and applies a
     *           color transform.
     * IMPLEMENTATION: Create a transform from an sRGB profile to a CMYK profile
     *                 using cmsCreateTransform. Then, call cmsDoTransform on some
     *                 fuzzer-derived pixel data. This directly targets the core
     *                 transformation pipeline. All resources are properly freed to
     *                 prevent memory leaks.
     */
    cmsHPROFILE srgb_profile_xform = cmsCreate_sRGBProfile();
    cmsHPROFILE cmyk_profile_xform = cmsCreateInkLimitingDeviceLink(cmsSigCmykData, 200);
    if (srgb_profile_xform && cmyk_profile_xform) {
        cmsHTRANSFORM hTransform = cmsCreateTransform(srgb_profile_xform, TYPE_RGB_8,
                                                      cmyk_profile_xform, TYPE_CMYK_8,
                                                      intent, flags);
        if (hTransform) {
            uint8_t rgb_in[3] = { data[10], data[11], data[12] };
            uint8_t cmyk_out[4];
            cmsDoTransform(hTransform, rgb_in, cmyk_out, 1);
            cmsDeleteTransform(hTransform);
        }
    }
    if (srgb_profile_xform) cmsCloseProfile(srgb_profile_xform);
    if (cmyk_profile_xform) cmsCloseProfile(cmyk_profile_xform);


    cmsDeleteContext(context);
    return 0;
}