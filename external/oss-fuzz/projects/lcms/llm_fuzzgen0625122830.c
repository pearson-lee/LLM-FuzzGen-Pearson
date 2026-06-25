#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

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
    const cmsUInt32Number flags = *((const cmsUInt32Number*)(data + 1));
    const double dbl_val = *((const double*)(data + 5));
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

    cmsDeleteContext(context);
    return 0;
}