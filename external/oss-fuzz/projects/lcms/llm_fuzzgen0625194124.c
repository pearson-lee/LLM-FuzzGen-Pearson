#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

// Fuzz target entry point.
// The fuzzer will select one of five scenarios based on the first byte of input data.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Use a byte from the data to choose which API to fuzz.
    // This helps isolate crashes to a specific scenario.
    unsigned int choice = data[0] % 5; // Increased to 5 to accommodate a new scenario
    data++;
    size--;

    // All lcms functions that perform allocations must be executed within a valid context.
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    switch (choice) {
    case 0: {
        // Scenario 1: Fuzz profile parsing and tag reading.
        cmsHPROFILE hProfile = cmsOpenProfileFromMemTHR(context, data, size);
        if (hProfile) {
            // Added more tag reading to target uncovered type handlers from cmstypes.c.
            // The fuzzer may generate profiles that contain these tags.
            cmsReadTag(hProfile, cmsSigBToA0Tag);
            cmsReadTag(hProfile, cmsSigNamedColor2Tag);
            cmsReadTag(hProfile, cmsSigUcrBgTag);
            cmsReadTag(hProfile, cmsSigCrdInfoTag);
            cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);

            // Clean up the profile handle.
            cmsCloseProfile(hProfile);
        }
        break;
    }

    case 1: {
        // Scenario 2: Fuzz _cmsDefaultICCintents.
        // Goal: Test the creation of a complex pipeline from multiple profiles.
        if (size < 1) break;
        cmsUInt32Number nProfiles = (data[0] % 4) + 1; // Use 1 to 4 profiles.
        data++;
        size--;

        // Ensure there's enough data for the required arrays.
        if (size < (nProfiles * (sizeof(cmsUInt32Number) + sizeof(cmsBool) + sizeof(cmsFloat64Number)))) break;

        cmsHPROFILE hProfiles[4] = {NULL, NULL, NULL, NULL};
        cmsUInt32Number TheIntents[4];
        cmsBool BPC[4];
        cmsFloat64Number AdaptationStates[4];
        cmsUInt32Number i;

        // Create dummy profiles to build the transform.
        for (i = 0; i < nProfiles; i++) {
            hProfiles[i] = cmsCreateGrayProfile(context, NULL);
            if (!hProfiles[i]) {
                // If one creation fails, clean up previously created profiles and exit.
                for (cmsUInt32Number j = 0; j < i; j++) {
                    cmsCloseProfile(hProfiles[j]);
                }
                cmsDeleteContext(context);
                return 0;
            }
        }

        // Populate parameters from fuzzer data.
        memcpy(TheIntents, data, nProfiles * sizeof(cmsUInt32Number));
        data += nProfiles * sizeof(cmsUInt32Number);
        memcpy(BPC, data, nProfiles * sizeof(cmsBool));
        data += nProfiles * sizeof(cmsBool);
        memcpy(AdaptationStates, data, nProfiles * sizeof(cmsFloat64Number));

        // Call the target function to create the pipeline.
        cmsPipeline *p = _cmsDefaultICCintents(context, nProfiles, TheIntents, hProfiles, BPC, AdaptationStates, 0);

        // Clean up all allocated resources.
        if (p) {
            cmsPipelineFree(p);
        }
        for (i = 0; i < nProfiles; i++) {
            cmsCloseProfile(hProfiles[i]);
        }
        break;
    }

    case 2: {
        // Scenario 3: Fuzz cmsIT8SetPropertyMulti and other IT8 functions.
        // Goal: Test the IT8 (CGATS) data handling functionality.
        cmsHANDLE hIT8 = cmsIT8Alloc(context);
        if (!hIT8) break;

        if (size < 3) {
            cmsIT8Free(hIT8);
            break;
        }

        // Divide the input data into three null-terminated strings for the properties.
        size_t part_len = size / 3;
        char *prop = (char *)malloc(part_len + 1);
        char *subprop = (char *)malloc(part_len + 1);
        char *value = (char *)malloc(size - 2 * part_len + 1);

        if (!prop || !subprop || !value) {
            free(prop);
            free(subprop);
            free(value);
            cmsIT8Free(hIT8);
            break;
        }

        memcpy(prop, data, part_len);
        prop[part_len] = '\0';
        memcpy(subprop, data + part_len, part_len);
        subprop[part_len] = '\0';
        memcpy(value, data + 2 * part_len, size - 2 * part_len);
        value[size - 2 * part_len] = '\0';

        // Call the target function.
        cmsIT8SetPropertyMulti(hIT8, prop, subprop, value);

        // Added call to cmsIT8EnumPropertyMulti to improve coverage in cmscgats.c,
        // as this function was previously uncovered.
        const char **SubpropertyNames = NULL;
        cmsIT8EnumPropertyMulti(hIT8, prop, &SubpropertyNames);

        // Clean up all memory.
        free(prop);
        free(subprop);
        free(value);
        cmsIT8Free(hIT8);
        break;
    }

    case 3: {
        // Scenario 4: Fuzz cmsStageAllocCLutFloat.
        // Goal: Test the creation of a floating-point CLUT pipeline stage.
        if (size < 3) break;

        // Restrict parameters to prevent excessive memory allocation.
        cmsUInt32Number inputChan = (data[0] % 3) + 1;  // 1-3 channels
        cmsUInt32Number outputChan = (data[1] % 3) + 1; // 1-3 channels
        cmsUInt32Number nGridPoints = (data[2] % 32) + 2; // 2-33 grid points
        data += 3;
        size -= 3;

        // Safely calculate the required table size, checking for potential overflow.
        double table_entries_d = pow((double)nGridPoints, (double)inputChan);
        if (table_entries_d > 200000.0) break; // Limit to ~800KB table
        cmsUInt32Number table_entries = (cmsUInt32Number)table_entries_d;

        cmsUInt32Number table_floats = table_entries * outputChan;
        if (table_floats > 200000) break;

        // Ensure we have enough data for the table.
        if (size < table_floats * sizeof(cmsFloat32Number)) break;

        const cmsFloat32Number *table_data = (const cmsFloat32Number *)data;

        // Allocate the CLUT stage.
        cmsStage *stage = cmsStageAllocCLutFloat(context, nGridPoints, inputChan, outputChan, table_data);

        // Free the stage if allocation was successful.
        if (stage) {
            cmsStageFree(stage);
        }
        break;
    }
    case 4: {
        // Added scenario to target PostScript generation functions in cmsps2.c,
        // which were previously uncovered.
        cmsHPROFILE hProfile = cmsOpenProfileFromMemTHR(context, data, size);
        if (hProfile) {
            char buffer[1024];
            cmsGetPostScriptCSA(context, hProfile, 0, 0, buffer, sizeof(buffer));
            cmsGetPostScriptCRD(context, hProfile, 0, 0, buffer, sizeof(buffer));
            cmsCloseProfile(hProfile);
        }
        break;
    }
    }

    cmsDeleteContext(context);
    return 0;
}