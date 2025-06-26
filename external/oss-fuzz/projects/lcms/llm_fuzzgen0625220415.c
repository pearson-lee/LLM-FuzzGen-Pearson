#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Include the main header for the lcms2 library.
#include "/src/lcms/include/lcms2.h"

// Fuzz target entry point.
// The fuzzer will explore three different paths based on the input data
// to cover a diverse set of APIs.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input to select which API set to fuzz.
    // This allows the fuzzer to explore different functionalities of the library.
    unsigned int choice = Data[0] % 3;
    Data++;
    Size--;

    if (choice == 0) {
        if (Size == 0) {
            return 0;
        }
        // --- Fuzzing Path 1: ICC Profile Parsing ---
        // This path focuses on parsing ICC profiles from memory. cmsOpenProfileFromMem
        // is the main entry point for this and will trigger a cascade of parsing functions.
        // Many of the Type_*_Read functions with 0% coverage will be exercised here.
        cmsHPROFILE hProfile = cmsOpenProfileFromMem(Data, Size);
        if (hProfile) {
            // If the profile was opened successfully, it implies a valid header and tag table.
            // We can now try to read all the tags to exercise the individual tag parsers.
            cmsUInt32Number nTags = cmsGetTagCount(hProfile);
            for (cmsUInt32Number i = 0; i < nTags; i++) {
                cmsTagSignature sig = cmsGetTagSignature(hProfile, i);
                // cmsReadTag allocates memory for the tag data. We don't use the data directly,
                // but calling the function is enough to exercise the parsing code for that tag type.
                // The memory allocated by cmsReadTag is associated with the profile handle
                // and will be correctly freed when cmsCloseProfile is called.
                cmsReadTag(hProfile, sig);
            }

            // The function cmsFormatterForPCSOfProfile has 0% coverage.
            // Let's call it with some common arguments to improve coverage.
            cmsFormatterForPCSOfProfile(hProfile, 2, 0); // For 16-bit integer format
            cmsFormatterForPCSOfProfile(hProfile, 4, 1); // For 32-bit float format

            // Clean up the profile handle and all associated resources. This is crucial
            // to prevent memory leaks.
            cmsCloseProfile(hProfile);
        }
    } else if (choice == 1) {
        if (Size == 0) {
            return 0;
        }
        // --- Fuzzing Path 2: IT8 File Parsing ---
        // This path fuzzes the parser for IT8 characterization data sheets.
        cmsHANDLE hIT8 = cmsIT8LoadFromMem(NULL, Data, Size);
        if (hIT8) {
            // If the IT8 data was parsed successfully, we must free the handle
            // to release the allocated memory.
            cmsIT8Free(hIT8);
        }
    } else { // choice == 2
        // --- Fuzzing Path 3: Color Conversion and Difference Functions ---
        // This path targets several color utility functions that have 0% coverage.

        // Fuzz various delta-E (color difference) functions.
        if (Size >= sizeof(cmsCIELab) * 2) {
            // We treat the input data as two cmsCIELab structures.
            const cmsCIELab* lab1 = (const cmsCIELab*)Data;
            const cmsCIELab* lab2 = (const cmsCIELab*)(Data + sizeof(cmsCIELab));

            // These delta-E functions are completely uncovered according to the report.
            cmsDeltaE(lab1, lab2);
            cmsCIE94DeltaE(lab1, lab2);
            cmsBFDdeltaE(lab1, lab2);
            cmsCMCdeltaE(lab1, lab2, 1.0, 1.0);
            cmsCIE2000DeltaE(lab1, lab2, 1.0, 1.0, 1.0);
        }

        // Fuzz Lab color encoding/decoding functions.
        if (Size >= sizeof(cmsUInt16Number) * 3) {
            cmsCIELab lab;
            // cmsLabEncoded2FloatV2 has 0% coverage.
            cmsLabEncoded2FloatV2(&lab, (const cmsUInt16Number*)Data);

            cmsUInt16Number wlab[3];
            // cmsFloat2LabEncodedV2 also has 0% coverage.
            cmsFloat2LabEncodedV2(wlab, &lab);
        }
    }

    return 0;
}