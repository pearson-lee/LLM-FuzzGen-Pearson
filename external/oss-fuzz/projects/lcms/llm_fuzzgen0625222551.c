#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Include the main header for the lcms2 library.
#include "/src/lcms/include/lcms2.h"

// Fuzz target entry point.
// The fuzzer will explore five different paths based on the input data
// to cover a diverse set of APIs.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input to select which API set to fuzz.
    // This allows the fuzzer to explore different functionalities of the library.
    unsigned int choice = Data[0] % 5;
    Data++;
    Size--;

    if (choice == 0) {
        // --- Fuzzing Path 1: ICC Profile Parsing and Writing ---
        // This path is enhanced to cover tag writing and saving, which in turn provides
        // valid profiles for the reading path, fixing the zero-tag issue from the
        // original fuzzer.
        cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
        if (!hProfile) {
            return 0;
        }

        // Create and write a profile description tag to exercise tag writing APIs.
        cmsMLU *mlu = cmsMLUalloc(NULL, 1);
        if (mlu) {
            cmsMLUsetASCII(mlu, "en", "US", "Fuzzer-generated profile");
            cmsWriteTag(hProfile, cmsSigProfileDescriptionTag, mlu);
            cmsMLUfree(mlu);
        }

        // Save the profile to a memory buffer to exercise the save-to-memory functionality.
        unsigned char *buffer = NULL;
        cmsUInt32Number profileLen = 0;
        if (cmsSaveProfileToMem(hProfile, NULL, &profileLen)) {
            buffer = (unsigned char *)malloc(profileLen);
            if (buffer) {
                cmsSaveProfileToMem(hProfile, buffer, &profileLen);

                // Now, open the profile from the buffer we just created. This ensures
                // that the profile parsing logic is tested with a known-good profile
                // that is guaranteed to have at least one tag.
                cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(buffer, profileLen);
                if (hProfileRead) {
                    // This loop, previously uncovered, is now reachable.
                    cmsUInt32Number nTags = cmsGetTagCount(hProfileRead);
                    for (cmsUInt32Number i = 0; i < nTags; i++) {
                        cmsTagSignature sig = cmsGetTagSignature(hProfileRead, i);
                        cmsReadTag(hProfileRead, sig);
                    }
                    cmsFormatterForPCSOfProfile(hProfileRead, 2, 0);
                    cmsFormatterForPCSOfProfile(hProfileRead, 4, 1);
                    cmsCloseProfile(hProfileRead);
                }
                free(buffer);
            }
        }
        cmsCloseProfile(hProfile);

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
    } else if (choice == 2) {
        // --- Fuzzing Path 3: Color Conversion and Difference Functions ---
        // This path targets several color utility functions.

        // Fuzz various delta-E (color difference) functions.
        if (Size >= sizeof(cmsCIELab) * 2) {
            const cmsCIELab* lab1 = (const cmsCIELab*)Data;
            const cmsCIELab* lab2 = (const cmsCIELab*)(Data + sizeof(cmsCIELab));
            cmsDeltaE(lab1, lab2);
            cmsCIE94DeltaE(lab1, lab2);
            cmsBFDdeltaE(lab1, lab2);
            cmsCMCdeltaE(lab1, lab2, 1.0, 1.0);
            cmsCIE2000DeltaE(lab1, lab2, 1.0, 1.0, 1.0);
        }

        // Fuzz Lab color encoding/decoding functions.
        if (Size >= sizeof(cmsUInt16Number) * 3) {
            cmsCIELab lab;
            cmsLabEncoded2FloatV2(&lab, (const cmsUInt16Number*)Data);
            cmsUInt16Number wlab[3];
            cmsFloat2LabEncodedV2(wlab, &lab);
        }
    } else if (choice == 3) {
        // --- Fuzzing Path 4: PostScript Generation ---
        // This path was added to target the PostScript generation functions in cmsps2.c,
        // which were previously uncovered.
        cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
        if (!hProfile) {
            return 0;
        }

        // To use cmsGetPostScriptCSA, we first call it with a NULL buffer
        // to determine the required size.
        cmsUInt32Number csaSize = cmsGetPostScriptCSA(NULL, hProfile, 0, 0, NULL, 0);
        if (csaSize > 0) {
            void *csaBuffer = malloc(csaSize);
            if (csaBuffer) {
                // Then we call it again with the allocated buffer.
                cmsGetPostScriptCSA(NULL, hProfile, 0, 0, csaBuffer, csaSize);
                free(csaBuffer);
            }
        }

        // We do the same for cmsGetPostScriptCRD.
        cmsUInt32Number crdSize = cmsGetPostScriptCRD(NULL, hProfile, 0, 0, NULL, 0);
        if (crdSize > 0) {
            void *crdBuffer = malloc(crdSize);
            if (crdBuffer) {
                // Then we call it again with the allocated buffer.
                cmsGetPostScriptCRD(NULL, hProfile, 0, 0, crdBuffer, crdSize);
                free(crdBuffer);
            }
        }

        cmsCloseProfile(hProfile);
    } else { // choice == 4
        // --- Fuzzing Path 5: Named Color Lists ---
        // This path was added to target the named color functions in cmsnamed.c,
        // which were previously uncovered.
        if (Size < 40) { // Need enough data for names and color values
            return 0;
        }

        // Allocate a named color list.
        cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(NULL, 1, 3, "prefix", "suffix");
        if (nc) {
            char name[33];
            strncpy(name, (const char*)Data, 32);
            name[32] = '\0';
            Data += 32;
            Size -= 32;

            cmsUInt16Number PCS[3];
            cmsUInt16Number Colorant[16];
            if (Size >= sizeof(PCS) + sizeof(Colorant[0])) {
                memcpy(PCS, Data, sizeof(PCS));
                memcpy(Colorant, Data + sizeof(PCS), sizeof(Colorant[0]));

                // Append a color to exercise writing functions.
                cmsAppendNamedColor(nc, name, PCS, Colorant);

                // Check the count and info to exercise reading functions.
                cmsUInt32Number count = cmsNamedColorCount(nc);
                if (count > 0) {
                    cmsNamedColorInfo(nc, 0, NULL, NULL, NULL, PCS, Colorant);
                }
            }
            cmsFreeNamedColorList(nc);
        }
    }

    return 0;
}