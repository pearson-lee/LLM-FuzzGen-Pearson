#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // Added to support cmsSigDateTimeTag

// Include the main header for the lcms2 library.
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// Fuzz target entry point.
// The fuzzer will explore six different paths based on the input data
// to cover a diverse set of APIs.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input to select which API set to fuzz.
    // This allows the fuzzer to explore different functionalities of the library.
    // Increased choices from 5 to 6 to add a new fuzzing path.
    unsigned int choice = Data[0] % 6;
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
        
        // Added: Write a signature tag to cover Type_Signature_Write in cmstypes.c,
        // which was previously uncovered.
        cmsTagSignature mySig = (cmsTagSignature)'fuzz';
        cmsWriteTag(hProfile, cmsSigSignatureType, &mySig);

        // Added: Write a date time tag to cover Type_DateTime_Write in cmstypes.c,
        // which was previously uncovered.
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        if (tm_now) {
            cmsWriteTag(hProfile, cmsSigDateTimeTag, tm_now);
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
        // The original size check was too strict and prevented this block from ever executing.
        // Relaxed the check to ensure these functions are fuzzed even with small inputs.
        if (Size >= sizeof(cmsCIELab)) {
            cmsCIELab lab1, lab2;
            memcpy(&lab1, Data, sizeof(cmsCIELab));

            // If there isn't enough data for a second Lab value, create one from the first
            // to ensure the deltaE functions still have valid, non-identical inputs.
            if (Size >= sizeof(cmsCIELab) * 2) {
                memcpy(&lab2, Data + sizeof(cmsCIELab), sizeof(cmsCIELab));
            } else {
                memcpy(&lab2, &lab1, sizeof(cmsCIELab));
                lab2.L = 100.0 - lab1.L;
            }

            cmsDeltaE(&lab1, &lab2);
            cmsCIE94DeltaE(&lab1, &lab2);
            cmsBFDdeltaE(&lab1, &lab2);
            cmsCMCdeltaE(&lab1, &lab2, 1.0, 1.0);
            cmsCIE2000DeltaE(&lab1, &lab2, 1.0, 1.0, 1.0);
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
    } else if (choice == 4) {
        // --- Fuzzing Path 5: Named Color Lists ---
        // This path was added to target the named color functions in cmsnamed.c,
        // which were previously uncovered.

        // Allocate a named color list.
        cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(NULL, 1, 3, "prefix", "suffix");
        if (nc) {
            // The previous size check prevented this block from ever executing.
            // Now we check for size just before using the data, allowing
            // cmsAllocNamedColorList and cmsFreeNamedColorList to be covered regardless.
            if (Size >= 40) { // Need enough data for names and color values
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
                    if(cmsAppendNamedColor(nc, name, PCS, Colorant)) {
                        // Check the count and info to exercise reading functions.
                        cmsUInt32Number count = cmsNamedColorCount(nc);
                        if (count > 0) {
                            cmsNamedColorInfo(nc, 0, NULL, NULL, NULL, PCS, Colorant);
                        }
                    }
                }
            }
            cmsFreeNamedColorList(nc);
        }
    } else { // choice == 5
        // --- Fuzzing Path 6: Dictionary Functions ---
        // This path was added to target dictionary functions in cmsnamed.c,
        // which were previously uncovered (e.g., cmsDictGetEntryList, cmsDictNextEntry, cmsDictDup).
        cmsHANDLE dict = cmsDictAlloc(NULL);
        if (dict) {
            // Add some entries to the dictionary.
            cmsDictAddEntry(dict, L"Name1", L"Value1", NULL, NULL);
            cmsDictAddEntry(dict, L"Name2", L"Value2", NULL, NULL);

            // Exercise the duplication and iteration functions.
            cmsHANDLE dict_dup = cmsDictDup(dict);
            if (dict_dup) {
                const cmsDICTentry* entry = cmsDictGetEntryList(dict_dup);
                while (entry != NULL) {
                    // Iterate through the list to exercise the next entry function.
                    entry = cmsDictNextEntry(entry);
                }
                cmsDictFree(dict_dup);
            }
            cmsDictFree(dict);
        }
    }

    return 0;
}