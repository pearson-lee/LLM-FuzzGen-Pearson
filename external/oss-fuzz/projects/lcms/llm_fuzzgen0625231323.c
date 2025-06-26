#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // Added to support cmsSigDateTimeTag

// Include the main header for the lcms2 library.
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// Fuzz target entry point.
// The fuzzer will explore seven different paths based on the input data
// to cover a diverse set of APIs.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of the input to select which API set to fuzz.
    // This allows the fuzzer to explore different functionalities of the library.
    // Increased choices from 6 to 7 to add a new fuzzing path for alpha channels.
    unsigned int choice = Data[0] % 7;
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

        // Added: Write a colorant order tag to cover Type_ColorantOrderType_Write in cmstypes.c
        // The colorant order tag requires a 16-byte array for the colorants, plus one byte for the count.
        // The original code provided a 3-byte array, causing a stack buffer overflow.
        cmsUInt8Number order[17] = {3, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // 3 colorants: RGB
        cmsWriteTag(hProfile, cmsSigColorantOrderTag, order);

        // Added: Write a measurement tag to cover Type_Measurement_Write in cmstypes.c
        cmsICCMeasurementConditions mc;
        mc.Observer = 1; // cmsICCStandardObserver_CIE1931
        mc.Backing.X = 0; mc.Backing.Y = 0; mc.Backing.Z = 0;
        mc.Geometry = 1; // cmsICCGeometry_45_0
        mc.Flare = 0;
        mc.IlluminantType = 1; // cmsILLUMINANT_TYPE_D50
        cmsWriteTag(hProfile, cmsSigMeasurementTag, &mc);

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
        // The logic is now changed to always execute this path and use fuzzer data
        // when available, or fixed data otherwise.
        cmsCIELab lab1, lab2;
        if (Size >= sizeof(cmsCIELab) * 2) {
            memcpy(&lab1, Data, sizeof(cmsCIELab));
            memcpy(&lab2, Data + sizeof(cmsCIELab), sizeof(cmsCIELab));
        } else if (Size >= sizeof(cmsCIELab)) {
            memcpy(&lab1, Data, sizeof(cmsCIELab));
            memcpy(&lab2, &lab1, sizeof(cmsCIELab));
            lab2.L = 100.0 - lab1.L; // Ensure values are different
        } else {
            // Not enough data, use fixed values to ensure functions are called.
            lab1 = (cmsCIELab){ .L = 50.0, .a = 10.0, .b = -10.0 };
            lab2 = (cmsCIELab){ .L = 70.0, .a = -20.0, .b = 20.0 };
        }

        cmsDeltaE(&lab1, &lab2);
        cmsCIE94DeltaE(&lab1, &lab2);
        cmsBFDdeltaE(&lab1, &lab2);
        cmsCMCdeltaE(&lab1, &lab2, 1.0, 1.0);
        cmsCIE2000DeltaE(&lab1, &lab2, 1.0, 1.0, 1.0);

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
            // Now we use fuzzer data if available, or fixed data otherwise,
            // to ensure the named color functions are always exercised.
            char name[33];
            cmsUInt16Number PCS[3];
            cmsUInt16Number Colorant[16];

            // Use fuzzer data if we have enough for a name and some color values.
            if (Size >= 32 + sizeof(PCS) + sizeof(Colorant[0])) {
                strncpy(name, (const char*)Data, 32);
                name[32] = '\0';
                memcpy(PCS, Data + 32, sizeof(PCS));
                memcpy(Colorant, Data + 32 + sizeof(PCS), sizeof(Colorant[0]));
            } else {
                // Otherwise, use fixed data.
                strcpy(name, "fuzzer_color");
                PCS[0] = 0x1111; PCS[1] = 0x2222; PCS[2] = 0x3333;
                Colorant[0] = 0x4444;
            }

            // Append a color to exercise writing functions.
            if(cmsAppendNamedColor(nc, name, PCS, Colorant)) {
                // Check the count and info to exercise reading functions.
                cmsUInt32Number count = cmsNamedColorCount(nc);
                if (count > 0) {
                    cmsNamedColorInfo(nc, 0, NULL, NULL, NULL, PCS, Colorant);
                }
            }
            cmsFreeNamedColorList(nc);
        }
    } else if (choice == 5) { 
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
    } else { // choice == 6
        // --- Fuzzing Path 7: Alpha Channel Handling ---
        // This path was added to target the alpha channel functions in cmsalpha.c,
        // which were previously uncovered, by creating a transform with the
        // cmsFLAGS_COPY_ALPHA flag.
        cmsHPROFILE hInProfile = cmsCreate_sRGBProfile();
        cmsHPROFILE hOutProfile = cmsCreate_sRGBProfile();
        if (!hInProfile || !hOutProfile) {
            if (hInProfile) cmsCloseProfile(hInProfile);
            if (hOutProfile) cmsCloseProfile(hOutProfile);
            return 0;
        }

        // Create a transform with the COPY_ALPHA flag.
        // This requires a pixel format that includes an alpha channel, like TYPE_RGBA_8.
        cmsHTRANSFORM hTransform = cmsCreateTransform(hInProfile, TYPE_RGBA_8,
                                                      hOutProfile, TYPE_RGBA_8,
                                                      INTENT_PERCEPTUAL, cmsFLAGS_COPY_ALPHA);

        if (hTransform) {
            // Create some dummy pixel data to transform.
            uint8_t in_pixels[] = { 10, 20, 30, 40, 50, 60, 70, 80 }; // 2 RGBA pixels
            uint8_t out_pixels[8];
            cmsDoTransform(hTransform, in_pixels, out_pixels, 2);
            cmsDeleteTransform(hTransform);
        }

        cmsCloseProfile(hInProfile);
        cmsCloseProfile(hOutProfile);
    }

    return 0;
}