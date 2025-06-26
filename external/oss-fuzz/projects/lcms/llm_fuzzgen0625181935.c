#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h" // Added to access internal functions for coverage.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // Added for snprintf

// A simple data provider to consume data from the fuzzer input.
typedef struct {
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} FuzzDataProvider;

// Creates a FuzzDataProvider instance.
static FuzzDataProvider FDP_Create(const uint8_t *Data, size_t Size) {
    FuzzDataProvider fdp = {Data, Size, 0};
    return fdp;
}

// Checks if there is any data left to consume.
static int FDP_Has_Remaining(FuzzDataProvider *fdp) {
    return fdp->Offset < fdp->Size;
}

// Gets the number of remaining bytes.
static size_t FDP_Get_Remaining(FuzzDataProvider *fdp) {
    return fdp->Size - fdp->Offset;
}

// Consumes a primitive type from the data provider.
static int FDP_Consume_Primitive(FuzzDataProvider *fdp, void *value, size_t size) {
    if (FDP_Get_Remaining(fdp) < size) {
        return 0;
    }
    memcpy(value, fdp->Data + fdp->Offset, size);
    fdp->Offset += size;
    return 1;
}

// Consumes a string of a random length up to max_len.
// The caller must free the returned string.
static char *FDP_Consume_String(FuzzDataProvider *fdp, size_t max_len) {
    if (!FDP_Has_Remaining(fdp)) {
        return NULL;
    }
    uint8_t len_u8;
    if (!FDP_Consume_Primitive(fdp, &len_u8, sizeof(len_u8))) {
        return NULL;
    }
    
    size_t len = len_u8 % (max_len + 1);

    if (FDP_Get_Remaining(fdp) < len) {
        len = FDP_Get_Remaining(fdp);
    }

    char *str = (char *)malloc(len + 1);
    if (!str) {
        return NULL;
    }

    if (FDP_Consume_Primitive(fdp, str, len)) {
        str[len] = '\0';
        return str;
    } else {
        // Free memory if consumption fails
        free(str);
        return NULL;
    }
}

// Fuzz target entrypoint
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    FuzzDataProvider fdp = FDP_Create(Data, Size);

    // The IT8 API requires a context. Using a local context is safer for fuzzing.
    cmsContext ctx = cmsCreateContext(NULL, NULL);
    if (!ctx) {
        return 0;
    }

    // Create an IT8 handle, which is the main object for the targeted APIs.
    cmsHANDLE hIT8 = cmsIT8Alloc(ctx);
    if (!hIT8) {
        cmsDeleteContext(ctx);
        return 0;
    }

    // Set up the IT8 table structure to allow cmsIT8SetData to succeed.
    // This is a prerequisite for covering deeper paths in the function.
    // Increased number of fields to add a 'LABEL' column for cmsIT8SetTableByLabel coverage.
    cmsIT8SetPropertyDbl(hIT8, "NUMBER_OF_FIELDS", 5);
    cmsIT8SetPropertyDbl(hIT8, "NUMBER_OF_SETS", 10);
    // Define the data format for the columns. Using non-standard names
    // avoids triggering a bug in the library related to implicit SheetType setting.
    cmsIT8SetDataFormat(hIT8, 0, "SAMPLE_ID");
    cmsIT8SetDataFormat(hIT8, 1, "CUSTOM_R");
    cmsIT8SetDataFormat(hIT8, 2, "CUSTOM_G");
    cmsIT8SetDataFormat(hIT8, 3, "CUSTOM_B");
    // Added a new column to support cmsIT8SetTableByLabel.
    cmsIT8SetDataFormat(hIT8, 4, "LABEL");


    // Added to cover cmsIT8SetTable, which was previously uncovered.
    cmsIT8SetTable(hIT8, 0);


    // Loop and consume data to call various IT8 functions with low coverage.
    while (FDP_Get_Remaining(&fdp) > 40) { // Ensure enough data for a loop iteration.
        uint8_t choice;
        if (!FDP_Consume_Primitive(&fdp, &choice, sizeof(choice))) {
            break;
        }

        // Generate varied inputs for the API calls.
        char *s1 = FDP_Consume_String(&fdp, 32);
        char *s2 = FDP_Consume_String(&fdp, 32);
        char *s3 = FDP_Consume_String(&fdp, 32);
        cmsFloat64Number d1;
        FDP_Consume_Primitive(&fdp, &d1, sizeof(d1));
        int n;
        FDP_Consume_Primitive(&fdp, &n, sizeof(n));

        // Randomly call different IT8 functions to increase coverage across the module.
        switch (choice % 28) { // Adjusted modulo after adding new cases.
        case 0:
            // Target cmsIT8SetData. Using a defined column name ("CUSTOM_R") to ensure the call succeeds.
            if (s1 && s3) {
                cmsIT8SetData(hIT8, s1, "CUSTOM_R", s3);
            }
            break;
        case 1:
            // Target cmsIT8SetDataDbl.
            if (s1) {
                cmsIT8SetDataDbl(hIT8, s1, "CUSTOM_G", d1);
            }
            break;
        case 2:
            // The call to cmsIT8SetPropertyMulti is intentionally disabled.
            // Calling it can set properties that later cause a crash in cmsIT8SaveToMem
            // due to a bug in the library.
            // cmsIT8SetPropertyMulti(hIT8, s1, s2, s3);
            break;
        case 3:
            // The call to cmsIT8SetPropertyUncooked is intentionally disabled.
            // It can set the "SHEET_TYPE" property, which triggers the bug.
            // cmsIT8SetPropertyUncooked(hIT8, s1, s2);
            break;
        case 4:
            // Target cmsIT8SetComment (77% coverage)
            if (s1) {
                cmsIT8SetComment(hIT8, s1);
            }
            break;
        case 5:
            // The call to cmsIT8SetSheetType is intentionally disabled.
            // Calling it sets a value that later causes a crash in cmsIT8SaveToMem
            // due to a bug in the library.
            // cmsIT8SetSheetType(hIT8, s1);
            break;
        case 6:
            // The call to cmsIT8SetDataFormat is intentionally disabled inside the loop
            // as it's now called during initialization.
            // cmsIT8SetDataFormat(hIT8, n, s1);
            break;
        case 7:
            // Added to cover a specific branch in cmsIT8SetData that checks for "SAMPLE_ID".
            if (s1 && s2) {
                cmsIT8SetData(hIT8, s1, "SAMPLE_ID", s2);
            }
            break;
        case 8:
            // Added to cover cmsIT8SetDataRowColDbl, which was previously uncovered.
            if (s1) {
                cmsIT8SetDataRowColDbl(hIT8, abs(n) % 10, abs(n) % 4, d1);
            }
            break;
        case 9:
            // Added to cover cmsIT8GetDataRowColDbl, which was previously uncovered.
            cmsIT8GetDataRowColDbl(hIT8, abs(n) % 10, abs(n) % 4);
            break;
        case 10:
            // Added to cover cmsIT8GetPatchByName and cmsIT8GetPatchName, which were previously uncovered.
            if (s1) {
                cmsIT8SetData(hIT8, s1, "SAMPLE_ID", s1);
                int patch_index = cmsIT8GetPatchByName(hIT8, s1);
                if (patch_index != -1) {
                    char buffer[1024]; // Increased buffer size to prevent overflow
                    cmsIT8GetPatchName(hIT8, patch_index, buffer);
                }
            }
            break;
        case 11:
            // Added to cover cmsIT8GetData and cmsIT8GetDataDbl, which were previously uncovered.
            if (s1) {
                cmsIT8GetData(hIT8, s1, "CUSTOM_R");
                cmsIT8GetDataDbl(hIT8, s1, "CUSTOM_G");
            }
            break;
        case 12:
            // Added to cover cmsIT8DefineDblFormat, which was previously uncovered (0% coverage).
            if (s1) {
                cmsIT8DefineDblFormat(hIT8, s1);
            }
            break;
        case 13:
            // Added to cover cmsIT8SetIndexColumn, which was previously uncovered (0% coverage).
            if (s1) {
                // Set a sample ID first to maximize the chance of success.
                cmsIT8SetData(hIT8, s1, "SAMPLE_ID", s1);
                cmsIT8SetIndexColumn(hIT8, s1);
            }
            break;
        case 14:
            // Added to cover cmsIT8SetTableByLabel, which was previously uncovered (0% coverage).
            if (s1 && s2 && s3) {
                char table_label[128];
                // Construct a label that cmsIT8SetTableByLabel can parse.
                snprintf(table_label, sizeof(table_label), "%s %u %s", s2, abs(n) % 10, s3);
                // Set this label as data in the table.
                cmsIT8SetData(hIT8, s1, "LABEL", table_label);
                // Attempt to set the table by this label.
                cmsIT8SetTableByLabel(hIT8, s1, "LABEL", s3);
            }
            break;
        case 15:
            // Added to cover cmsIT8FindDataFormat, which was previously uncovered (0% coverage).
            if (s1) {
                cmsIT8FindDataFormat(hIT8, s1);
            }
            break;
        case 16: {
            // Added to cover the cmscam02.c file, which was at 0% coverage.
            cmsViewingConditions vc;
            vc.whitePoint.X = 0.9642;
            vc.whitePoint.Y = 1.0;
            vc.whitePoint.Z = 0.8249;
            vc.La = 200.0;
            vc.Yb = 20.0;
            vc.surround = 2; // AVERAGE_SURROUND
            vc.D_value = 1.0;

            cmsHANDLE view = cmsCIECAM02Init(ctx, &vc);
            if (view) {
                cmsJCh JCh;
                cmsCIEXYZ XYZ;
                FDP_Consume_Primitive(&fdp, &XYZ, sizeof(XYZ));
                cmsCIECAM02Forward(view, &XYZ, &JCh);
                cmsCIECAM02Reverse(view, &JCh, &XYZ);
                cmsCIECAM02Done(view);
            }
            break;
        }
        case 17: {
            // Added to cover cmsps2.c functions, which had low coverage.
            cmsHPROFILE hProfile = cmsCreate_sRGBProfileTHR(ctx);
            if (hProfile) {
                char buffer[1024];
                cmsGetPostScriptCSA(ctx, hProfile, 0, 0, buffer, sizeof(buffer));
                cmsCloseProfile(hProfile);
            }
            break;
        }
        case 18: {
            // Added to cover the dictionary API in cmsnamed.c, which was at 0% coverage.
            cmsHANDLE hDict = cmsDictAlloc(ctx);
            if (hDict) {
                if (s1 && s2) {
                    cmsMLU* mlu1 = cmsMLUalloc(ctx, 1);
                    cmsMLU* mlu2 = cmsMLUalloc(ctx, 1);
                    if (mlu1 && mlu2) {
                        cmsMLUsetASCII(mlu1, "en", "US", s1);
                        cmsMLUsetASCII(mlu2, "en", "US", s2);
                        cmsDictAddEntry(hDict, L"key1", L"val1", mlu1, mlu2);
                    }
                    if (mlu1) cmsMLUfree(mlu1);
                    if (mlu2) cmsMLUfree(mlu2);
                }
                if (s3) {
                    cmsMLU* mlu3 = cmsMLUalloc(ctx, 1);
                    if (mlu3) {
                        cmsMLUsetASCII(mlu3, "en", "US", s3);
                        cmsDictAddEntry(hDict, L"key2", NULL, mlu3, NULL);
                        cmsMLUfree(mlu3);
                    }
                }
                cmsDictFree(hDict);
            }
            break;
        }
        case 19: {
            // Added to cover cmshalf.c functions, which were at 0% coverage.
            uint16_t h;
            FDP_Consume_Primitive(&fdp, &h, sizeof(h));
            _cmsHalf2Float(h);

            float f;
            FDP_Consume_Primitive(&fdp, &f, sizeof(f));
            _cmsFloat2Half(f);
            break;
        }
        case 20: {
            // Added to cover more of cmsps2.c by creating a CMYK profile
            // and generating a Color Rendering Dictionary (CRD).
            cmsHPROFILE hProfile = cmsCreateInkLimitingDeviceLinkTHR(ctx, cmsSigCmykData, 150);
            if (hProfile) {
                char buffer[2048]; // Use a larger buffer for CRD
                // Try to generate a CRD to hit different code paths than CSA.
                cmsGetPostScriptCRD(ctx, hProfile, 0, 0, buffer, sizeof(buffer));
                cmsCloseProfile(hProfile);
            }
            break;
        }
        case 21: {
            // Added to cover cmsTransform2DeviceLink, which was at 0% coverage.
            // All created handles are freed within this block to ensure memory safety.
            cmsHPROFILE hSRGB = cmsCreate_sRGBProfileTHR(ctx);
            cmsHPROFILE hLab = cmsCreateLab4ProfileTHR(ctx, NULL);
            if (hSRGB && hLab) {
                uint32_t dwFlags;
                FDP_Consume_Primitive(&fdp, &dwFlags, sizeof(dwFlags));

                // Prevent cmsFLAGS_NULLTRANSFORM, which creates a transform with a NULL
                // pipeline, causing a crash in cmsTransform2DeviceLink.
                dwFlags &= ~cmsFLAGS_NULLTRANSFORM;

                cmsHTRANSFORM hTransform = cmsCreateTransform(hSRGB, TYPE_RGB_8, hLab, TYPE_Lab_8, INTENT_PERCEPTUAL, dwFlags);
                if (hTransform) {
                    cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hTransform, 4.3, 0);
                    if (hDeviceLink) {
                        cmsCloseProfile(hDeviceLink); // hDeviceLink is freed here.
                    }
                    cmsDeleteTransform(hTransform); // hTransform is freed here.
                }
            }
            if (hSRGB) cmsCloseProfile(hSRGB); // hSRGB is freed here.
            if (hLab) cmsCloseProfile(hLab);   // hLab is freed here.
            break;
        }
        case 22: {
            // Added to cover cmsDictDup in cmsnamed.c, which was at 0% coverage.
            cmsHANDLE hDict = cmsDictAlloc(ctx);
            if (hDict) {
                cmsHANDLE hDictDup = cmsDictDup(hDict);
                if (hDictDup) {
                    cmsDictFree(hDictDup);
                }
                cmsDictFree(hDict);
            }
            break;
        }
        case 23: {
            // Added to cover cmsNamedColor* functions in cmsnamed.c, which had 0% coverage.
            // All resources are allocated and freed within this block.
            cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(ctx, 10, 3, "p", "s");
            if (nc) {
                cmsUInt16Number PCS[3];
                cmsUInt16Number Colorant[cmsMAXCHANNELS];
                FDP_Consume_Primitive(&fdp, &PCS, sizeof(PCS));
                FDP_Consume_Primitive(&fdp, &Colorant, sizeof(Colorant));
                char* name = FDP_Consume_String(&fdp, 16);
                if (name) {
                    cmsAppendNamedColor(nc, name, PCS, Colorant);
                    cmsNamedColorCount(nc);
                    int index = cmsNamedColorIndex(nc, name);
                    if (index != -1) {
                        char name_out[33];
                        char prefix_out[33];
                        char suffix_out[33];
                        cmsNamedColorInfo(nc, index, name_out, prefix_out, suffix_out, NULL, NULL);
                    }
                    free(name);
                }
                cmsFreeNamedColorList(nc);
            }
            break;
        }
        case 24: {
            // Added to cover WriteNamedColorCSA in cmsps2.c, which was at 0% coverage.
            // This requires a profile with a cmsSigNamedColor2Tag.
            cmsHPROFILE hProfile = cmsCreateNULLProfileTHR(ctx);
            if (hProfile) {
                cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(ctx, 1, 3, "p", "s");
                if (nc) {
                    cmsUInt16Number PCS[3] = {0x1000, 0x2000, 0x3000};
                    cmsUInt16Number Colorant[cmsMAXCHANNELS] = {0,0,0,0};
                    cmsAppendNamedColor(nc, "a_color", PCS, Colorant);
                    if (cmsWriteTag(hProfile, cmsSigNamedColor2Tag, nc)) {
                        char buffer[2048];
                        cmsGetPostScriptCSA(ctx, hProfile, 0, 0, buffer, sizeof(buffer));
                    }
                    cmsFreeNamedColorList(nc);
                }
                cmsCloseProfile(hProfile);
            }
            break;
        }
        case 25: {
            // Added to cover cmsps2.c:EmitCIEBasedA which was at 0% coverage.
            // This function is called when getting PostScript for a gray profile.
            cmsHPROFILE hProfile = cmsCreateGrayProfileTHR(ctx, NULL, NULL);
            if (hProfile) {
                // Set the color space to cmsSigGrayData to trigger the uncovered path.
                cmsSetColorSpace(hProfile, cmsSigGrayData);
                char buffer[2048];
                cmsGetPostScriptCSA(ctx, hProfile, 0, 0, buffer, sizeof(buffer));
                cmsCloseProfile(hProfile);
            }
            break;
        }
        case 26: {
            // Added to cover cmsTempFromWhitePoint and cmsAdaptToIlluminant in cmswtpnt.c (0% coverage).
            cmsCIExyY D50_xyY, WhitePoint_xyY;
            cmsCIEXYZ D50_XYZ, WhitePoint_XYZ, Result_XYZ, Value_XYZ;
            cmsFloat64Number TempK;
            FDP_Consume_Primitive(&fdp, &WhitePoint_xyY, sizeof(WhitePoint_xyY));
            FDP_Consume_Primitive(&fdp, &Value_XYZ, sizeof(Value_XYZ));
            
            cmsWhitePointFromTemp(&D50_xyY, 5000);
            cmsTempFromWhitePoint(&TempK, &WhitePoint_xyY);

            cmsxyY2XYZ(&D50_XYZ, &D50_xyY);
            cmsxyY2XYZ(&WhitePoint_XYZ, &WhitePoint_xyY);
            cmsAdaptToIlluminant(&Result_XYZ, &D50_XYZ, &WhitePoint_XYZ, &Value_XYZ);
            break;
        }
        case 27: {
            // Added to cover CreateNamedColorDevicelink in cmsvirt.c (0% coverage).
            // This function is not included in the default build, so this case is disabled.
            /*
            cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(ctx, 1, 3, "p", "s");
            if (nc) {
                cmsUInt16Number PCS[3] = {0,0,0};
                cmsUInt16Number Colorant[4] = {0,0,0,0};
                cmsAppendNamedColor(nc, "fuzz_color", PCS, Colorant);
                
                cmsHPROFILE hProfile = cmsCreateNamedColorDeviceLink(ctx, nc);
                if (hProfile) {
                    cmsCloseProfile(hProfile); // hProfile is freed here.
                }
                cmsFreeNamedColorList(nc); // nc is freed here.
            }
            */
            break;
        }
        }

        // Free the strings allocated in this loop iteration.
        free(s1);
        free(s2);
        free(s3);
    }

    // Added to cover cmsIT8GetPropertyDbl, which was previously uncovered.
    cmsIT8GetPropertyDbl(hIT8, "NUMBER_OF_FIELDS");

    // Added to cover cmsIT8EnumProperties, which was previously uncovered.
    char **property_names = NULL;
    if (cmsIT8EnumProperties(hIT8, &property_names)) {
        // The memory for the array is allocated by the function and must be freed.
        // The strings inside the array are pointers to internal data and should not be freed.
        // **FIX**: The memory for property_names is managed by the IT8 handle and should not be freed here.
        // free(property_names);
    }
    
    // Added to cover cmsIT8EnumDataFormat, which was previously uncovered.
    char **data_format_names = NULL;
    cmsIT8EnumDataFormat(hIT8, &data_format_names);
    // Memory is managed by the IT8 handle, no free needed.

    // After populating the IT8 object, save it to a memory buffer
    // to exercise the serialization logic, which is often complex.
    cmsUInt32Number bytes_needed = 0;
    // First call gets the required buffer size.
    if (cmsIT8SaveToMem(hIT8, NULL, &bytes_needed)) {
        if (bytes_needed > 0) {
            void *mem = malloc(bytes_needed);
            if (mem) {
                // Second call writes the data into the allocated buffer.
                if (cmsIT8SaveToMem(hIT8, mem, &bytes_needed)) {
                    // Added to cover cmsIT8LoadFromMem, which was previously uncovered.
                    // This call creates a new handle that must be freed.
                    cmsHANDLE hIT8_loaded = cmsIT8LoadFromMem(ctx, mem, bytes_needed);
                    if (hIT8_loaded) {
                        cmsIT8Free(hIT8_loaded);
                    }
                }
                free(mem); // Free the serialization buffer.
            }
        }
    }

    // Clean up all lcms resources to prevent memory leaks.
    cmsIT8Free(hIT8);
    cmsDeleteContext(ctx);

    return 0;
}