// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>    // For file operations (fopen, fclose, fwrite, remove)
#include <string.h>   // For memcpy
#include <stdlib.h>   // For mkstemp, malloc, free
#include <unistd.h>   // For close (for mkstemp)

// Include lcms headers
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h" // Required for cmsGBD and other internal types if used directly

// Define a simple error handler to prevent crashes from lcms errors.
// This is crucial for fuzzing, as malformed inputs can trigger error callbacks
// that might otherwise terminate the fuzzer.
void FuzzerErrorHandler(cmsContext ContextID, cmsUInt32Number ErrorCode, const char *Text) {
    (void)ContextID;   // Unused parameter
    (void)ErrorCode;   // Unused parameter
    (void)Text;        // Unused parameter
    // Do nothing, or log to stderr if debugging is needed.
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    cmsContext ContextID = NULL;
    cmsHPROFILE hProfile1 = NULL;
    cmsHPROFILE hProfile2 = NULL; // Added for new profile operations
    cmsIOHANDLER* ioHandler = NULL;
    cmsHANDLE hIT8 = NULL;
    cmsToneCurve* curve1 = NULL;
    cmsToneCurve* curve2 = NULL;
    cmsToneCurve* joinedCurve = NULL;
    cmsHANDLE hGBD = NULL; // Changed cmsGBD to cmsHANDLE as per cmsGBDAlloc signature

    // Create a lcms context. This is required for most lcms API calls.
    // Set a custom error handler to prevent lcms from exiting on errors.
    ContextID = cmsCreateContext(NULL, NULL);
    if (!ContextID) {
        return 0; // Failed to create context, nothing more to do.
    }
    cmsSetLogErrorHandlerTHR(ContextID, FuzzerErrorHandler);

    // Use a mutable offset to consume parts of the fuzzer input data for different API calls.
    size_t current_offset = 0;

    // 1. Test cmsCreateNULLProfileTHR
    // This function creates a basic "NULL" profile. It takes only a context.
    hProfile1 = cmsCreateNULLProfileTHR(ContextID);
    if (hProfile1) {
        // If profile creation was successful, close it to free resources.
        cmsCloseProfile(hProfile1);
        hProfile1 = NULL; // Reset handle for subsequent uses.
    }

    // 2. Test cmsCreateInkLimitingDeviceLinkTHR
    // This function creates a device link profile with ink limiting.
    // It requires a color space signature (cmsUInt32Number) and an ink limit (cmsFloat64Number).
    // Ensure enough data is available for both parameters.
    if (Size - current_offset >= sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number)) {
        cmsColorSpaceSignature colorSpace;
        cmsFloat64Number inkLimit;

        // Read colorSpace from fuzzer data.
        memcpy(&colorSpace, Data + current_offset, sizeof(cmsUInt32Number));
        current_offset += sizeof(cmsUInt32Number);

        // Read inkLimit from fuzzer data.
        memcpy(&inkLimit, Data + current_offset, sizeof(cmsFloat64Number));
        current_offset += sizeof(cmsFloat64Number);

        hProfile1 = cmsCreateInkLimitingDeviceLinkTHR(ContextID, colorSpace, inkLimit);
        if (hProfile1) {
            // If profile creation was successful, close it to free resources.
            cmsCloseProfile(hProfile1);
            hProfile1 = NULL;
        }
    }

    // --- NEW: Enhance coverage for cmsOpenProfileFromIOhandlerTHR and cmsmd5.c ---
    // The original fuzzer input often leads to cmsOpenProfileFromIOhandlerTHR failing
    // because the raw fuzzer data does not form a valid ICC header.
    // This section creates a valid (null) profile, saves it to memory, and then attempts
    // to open it from that memory buffer. This should hit the success path of
    // cmsOpenProfileFromIOhandlerTHR and also cover cmsSaveProfileToMem and MD5 calculation functions.
    cmsUInt8Number* savedProfileBuffer = NULL;
    cmsUInt32Number savedProfileBufferSize = 0;

    hProfile2 = cmsCreateNULLProfileTHR(ContextID); // Create a valid profile to save
    if (hProfile2) {
        // First call to get the required buffer size for saving the profile
        cmsSaveProfileToMem(hProfile2, NULL, &savedProfileBufferSize);

        if (savedProfileBufferSize > 0) {
            // Allocate a buffer to store the saved profile
            savedProfileBuffer = (cmsUInt8Number*)malloc(savedProfileBufferSize);
            if (savedProfileBuffer) {
                // Save the profile to the allocated memory buffer
                if (cmsSaveProfileToMem(hProfile2, savedProfileBuffer, &savedProfileBufferSize)) {
                    // Now, try to open this valid profile from the memory buffer
                    ioHandler = cmsOpenIOhandlerFromMem(ContextID, savedProfileBuffer, savedProfileBufferSize, "r");
                    if (ioHandler) {
                        cmsHPROFILE openedProfile = cmsOpenProfileFromIOhandlerTHR(ContextID, ioHandler);
                        if (openedProfile) {
                            cmsCloseProfile(openedProfile); // Close the newly opened profile
                        }
                        // ioHandler is freed by cmsCloseProfile (or internally by cmsOpenProfileFromIOhandlerTHR on failure)
                        ioHandler = NULL;
                    }
                }
                free(savedProfileBuffer); // Free the allocated buffer
                savedProfileBuffer = NULL;
            }
        }
        cmsCloseProfile(hProfile2); // Close the original profile used for saving
        hProfile2 = NULL;
    }

    // 3. Test cmsOpenProfileFromIOhandlerTHR (original section)
    // This section remains useful for testing with arbitrary fuzzer data, which might
    // still trigger various error paths in profile parsing.
    if (Size > current_offset) {
        ioHandler = cmsOpenIOhandlerFromMem(ContextID, (void*)(Data + current_offset), Size - current_offset, "r");
        if (ioHandler) {
            hProfile1 = cmsOpenProfileFromIOhandlerTHR(ContextID, ioHandler);
            if (hProfile1) {
                // If profile was opened successfully, close it.
                // cmsCloseProfile will also close the associated ioHandler.
                cmsCloseProfile(hProfile1);
                hProfile1 = NULL;
            }
            // IMPORTANT: If cmsOpenProfileFromIOhandlerTHR fails (returns NULL),
            // it internally calls cmsCloseProfile on the placeholder profile,
            // which in turn frees the ioHandler that was assigned to it.
            // Therefore, we do NOT need to call cmsCloseIOhandler here,
            // as the ioHandler is always freed by lcms, either on success
            // (via cmsCloseProfile(hProfile1)) or on failure (via
            // cmsOpenProfileFromIOhandlerTHR's internal cleanup).
            ioHandler = NULL; // Reset ioHandler to NULL to prevent dangling pointer use.
        }
    }

    // 4. Test cmsIT8LoadFromFile
    // This function loads an IT8 file. Since fuzzers typically operate on in-memory data,
    // we write the fuzzer input to a temporary file and then pass its path to the API.
    // This pattern is necessary for APIs that strictly take file paths.
    char filename[] = "/tmp/fuzz_it8_XXXXXX";
    int fd = mkstemp(filename); // Create a unique temporary file.
    if (fd != -1) {
        FILE *f = fdopen(fd, "wb"); // Open the file descriptor as a FILE stream.
        if (f) {
            fwrite(Data, 1, Size, f); // Write the entire fuzzer input to the file.
            fclose(f); // Close the file stream.

            hIT8 = cmsIT8LoadFromFile(ContextID, filename);
            if (hIT8) {
                // If IT8 data was loaded successfully, free the handle.
                cmsIT8Free(hIT8);
                hIT8 = NULL;
            }
        } else {
            close(fd); // If fdopen failed, ensure the file descriptor is closed.
        }
        remove(filename); // Clean up the temporary file from the filesystem.
    }

    // 5. Test cmsJoinToneCurve
    // This function joins two tone curves.
    // It requires two cmsToneCurve* objects and a cmsUInt32Number for the number of points.
    // We'll create two simple tabulated tone curves for this test.
    // cmsBuildTabulatedToneCurve16 requires at least 2 entries.
    cmsUInt32Number nPoints = 2; // Fixed number of points for simplicity and to ensure minimum requirement.
    size_t required_data_for_curves = 2 * nPoints * sizeof(cmsUInt16Number); // Data needed for two tables.

    if (Size - current_offset >= required_data_for_curves) {
        cmsUInt16Number table1[2]; // Table for the first tone curve.
        cmsUInt16Number table2[2]; // Table for the second tone curve.

        // Copy data for table1 from fuzzer input.
        memcpy(table1, Data + current_offset, nPoints * sizeof(cmsUInt16Number));
        current_offset += nPoints * sizeof(cmsUInt16Number);

        // Copy data for table2 from fuzzer input.
        memcpy(table2, Data + current_offset, nPoints * sizeof(cmsUInt16Number));
        current_offset += nPoints * sizeof(cmsUInt16Number);

        // Build the two tone curves.
        curve1 = cmsBuildTabulatedToneCurve16(ContextID, nPoints, table1);
        curve2 = cmsBuildTabulatedToneCurve16(ContextID, nPoints, table2);

        if (curve1 && curve2) {
            // If both curves were successfully built, attempt to join them.
            joinedCurve = cmsJoinToneCurve(ContextID, curve1, curve2, nPoints);
            if (joinedCurve) {
                // If joining was successful, free the resulting joined curve.
                cmsFreeToneCurve(joinedCurve);
                joinedCurve = NULL;
            }
        }

        // Always free the individual curves, if they were successfully created.
        if (curve1) {
            cmsFreeToneCurve(curve1);
            curve1 = NULL;
        }
        if (curve2) {
            cmsFreeToneCurve(curve2);
            curve2 = NULL;
        }
    }

    // --- NEW: Test cmsGBDAlloc and cmsGBDFree ---
    // This addresses 0% coverage for functions in cmssm.c related to Gamut Boundary Description.
    // Corrected cmsGBDAlloc to take only cmsContextID as per its signature.
    hGBD = cmsGBDAlloc(ContextID);
    if (hGBD) {
        // For deeper coverage, one would add calls to cmsGDBAddPoint, cmsGDBCheckPoint, cmsGDBCompute.
        // For now, just covering allocation and deallocation.
        cmsGBDFree(hGBD); // Free the allocated GBD object
        hGBD = NULL;
    }

// Cleanup label: Ensures all allocated resources are freed before exiting.
cleanup:
    // Clean up the lcms context. This frees all resources associated with it.
    if (ContextID) {
        cmsDeleteContext(ContextID);
        ContextID = NULL;
    }

    return 0;
}