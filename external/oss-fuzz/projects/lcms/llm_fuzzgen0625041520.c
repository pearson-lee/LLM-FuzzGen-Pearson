#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For unlink and mkstemp

// lcms public headers
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// Define a maximum number of profiles for cmsCreateMultiprofileTransform
#define MAX_PROFILES 256

// Fuzz target for lcms library
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    cmsContext Context = NULL;
    cmsHPROFILE hProfile = NULL;
    cmsHTRANSFORM hTransform = NULL;
    FILE *fp = NULL;
    // Use a buffer for the temporary filename to avoid issues with string literals
    char temp_filename_buffer[] = "/tmp/fuzz_profile_XXXXXX";

    // Create a new context for each fuzz run to isolate state
    Context = cmsCreateContext(NULL, NULL);
    if (!Context) {
        // If context creation fails, there's nothing more we can do.
        return 0;
    }

    // Simple FuzzedDataProvider-like approach for C
    // This allows consuming bytes from the fuzzer input in a structured way.
    size_t offset = 0;

    // Helper macro to safely consume bytes from the fuzzer input.
    // It checks for out-of-bounds access and updates the offset.
    // The macro uses a comma expression to ensure it's a single expression
    // that returns the consumed value and updates the offset.
    #define CONSUME_BYTES(type, num_bytes) \
        ( (offset + num_bytes <= Size) ? \
          ( (offset += num_bytes), (*(type *)(Data + offset - num_bytes)) ) : \
          ( (offset = Size), (type)0 ) )

    // Specific macros for common types
    #define CONSUME_UINT32() CONSUME_BYTES(cmsUInt32Number, sizeof(cmsUInt32Number))
    #define CONSUME_BOOL() CONSUME_BYTES(cmsBool, sizeof(cmsBool))
    #define CONSUME_FLOAT64() CONSUME_BYTES(cmsFloat64Number, sizeof(cmsFloat64Number))
    #define CONSUME_UCHAR() CONSUME_BYTES(unsigned char, sizeof(unsigned char))

    // 1. Fuzz cmsDupContext: Tests context duplication.
    cmsContext DupContext = cmsDupContext(Context, NULL);
    if (DupContext) {
        // Ensure the duplicated context is properly deleted to prevent leaks.
        cmsDeleteContext(DupContext);
    }

    // Create a basic sRGB profile. This profile will be used as input for other functions
    // that require a valid cmsHPROFILE.
    hProfile = cmsCreate_sRGBProfileTHR(Context);
    if (!hProfile) {
        // If profile creation fails, clean up the context and exit.
        cmsDeleteContext(Context);
        return 0;
    }

    // 2. Fuzz cmsCreateMultiprofileTransform: Tests creation of transforms from multiple profiles.
    // This function has branches related to the number of profiles (nProfiles <= 0 || nProfiles > 255).
    // We generate nProfiles to specifically hit these boundary conditions.
    // Ensure enough data is available for all parameters before consuming.
    cmsUInt32Number multi_InputFormat = 0, multi_OutputFormat = 0, multi_Intent = 0, multi_dwFlags = 0;
    if (offset + sizeof(cmsUInt32Number) * 5 <= Size) { // 5 * sizeof(cmsUInt32Number) for nProfiles, InputFormat, OutputFormat, Intent, dwFlags
        // Generate nProfiles that can be 0, 1, 255, or 256 to cover boundary conditions.
        cmsUInt32Number nProfiles = CONSUME_UINT32() % (MAX_PROFILES + 2);
        multi_InputFormat = CONSUME_UINT32();
        multi_OutputFormat = CONSUME_UINT32();
        multi_Intent = CONSUME_UINT32();
        multi_dwFlags = CONSUME_UINT32();

        cmsHPROFILE* hProfiles_array = NULL;
        if (nProfiles > 0 && nProfiles <= MAX_PROFILES) {
            // Allocate an array of profile handles.
            hProfiles_array = (cmsHPROFILE*) calloc(nProfiles, sizeof(cmsHPROFILE));
            if (hProfiles_array) {
                // Populate the array with the previously created sRGB profile for simplicity.
                for (cmsUInt32Number i = 0; i < nProfiles; ++i) {
                    hProfiles_array[i] = hProfile;
                }
                // Call the target function.
                hTransform = cmsCreateMultiprofileTransform(hProfiles_array, nProfiles, multi_InputFormat, multi_OutputFormat, multi_Intent, multi_dwFlags);
                if (hTransform) {
                    // Delete the created transform to prevent memory leaks.
                    cmsDeleteTransform(hTransform);
                    hTransform = NULL;
                }
                // Free the allocated array of profile handles.
                free(hProfiles_array);
            }
        } else {
            // This path specifically targets the error handling branch (nProfiles <= 0 or nProfiles > 255).
            // The function is expected to return NULL and signal an error.
            cmsCreateMultiprofileTransform(NULL, nProfiles, multi_InputFormat, multi_OutputFormat, multi_Intent, multi_dwFlags);
        }
    }

    // 3. Fuzz cmsOpenProfileFromStream: Tests opening profiles from a file stream.
    // We create a temporary file, write fuzzer input to it, and then attempt to open it.
    int fd = mkstemp(temp_filename_buffer); // Create a unique temporary file
    if (fd != -1) {
        fp = fdopen(fd, "wb"); // Open the file descriptor as a FILE* in binary write mode
        if (fp) {
            // Write the previously created sRGB profile to the temporary file
            // to ensure cmsOpenProfileFromStream can open a valid profile.
            // This addresses the uncovered 'true' branch at line 119 in the fuzz target coverage report.
            cmsSaveProfileToStream(hProfile, fp);
            // cmsSaveProfileToStream takes ownership of the FILE* and closes it internally.
            // Therefore, we must set fp to NULL to prevent a double-free.
            fp = NULL;

            fp = fopen(temp_filename_buffer, "rb"); // Re-open the file in binary read mode
            if (fp) {
                // Call the target function to open the profile from the stream.
                cmsHPROFILE opened_profile = cmsOpenProfileFromStream(fp, "r");
                if (opened_profile) {
                    // If profile was opened successfully, cmsOpenProfileFromStream took ownership of fp.
                    // cmsCloseProfile will close fp.
                    cmsCloseProfile(opened_profile);
                    opened_profile = NULL; // Set to NULL after closing
                    fp = NULL; // Set fp to NULL as it's now closed by cmsCloseProfile
                } else {
                    // If cmsOpenProfileFromStream returns NULL, it means an error occurred.
                    // The internal error handling of cmsOpenProfileFromStreamTHR (which cmsOpenProfileFromStream calls)
                    // will call cmsCloseProfile(hEmpty), which in turn closes the FILE* if an IOhandler was created.
                    // Therefore, we should NOT call fclose(fp) here to avoid a double-free.
                    fp = NULL; // Set fp to NULL to prevent accidental use of a potentially closed pointer.
                }
            }
        }
        unlink(temp_filename_buffer); // Delete the temporary file from the filesystem.
    }

    // 4. Fuzz cmsGetPostScriptCSA: Tests generation of PostScript Color Space Array.
    // This function requires a profile and a buffer for output.
    // Ensure enough data is available for all parameters before consuming.
    if (offset + sizeof(cmsUInt32Number) * 3 <= Size) { // 3 * sizeof(cmsUInt32Number) for dwFlags_csa, dwColorSpace_csa, dwBufferLen_csa
        cmsUInt32Number dwFlags_csa = CONSUME_UINT32();
        cmsUInt32Number dwColorSpace_csa = CONSUME_UINT32();
        // Limit buffer size to prevent excessive memory allocations.
        cmsUInt32Number dwBufferLen_csa = CONSUME_UINT32() % 1024;

        void* Buffer_csa = NULL;
        if (dwBufferLen_csa > 0) {
            Buffer_csa = malloc(dwBufferLen_csa); // Allocate buffer for output
            if (Buffer_csa) {
                // Call the target function.
                cmsGetPostScriptCSA(Context, hProfile, dwFlags_csa, dwColorSpace_csa, Buffer_csa, dwBufferLen_csa);
                free(Buffer_csa); // Free the allocated buffer.
            }
        } else {
            // Test with NULL buffer and zero length to cover error paths or edge cases.
            cmsGetPostScriptCSA(Context, hProfile, dwFlags_csa, dwColorSpace_csa, NULL, 0);
        }
    }

    // 5. Fuzz cmsDetectTAC: Tests detection of Total Area Coverage (TAC) from a profile.
    // This function takes a profile handle as input.
    cmsFloat64Number tac = cmsDetectTAC(hProfile);
    (void)tac; // Suppress unused variable warning, as the return value is not used further.

    // 6. Fuzz cmsIT8 functions: Tests IT8 data handling.
    // This section aims to improve coverage for functions in cmscgats.c, many of which are at 0%.
    cmsHANDLE hIT8 = cmsIT8Alloc(Context);
    if (hIT8) {
        char tableName[32];
        char propertyName[32];
        char stringValue[100];

        // Consume data for table name (up to 31 chars + null terminator)
        size_t bytes_to_copy = sizeof(tableName) - 1;
        size_t actual_bytes_to_copy = (offset + bytes_to_copy <= Size) ? bytes_to_copy : (Size - offset);
        memcpy(tableName, Data + offset, actual_bytes_to_copy);
        tableName[actual_bytes_to_copy] = '\0';
        offset += actual_bytes_to_copy;

        // Consume data for property name (up to 31 chars + null terminator)
        bytes_to_copy = sizeof(propertyName) - 1;
        actual_bytes_to_copy = (offset + bytes_to_copy <= Size) ? bytes_to_copy : (Size - offset);
        memcpy(propertyName, Data + offset, actual_bytes_to_copy);
        propertyName[actual_bytes_to_copy] = '\0';
        offset += actual_bytes_to_copy;

        // Consume data for string value (up to 99 chars + null terminator)
        bytes_to_copy = sizeof(stringValue) - 1;
        actual_bytes_to_copy = (offset + bytes_to_copy <= Size) ? bytes_to_copy : (Size - offset);
        memcpy(stringValue, Data + offset, actual_bytes_to_copy);
        stringValue[actual_bytes_to_copy] = '\0';
        offset += actual_bytes_to_copy;

        // Removed incorrect call to cmsIT8SetTable.
        // The original code was trying to pass string arguments to a function expecting a table index.
        cmsIT8SetPropertyStr(hIT8, propertyName, stringValue);

        // Ensure enough data for the following CONSUME_FLOAT64 and CONSUME_UINT32
        if (offset + sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number) <= Size) {
            cmsIT8SetPropertyDbl(hIT8, propertyName, CONSUME_FLOAT64());
            cmsIT8SetPropertyHex(hIT8, propertyName, CONSUME_UINT32());
        }
        cmsIT8SetSheetType(hIT8, stringValue); // This one uses a string already consumed

        // Fuzz cmsIT8SaveToFile and cmsIT8LoadFromFile
        // This targets file I/O related IT8 functions.
        char it8_temp_filename_buffer[] = "/tmp/fuzz_it8_XXXXXX";
        int it8_fd = mkstemp(it8_temp_filename_buffer);
        if (it8_fd != -1) {
            FILE *it8_fp = fdopen(it8_fd, "wb");
            if (it8_fp) {
                cmsIT8SaveToFile(hIT8, it8_fp);
                fclose(it8_fp);
                it8_fp = NULL;

                it8_fp = fopen(it8_temp_filename_buffer, "rb");
                if (it8_fp) {
                    cmsHANDLE loaded_it8 = cmsIT8LoadFromFile(Context, it8_fp);
                    if (loaded_it8) {
                        cmsIT8Free(loaded_it8); // Free the loaded IT8 object
                    }
                    fclose(it8_fp); // Close the file handle
                    it8_fp = NULL;
                }
            }
            unlink(it8_temp_filename_buffer); // Delete the temporary file
        }

        cmsIT8Free(hIT8); // Free the allocated IT8 object
    }

    // 7. Fuzz cmsGBD functions: Tests Gamut Boundary Description.
    // This section targets functions in cmssm.c, which are almost entirely uncovered.
    cmsHANDLE hGBD = cmsGBDAlloc(Context);
    if (hGBD) {
        // Fuzz cmsGDBAddPoint
        // Add a few points to cover the internal logic of adding points.
        cmsUInt32Number num_points = CONSUME_UCHAR() % 5; // Add up to 4 points
        for (cmsUInt32Number i = 0; i < num_points; ++i) {
            if (offset + sizeof(cmsFloat64Number) * 3 <= Size) {
                cmsCIELab Lab; // Declare a cmsCIELab structure
                Lab.L = CONSUME_FLOAT64();
                Lab.a = CONSUME_FLOAT64();
                Lab.b = CONSUME_FLOAT64();
                cmsGDBAddPoint(hGBD, &Lab); // Pass the address of the cmsCIELab structure
            } else {
                break;
            }
        }

        // Fuzz cmsGDBCompute
        // This call targets the main computation function for GBD.
        if (offset + sizeof(cmsUInt32Number) <= Size) {
            cmsGDBCompute(hGBD, CONSUME_UINT32()); // Pass a fuzzed dwFlags
        }

        cmsGBDFree(hGBD); // Free the allocated GBD object
    }

    // 8. Fuzz cmsCreateTransformTHR and cmsDoTransform:
    // This aims to hit various pixel formatters and transformation paths in cmspack.c and cmsxform.c.
    // Reusing multi_Intent from earlier consumption.
    if (offset + sizeof(cmsUInt32Number) * 3 <= Size) { // Need enough data for input/output formats and flags
        cmsUInt32Number inputFormat_simple = CONSUME_UINT32();
        cmsUInt32Number outputFormat_simple = CONSUME_UINT32();
        cmsUInt32Number transformFlags_simple = CONSUME_UINT32();

        cmsHTRANSFORM simpleTransform = cmsCreateTransformTHR(Context, hProfile, inputFormat_simple, hProfile, outputFormat_simple, multi_Intent, transformFlags_simple);
        if (simpleTransform) {
            // Allocate small buffers to avoid excessive memory usage.
            // These sizes are arbitrary but aim to be large enough for a few pixels.
            size_t input_buffer_size = 128;
            size_t output_buffer_size = 128;
            void* input_buffer = malloc(input_buffer_size);
            void* output_buffer = malloc(output_buffer_size);

            if (input_buffer && output_buffer) {
                // Fill input buffer with some fuzzer data.
                size_t data_to_copy = Size - offset > input_buffer_size ? input_buffer_size : Size - offset;
                memcpy(input_buffer, Data + offset, data_to_copy);
                offset += data_to_copy;

                // Perform a transform for a small number of pixels.
                // This will exercise the internal formatter functions.
                cmsDoTransform(simpleTransform, input_buffer, output_buffer, 1);
            }

            free(input_buffer); // Free input buffer
            free(output_buffer); // Free output buffer
            cmsDeleteTransform(simpleTransform); // Delete the transform
        }
    }

    // Cleanup: Ensure all allocated lcms resources are properly freed.
    // The order of cleanup is important: close profiles/transforms before deleting the context.
    cmsCloseProfile(hProfile);
    cmsDeleteContext(Context);

    return 0;
}