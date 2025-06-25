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
    if (offset + sizeof(cmsUInt32Number) * 5 <= Size) { // 5 * sizeof(cmsUInt32Number) for nProfiles, InputFormat, OutputFormat, Intent, dwFlags
        // Generate nProfiles that can be 0, 1, 255, or 256 to cover boundary conditions.
        cmsUInt32Number nProfiles = CONSUME_UINT32() % (MAX_PROFILES + 2);
        cmsUInt32Number InputFormat = CONSUME_UINT32();
        cmsUInt32Number OutputFormat = CONSUME_UINT32();
        cmsUInt32Number Intent = CONSUME_UINT32();
        cmsUInt32Number dwFlags = CONSUME_UINT32();

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
                hTransform = cmsCreateMultiprofileTransform(hProfiles_array, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);
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
            cmsCreateMultiprofileTransform(NULL, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);
        }
    }

    // 3. Fuzz cmsOpenProfileFromStream: Tests opening profiles from a file stream.
    // We create a temporary file, write fuzzer input to it, and then attempt to open it.
    int fd = mkstemp(temp_filename_buffer); // Create a unique temporary file
    if (fd != -1) {
        fp = fdopen(fd, "wb"); // Open the file descriptor as a FILE* in binary write mode
        if (fp) {
            // Write the remaining fuzzer data to the temporary file.
            fwrite(Data + offset, 1, Size - offset, fp);
            fclose(fp); // Close the write stream
            fp = NULL; // Reset fp to NULL as it's closed

            fp = fopen(temp_filename_buffer, "rb"); // Re-open the file in binary read mode
            if (fp) {
                // Call the target function to open the profile from the stream.
                cmsHPROFILE opened_profile = cmsOpenProfileFromStream(fp, "r");
                if (opened_profile) {
                    // If profile was opened successfully, cmsOpenProfileFromStream took ownership of fp.
                    // cmsCloseProfile will close fp.
                    cmsCloseProfile(opened_profile);
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

    // Cleanup: Ensure all allocated lcms resources are properly freed.
    // The order of cleanup is important: close profiles/transforms before deleting the context.
    cmsCloseProfile(hProfile);
    cmsDeleteContext(Context);

    return 0;
}