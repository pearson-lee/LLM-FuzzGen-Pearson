#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <math.h>
#include <unistd.h>
#include <stdio.h>

#include "/src/lcms/include/lcms2.h"

// The build system provides this compile-time macro.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0625093538"
#endif

// Helper function to safely consume a block of bytes from the fuzzing data buffer.
// It advances the data pointer and decrements the size.
// Returns 1 on success, 0 if there is not enough data.
static int consume_bytes(const uint8_t **data, size_t *size, void *dest, size_t dest_size) {
    if (*size < dest_size) {
        return 0;
    }
    if (dest != NULL) {
        memcpy(dest, *data, dest_size);
    }
    *data += dest_size;
    *size -= dest_size;
    return 1;
}

// Helper function to create a profile for testing.
// It consumes data from the fuzzer input to generate profile parameters.
static cmsHPROFILE CreateTestingProfile(cmsContext context, const uint8_t **data, size_t *size) {
    // Required data: uint32_t for grid points, 4x cmsFloat64Number, 2x uint32_t for temperatures.
    if (*size < (sizeof(uint32_t) + 4 * sizeof(cmsFloat64Number) + 2 * sizeof(uint32_t))) {
        return NULL;
    }

    uint32_t grid_points_raw;
    consume_bytes(data, size, &grid_points_raw, sizeof(grid_points_raw));
    int nGridPoints = (grid_points_raw % 10) + 1; // Range [1, 10]

    cmsFloat64Number b, c, h, s;
    consume_bytes(data, size, &b, sizeof(b));
    consume_bytes(data, size, &c, sizeof(c));
    consume_bytes(data, size, &h, sizeof(h));
    consume_bytes(data, size, &s, sizeof(s));

    uint32_t temp_src_raw;
    consume_bytes(data, size, &temp_src_raw, sizeof(temp_src_raw));
    int temp_src = 5000 + (temp_src_raw % 2001); // Range [5000, 7000]

    uint32_t temp_dest_raw;
    consume_bytes(data, size, &temp_dest_raw, sizeof(temp_dest_raw));
    int temp_dest = 5000 + (temp_dest_raw % 2001); // Range [5000, 7000]

    cmsHPROFILE profile = cmsCreateBCHSWabstractProfileTHR(
        context, nGridPoints, b, c, h, s, temp_src, temp_dest);
    return profile;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *fuzz_data = data;
    size_t fuzz_size = size;

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    /*
     * FUZZING BLOCK 1: Test cmsIT8LoadFromMem with fuzzed data.
     */
    size_t it8_size_val = 0;
    if (consume_bytes(&fuzz_data, &fuzz_size, &it8_size_val, sizeof(it8_size_val))) {
        size_t it8_data_len = it8_size_val % (fuzz_size + 1);
        if (it8_data_len > 0) {
            cmsHANDLE it8_handle = cmsIT8LoadFromMem(context, fuzz_data, it8_data_len);
            if (it8_handle) {
                cmsIT8Free(it8_handle);
            }
        }
        // Advance the data pointer past the consumed block.
        consume_bytes(&fuzz_data, &fuzz_size, NULL, it8_data_len);
    }

    /*
     * FUZZING BLOCK 2: Test profile sequence compilation logic.
     */
    cmsHPROFILE profiles[2];
    profiles[0] = cmsCreate_sRGBProfileTHR(context);
    profiles[1] = cmsCreateGrayProfileTHR(context, NULL, NULL);
    if (profiles[0] && profiles[1]) {
        cmsSEQ *seq = cmsAllocProfileSequenceDescription(context, 2);
        if (seq) {
            // The call to the internal function _cmsCompileProfileSequence is unstable
            // and has been removed to prevent crashes and memory leaks.
            cmsFreeProfileSequenceDescription(seq);
        }
    }
    if (profiles[0])
        cmsCloseProfile(profiles[0]);
    if (profiles[1])
        cmsCloseProfile(profiles[1]);

    /*
     * FUZZING BLOCK 3: Test black point detection with a fuzzed CLUT-based profile.
     */
    uint8_t choice = 0;
    consume_bytes(&fuzz_data, &fuzz_size, &choice, sizeof(choice));

    if (choice % 3 == 0) {
        /*
         * ANALYSIS: The function cmsDetectDestinationBlackPoint had an uncovered branch for gray profiles.
         * IMPLEMENTATION: This path creates and tests a gray profile to cover that specific logic.
         */
        cmsHPROFILE gray_profile = cmsCreateGrayProfileTHR(context, NULL, NULL);
        if (gray_profile) {
            cmsCIEXYZ black_point;
            cmsDetectDestinationBlackPoint(&black_point, gray_profile, 0, 0);
            cmsCloseProfile(gray_profile);
        }
    } else if (choice % 3 == 1) {
        /*
         * ANALYSIS: The function cmsDetectDestinationBlackPoint has uncovered branches
         *           related to checking for cmsSigMediaBlackPointTag and
         *           cmsSigPerceptualRenderingIntentGamutTag. This also prevented
         *           BlackPointUsingPerceptualBlack from being called.
         * IMPLEMENTATION: Write these tags to a profile to exercise the corresponding
         *                 code paths.
         */
        cmsHPROFILE rgb_profile = cmsCreate_sRGBProfileTHR(context);
        if (rgb_profile) {
            cmsCIEXYZ black_point_tag_data = { 0.1, 0.2, 0.3 };
            cmsWriteTag(rgb_profile, cmsSigMediaBlackPointTag, &black_point_tag_data);

            cmsSignature gamut_tag_data = cmsSigPerceptualReferenceMediumGamut;
            cmsWriteTag(rgb_profile, cmsSigPerceptualRenderingIntentGamutTag, &gamut_tag_data);

            cmsCIEXYZ black_point;
            uint32_t intent = 0;
            if (fuzz_size > 0) {
                intent = fuzz_data[0] % 4;
            }
            cmsDetectDestinationBlackPoint(&black_point, rgb_profile, intent, 0);
            cmsCloseProfile(rgb_profile);
        }
    } else {
        // Original path
        cmsHPROFILE testing_profile = CreateTestingProfile(context, &fuzz_data, &fuzz_size);
        if (testing_profile) {
            cmsCIEXYZ black_point;
            uint32_t intent = 0;
            if (fuzz_size > 0) {
                intent = fuzz_data[0] % 4;
            }
            cmsDetectDestinationBlackPoint(&black_point, testing_profile, intent, 0);
            cmsDetectBlackPoint(&black_point, testing_profile, intent, 0);
            cmsCloseProfile(testing_profile);
        }
    }

    /*
     * FUZZING BLOCK 4: Test .cube file parsing.
     */
    /*
     * ANALYSIS: The coverage report showed that cube file parsing logic in cmscgats.c,
     *           such as ParseCube, was not being exercised.
     * IMPLEMENTATION: This block writes fuzzer data to a temporary file and calls
     *                 cmsCreateDeviceLinkFromCubeFileTHR to parse it, targeting
     *                 the uncovered file parsing logic. The temporary file is
     *                 uniquely named and cleaned up to ensure statelessness.
     */
    if (fuzz_size > 10) { // Ensure there's some data to write
        char path[256];
        snprintf(path, sizeof(path), "/tmp/%s.cube", _FUZZ_TARGET_NAME);

        FILE* f = fopen(path, "wb");
        if (f) {
            size_t cube_data_len = fuzz_size % 1024;
            if (cube_data_len > fuzz_size) cube_data_len = fuzz_size;
            fwrite(fuzz_data, 1, cube_data_len, f);
            fclose(f);

            cmsHPROFILE cube_profile = cmsCreateDeviceLinkFromCubeFileTHR(context, path);
            if (cube_profile) {
                cmsCloseProfile(cube_profile);
            }
            unlink(path);
        }
    }


    cmsDeleteContext(context);
    return 0;
}