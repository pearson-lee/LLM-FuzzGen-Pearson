#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <math.h>

#include "/src/lcms/include/lcms2.h"

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
            // The original code included this commented-out block to indicate
            // how an internal function might be tested. It is preserved here.
            // cmsSEQ* compiled_seq = _cmsCompileProfileSequence(context, 2, profiles);
            // if (compiled_seq) {
            //     cmsFreeProfileSequenceDescription(compiled_seq);
            // }
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
    cmsHPROFILE testing_profile = CreateTestingProfile(context, &fuzz_data, &fuzz_size);
    if (testing_profile) {
        cmsCIEXYZ black_point;
        uint32_t intent = 0;
        if (fuzz_size > 0) {
            // Use one byte of remaining data to generate intent [0-3].
            intent = fuzz_data[0] % 4;
        }
        cmsDetectDestinationBlackPoint(&black_point, testing_profile, intent, 0);
        cmsDetectBlackPoint(&black_point, testing_profile, intent, 0);
        cmsCloseProfile(testing_profile);
    }

    cmsDeleteContext(context);
    return 0;
}