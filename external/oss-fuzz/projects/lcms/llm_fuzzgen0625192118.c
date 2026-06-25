#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"

// FuzzedDataProvider is not available in C, so we'll use the raw data.
// Helper function to consume data from the buffer.
static const uint8_t *consume_data(const uint8_t **data, size_t *size, size_t amount) {
    if (*size < amount) {
        return NULL;
    }
    const uint8_t *ret = *data;
    *data += amount;
    *size -= amount;
    return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *original_data = data;
    size_t original_size = size;

    /*
     * ANALYSIS: The coverage report shows that `cmsIT8LoadFromMem` and its
     *           underlying parser functions like `ParseIT8` and `ParseFloatNumber`
     *           have very low coverage.
     * IMPLEMENTATION: The following block calls `cmsIT8LoadFromMem` with a
     *                 fuzzer-provided data chunk to exercise the IT8 parser.
     */
    size_t it8_size = 0;
    if (size > sizeof(it8_size)) {
        it8_size = *(size_t *)consume_data(&data, &size, sizeof(it8_size));
        it8_size = it8_size % (size + 1);
        const uint8_t *it8_data = consume_data(&data, &size, it8_size);
        if (it8_data && it8_size > 0) {
            cmsHANDLE it8_handle = cmsIT8LoadFromMem(NULL, it8_data, it8_size);
            if (it8_handle) {
                cmsIT8Free(it8_handle);
            }
        }
    }

    // Restore data and size for the next part of the fuzzer.
    data = original_data;
    size = original_size;

    /*
     * ANALYSIS: Many tag-parsing functions (`Type_*_Read` in cmstypes.c) like
     *           `Type_LUT8_Read` and `Type_ParametricCurve_Read` have zero or very
     *           low coverage. `cmsOpenProfileFromMem` is the entry point for
     *           parsing these tags. Additionally, `cmsDetectDestinationBlackPoint`
     *           has low coverage (44.54%).
     * IMPLEMENTATION: This block uses fuzzer data to create a memory-based
     *                 profile, which will trigger various tag parsing functions.
     *                 If a valid profile is created, it is then used to call
     *                 `cmsDetectDestinationBlackPoint` to exercise its logic.
     */
    cmsHPROFILE profile_from_mem = cmsOpenProfileFromMem(data, size);
    if (profile_from_mem) {
        cmsCIEXYZ black_point;
        uint32_t intent = 0;
        uint32_t flags = 0;
        if (size > sizeof(uint32_t) * 2) {
            intent = *(uint32_t *)consume_data(&data, &size, sizeof(uint32_t));
            flags = *(uint32_t *)consume_data(&data, &size, sizeof(uint32_t));
        }
        cmsDetectDestinationBlackPoint(&black_point, profile_from_mem, intent, flags);
        cmsCloseProfile(profile_from_mem);
    }

    /*
     * ANALYSIS: The functions `BuildGrayOutputPipeline` (20% coverage) and
     *           the optimization function `PatchLUT` (34% coverage) are poorly
     *           tested. They are part of the transform creation process.
     * IMPLEMENTATION: The following code creates a transform between a gray
     *                 profile and an sRGB profile. Using a gray profile helps
     *                 trigger `BuildGrayOutputPipeline`. The `cmsFLAGS_OPTIMIZE`
     *                 flag is used to encourage the optimizer, including `PatchLUT`,
     *                 to run. Fuzzer data is used for formats and flags to
     *                 increase variability.
     */
    cmsHPROFILE gray_profile = cmsCreateGrayProfile(NULL, NULL);
    cmsHPROFILE srgb_profile = cmsCreate_sRGBProfile();

    if (gray_profile && srgb_profile) {
        uint32_t in_format = 0;
        uint32_t out_format = 0;
        uint32_t transform_flags = 0; // Optimization is on by default

        if (original_size > sizeof(uint32_t) * 2) {
            // Use original data pointer to avoid dependency on previous consumption
            in_format = *(uint32_t *)(original_data);
            out_format = *(uint32_t *)(original_data + sizeof(uint32_t));
            if (original_size > sizeof(uint32_t) * 3) {
                 transform_flags |= *(uint32_t *)(original_data + sizeof(uint32_t) * 2);
            }
        }

        cmsHTRANSFORM transform = cmsCreateTransform(
            gray_profile, in_format, srgb_profile, out_format,
            INTENT_PERCEPTUAL, transform_flags);

        if (transform) {
            // With a valid transform, exercise the DoTransform function
            uint8_t in_buf[256];
            uint8_t out_buf[256];
            memset(in_buf, 0, sizeof(in_buf));
            if (original_size > sizeof(in_buf)) {
                memcpy(in_buf, original_data, sizeof(in_buf));
            }
            cmsDoTransform(transform, in_buf, out_buf, 1);
            cmsDeleteTransform(transform);
        }
    }

    // Cleanup created profiles
    if (gray_profile) {
        cmsCloseProfile(gray_profile);
    }
    if (srgb_profile) {
        cmsCloseProfile(srgb_profile);
    }

    return 0;
}