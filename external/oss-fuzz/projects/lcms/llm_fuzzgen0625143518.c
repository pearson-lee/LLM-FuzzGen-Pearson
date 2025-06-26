#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

// Helper to safely consume data from the fuzzer input
static const uint8_t *fuzz_data;
static size_t fuzz_size;

// List of valid formatters to increase the chances of successful API calls.
const uint32_t formatters[] = {
    TYPE_GRAY_8, TYPE_GRAY_8_REV, TYPE_GRAY_16, TYPE_GRAY_16_REV, TYPE_GRAY_16_SE,
    TYPE_GRAYA_8, TYPE_GRAYA_16, TYPE_GRAYA_16_SE, TYPE_GRAYA_8_PLANAR, TYPE_GRAYA_16_PLANAR,
    TYPE_RGB_8, TYPE_RGB_8_PLANAR, TYPE_BGR_8, TYPE_BGR_8_PLANAR, TYPE_RGB_16,
    TYPE_RGB_16_PLANAR, TYPE_RGB_16_SE, TYPE_BGR_16, TYPE_BGR_16_PLANAR, TYPE_BGR_16_SE,
    TYPE_RGBA_8, TYPE_RGBA_8_PLANAR, TYPE_RGBA_16, TYPE_RGBA_16_PLANAR, TYPE_RGBA_16_SE,
    TYPE_ARGB_8, TYPE_ARGB_16, TYPE_ABGR_8, TYPE_ABGR_16, TYPE_BGRA_8, TYPE_BGRA_16,
    TYPE_BGRA_16_SE, TYPE_CMY_8, TYPE_CMY_8_PLANAR, TYPE_CMY_16, TYPE_CMY_16_PLANAR,
    TYPE_CMY_16_SE, TYPE_CMYK_8, TYPE_CMYK_8_PLANAR, TYPE_CMYK_16, TYPE_CMYK_16_PLANAR,
    TYPE_CMYK_16_SE, TYPE_KYMC_8, TYPE_KYMC_16, TYPE_KCMY_8, TYPE_KCMY_16,
    TYPE_XYZ_16, TYPE_XYZ_DBL, TYPE_Lab_8, TYPE_ALab_8, TYPE_Lab_16, TYPE_Lab_DBL
};
const int num_formatters = sizeof(formatters) / sizeof(formatters[0]);


void FuzzDataProvider(const uint8_t *Data, size_t Size) {
    fuzz_data = Data;
    fuzz_size = Size;
}

size_t GetRandomData(void *buffer, size_t len) {
    if (fuzz_size == 0) {
        return 0;
    }
    if (len > fuzz_size) {
        len = fuzz_size;
    }
    if (buffer) {
        memcpy(buffer, fuzz_data, len);
    }
    fuzz_data += len;
    fuzz_size -= len;
    return len;
}

uint32_t GetRandomUInt32() {
    uint32_t val = 0;
    GetRandomData(&val, sizeof(val));
    return val;
}

double GetRandomDouble() {
    double val = 0;
    if (GetRandomData(&val, sizeof(val)) != sizeof(val)) {
        return 0.0;
    }
    return val;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    FuzzDataProvider(Data, Size);

    // --- API 1: cmsCreateRGBProfile ---
    // Create tone curves for the RGB profile. These are freed after profile creation.
    cmsToneCurve *gamma_curves[3];
    gamma_curves[0] = cmsBuildGamma(NULL, GetRandomDouble() * 2.0 + 0.5); // Gamma between 0.5 and 2.5
    gamma_curves[1] = cmsBuildGamma(NULL, GetRandomDouble() * 2.0 + 0.5);
    gamma_curves[2] = cmsBuildGamma(NULL, GetRandomDouble() * 2.0 + 0.5);

    // Create primaries for the RGB profile from fuzzer data.
    cmsCIExyYTRIPLE primaries;
    GetRandomData(&primaries, sizeof(primaries));

    // Create an RGB profile.
    cmsHPROFILE rgb_profile = cmsCreateRGBProfile(cmsD50_xyY(), &primaries, gamma_curves);

    // Free the tone curves as they are now embedded in the profile.
    if (gamma_curves[0]) cmsFreeToneCurve(gamma_curves[0]);
    if (gamma_curves[1]) cmsFreeToneCurve(gamma_curves[1]);
    if (gamma_curves[2]) cmsFreeToneCurve(gamma_curves[2]);


    // --- API 2: cmsCreateNULLProfile ---
    // Create a NULL profile for variety in testing.
    cmsHPROFILE null_profile = cmsCreateNULLProfile();


    // --- API 3: cmsCreateProofingTransform ---
    cmsHTRANSFORM transform = NULL;
    if (rgb_profile && null_profile) {
        // Select valid formatters, intents, and flags from fuzzer data.
        uint32_t input_format = formatters[GetRandomUInt32() % num_formatters];
        uint32_t output_format = formatters[GetRandomUInt32() % num_formatters];
        uint32_t intent = GetRandomUInt32() % 4;
        uint32_t proof_intent = GetRandomUInt32() % 4;
        uint32_t flags = GetRandomUInt32();

        // Create a proofing transform using the previously created profiles.
        transform = cmsCreateProofingTransform(rgb_profile, input_format, null_profile, output_format, null_profile, intent, proof_intent, flags);
    }


    // --- API 4: cmsTransform2DeviceLink ---
    cmsHPROFILE devicelink_profile = NULL;
    if (transform) {
        double version = (GetRandomUInt32() % 2 == 0) ? 4.3 : 2.1;
        uint32_t flags = GetRandomUInt32();
        // Convert the transform to a device link profile.
        devicelink_profile = cmsTransform2DeviceLink(transform, version, flags);
    }


    // --- API 5: cmsGetPostScriptCRD ---
    if (rgb_profile) {
        uint32_t intent = GetRandomUInt32() % 4;
        uint32_t flags = GetRandomUInt32();
        
        // Use remaining fuzzer data as a buffer for the PostScript CRD.
        uint8_t crd_buffer[256];
        size_t buffer_len = GetRandomData(crd_buffer, sizeof(crd_buffer));

        // Generate the PostScript CRD.
        cmsGetPostScriptCRD(NULL, rgb_profile, intent, flags, crd_buffer, buffer_len);
    }


    // --- Cleanup ---
    // All created resources must be freed to avoid memory leaks.
    if (transform) {
        cmsDeleteTransform(transform);
    }
    if (rgb_profile) {
        cmsCloseProfile(rgb_profile);
    }
    if (null_profile) {
        cmsCloseProfile(null_profile);
    }
    if (devicelink_profile) {
        cmsCloseProfile(devicelink_profile);
    }

    return 0;
}