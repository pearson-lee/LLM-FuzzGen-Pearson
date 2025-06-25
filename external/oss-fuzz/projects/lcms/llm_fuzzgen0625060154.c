#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free, calloc
#include <string.h> // For memcpy
#include <math.h>   // For fabs (though not directly used, good for general math operations)

// Include necessary lcms headers with full project-relative paths
#include "/src/lcms/include/lcms2.h"

// Global context for the fuzzer. This is initialized once per fuzzer process
// to avoid the overhead of creating and destroying a context for every single
// fuzzing input. Resources allocated within each LLVMFuzzerTestOneInput call
// are still meticulously freed.
cmsContext g_Context = NULL;

/**
 * @brief Safely consumes data from the fuzzer input and returns a cmsUInt32Number.
 *
 * Handles cases where the remaining input size is less than the size of cmsUInt32Number
 * by using the available bytes and setting the size to 0.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return A fuzzed cmsUInt32Number.
 */
cmsUInt32Number GetFuzzedUInt32(const uint8_t **Data, size_t *Size) {
    cmsUInt32Number val = 0;
    if (*Size >= sizeof(cmsUInt32Number)) {
        memcpy(&val, *Data, sizeof(cmsUInt32Number));
        *Data += sizeof(cmsUInt32Number);
        *Size -= sizeof(cmsUInt32Number);
    } else {
        // If not enough data, use remaining bytes to form the value
        for (size_t i = 0; i < *Size; ++i) {
            val = (val << 8) | (*Data)[i];
        }
        *Data += *Size;
        *Size = 0;
    }
    return val;
}

/**
 * @brief Safely consumes data from the fuzzer input and returns a cmsFloat64Number.
 *
 * Handles cases where the remaining input size is less than the size of cmsFloat64Number
 * by attempting to construct a float from the available bytes.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return A fuzzed cmsFloat64Number.
 */
cmsFloat64Number GetFuzzedFloat64(const uint8_t **Data, size_t *Size) {
    cmsFloat64Number val = 0.0;
    if (*Size >= sizeof(cmsFloat64Number)) {
        memcpy(&val, *Data, sizeof(cmsFloat64Number));
        *Data += sizeof(cmsFloat64Number);
        *Size -= sizeof(cmsFloat64Number);
    } else {
        // If not enough data, use remaining bytes as a fractional part
        if (*Size > 0) {
            double temp_val = 0.0;
            for (size_t i = 0; i < *Size; ++i) {
                temp_val = temp_val * 256.0 + (*Data)[i];
            }
            // Normalize to a reasonable range for a float
            val = temp_val / (double)(1ULL << ((*Size > 0 ? *Size : 1) * 8));
        }
        *Data += *Size;
        *Size = 0;
    }
    return val;
}

/**
 * @brief Consumes data and returns a fuzzed cmsColorSpaceSignature.
 *
 * Maps raw fuzzed data to a set of common and valid color space signatures
 * to increase the chances of successful API calls and better coverage.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return A fuzzed cmsColorSpaceSignature.
 */
cmsColorSpaceSignature GetFuzzedColorSpaceSignature(const uint8_t **Data, size_t *Size) {
    cmsUInt32Number raw_sig = GetFuzzedUInt32(Data, Size);

    // Map to known color space signatures
    switch (raw_sig % 10) {
        case 0: return cmsSigXYZData;
        case 1: return cmsSigLabData;
        case 2: return cmsSigLuvData;
        case 3: return cmsSigYCbCrData;
        case 4: return cmsSigYxyData;
        case 5: return cmsSigRgbData;
        case 6: return cmsSigGrayData;
        case 7: return cmsSigHsvData;
        case 8: return cmsSigHlsData;
        case 9: return cmsSigCmykData;
        default: return cmsSigRgbData; // Fallback, should not be reached with modulo 10
    }
}

/**
 * @brief Fuzz target for cmsCreateLinearizationDeviceLinkTHR.
 *
 * This function creates a linearization device link profile using fuzzed
 * color space signatures and tone curve parameters. It ensures proper
 * allocation and deallocation of all lcms objects.
 *
 * @param Data The fuzzer input data.
 * @param Size The size of the fuzzer input data.
 */
void FuzzCreateLinearizationDeviceLinkTHR(const uint8_t *Data, size_t Size) {
    const uint8_t *CurrentData = Data;
    size_t CurrentSize = Size;

    cmsColorSpaceSignature ColorSpace = GetFuzzedColorSpaceSignature(&CurrentData, &CurrentSize);
    if (CurrentSize == 0) return;

    cmsUInt32Number nChannels = cmsChannelsOfColorSpace(ColorSpace);
    if (nChannels == 0) return; // Invalid or unknown color space, skip

    // Allocate an array of tone curve pointers
    cmsToneCurve** TransferFunctions = (cmsToneCurve**)calloc(nChannels, sizeof(cmsToneCurve*));
    if (!TransferFunctions) return;

    // Create tone curves for each channel using fuzzed gamma values
    for (cmsUInt32Number i = 0; i < nChannels; ++i) {
        cmsFloat64Number gamma = GetFuzzedFloat64(&CurrentData, &CurrentSize);
        if (gamma <= 0) gamma = 2.2; // Ensure a valid positive gamma value

        TransferFunctions[i] = cmsBuildGamma(g_Context, gamma);
        if (!TransferFunctions[i]) {
            // If a curve allocation fails, clean up previously allocated curves
            for (cmsUInt32Number j = 0; j < i; ++j) {
                cmsFreeToneCurve(TransferFunctions[j]);
            }
            free(TransferFunctions);
            return;
        }
    }

    // Call the target API
    cmsHPROFILE hProfile = cmsCreateLinearizationDeviceLinkTHR(g_Context, ColorSpace, TransferFunctions);
    if (hProfile) {
        cmsCloseProfile(hProfile); // Free the created profile
    }

    // Free all allocated tone curves
    for (cmsUInt32Number i = 0; i < nChannels; ++i) {
        cmsFreeToneCurve(TransferFunctions[i]);
    }
    free(TransferFunctions); // Free the array of pointers
}

/**
 * @brief Fuzz target for cmsTransform2DeviceLink.
 *
 * This function creates a device link profile from an existing transform.
 * It sets up source and destination profiles, creates a transform, and then
 * calls the target API, ensuring all resources are properly managed.
 *
 * @param Data The fuzzer input data.
 * @param Size The size of the fuzzer input data.
 */
void FuzzTransform2DeviceLink(const uint8_t *Data, size_t Size) {
    const uint8_t *CurrentData = Data;
    size_t CurrentSize = Size;

    cmsHPROFILE hSrcProfile = NULL;
    cmsHPROFILE hDstProfile = NULL;
    cmsHTRANSFORM hTransform = NULL;

    // Create simple, known-good source and destination profiles to maximize
    // the chances of successful transform creation.
    hSrcProfile = cmsCreate_sRGBProfileTHR(g_Context);
    if (!hSrcProfile) goto cleanup;

    // Fix: Add the missing WhitePoint argument for cmsCreateLab4ProfileTHR
    hDstProfile = cmsCreateLab4ProfileTHR(g_Context, cmsD50_xyY());
    if (!hDstProfile) goto cleanup;

    // Fuzz input and output formats, intent, and flags for the transform
    cmsUInt32Number InputFormat = GetFuzzedUInt32(&CurrentData, &CurrentSize);
    cmsUInt32Number OutputFormat = GetFuzzedUInt32(&CurrentData, &CurrentSize);
    cmsUInt32Number Intent = GetFuzzedUInt32(&CurrentData, &CurrentSize) % 4; // Use 0-3 for standard intents
    // Fix: Limit dwFlags to a safe value to prevent invalid transform creation
    // Setting dwFlags to 0 or a combination of known safe flags can prevent crashes
    // caused by invalid flag combinations leading to an unusable transform object.
    cmsUInt32Number dwFlags = 0; // Set to 0 for robustness against fuzzed flags causing invalid transforms.

    // Map fuzzed formats to common ones to increase valid combinations
    switch (InputFormat % 3) {
        case 0: InputFormat = TYPE_RGB_8; break;
        case 1: InputFormat = TYPE_CMYK_8; break;
        case 2: InputFormat = TYPE_Lab_8; break;
    }
    switch (OutputFormat % 3) {
        case 0: OutputFormat = TYPE_RGB_8; break;
        case 1: OutputFormat = TYPE_CMYK_8; break;
        case 2: OutputFormat = TYPE_Lab_8; break;
    }

    // Create the color transform
    hTransform = cmsCreateTransformTHR(g_Context, hSrcProfile, InputFormat, hDstProfile, OutputFormat, Intent, dwFlags);
    if (!hTransform) goto cleanup;

    // Fuzz ICC version and additional flags for the device link
    cmsFloat64Number iccVersion = GetFuzzedFloat64(&CurrentData, &CurrentSize);
    if (iccVersion <= 0) iccVersion = 4.3; // Default to a valid version if fuzzed value is invalid

    cmsUInt32Number dwFlags2 = GetFuzzedUInt32(&CurrentData, &CurrentSize);

    // Call the target API
    cmsHPROFILE hDeviceLink = cmsTransform2DeviceLink(hTransform, iccVersion, dwFlags2);
    if (hDeviceLink) {
        cmsCloseProfile(hDeviceLink); // Free the created device link profile
    }

cleanup:
    // Ensure all allocated resources are freed
    if (hTransform) cmsDeleteTransform(hTransform);
    if (hSrcProfile) cmsCloseProfile(hSrcProfile);
    if (hDstProfile) cmsCloseProfile(hDstProfile);
}

/**
 * @brief Fuzz target for cmsIT8SaveToMem.
 *
 * This function creates an IT8 object, adds fuzzed properties and data to it,
 * and then attempts to save it to memory using a two-pass approach (first to get size,
 * then to fill the buffer). All dynamically allocated memory is freed.
 *
 * @param Data The fuzzer input data.
 * @param Size The size of the fuzzer input data.
 */
void FuzzIT8SaveToMem(const uint8_t *Data, size_t Size) {
    const uint8_t *CurrentData = Data;
    size_t CurrentSize = Size;

    // Fix: Use cmsHANDLE for cmsIT8 object as cmsIT8 is an opaque type
    cmsHANDLE it8 = cmsIT8Alloc(g_Context);
    if (!it8) return;

    // Add a fuzzed number of properties to the IT8 object
    cmsUInt32Number num_properties = GetFuzzedUInt32(&CurrentData, &CurrentSize) % 5; // Limit properties to avoid excessive memory usage
    for (cmsUInt32Number i = 0; i < num_properties; ++i) {
        if (CurrentSize < 2) break; // Need at least 2 bytes for name/value length

        // Fuzz property name length and content
        cmsUInt32Number name_len = GetFuzzedUInt32(&CurrentData, &CurrentSize) % 10; // Max 10 chars for name
        if (name_len > CurrentSize) name_len = CurrentSize;
        char* prop_name = (char*)malloc(name_len + 1);
        if (!prop_name) break;
        memcpy(prop_name, CurrentData, name_len);
        prop_name[name_len] = '\0';
        CurrentData += name_len;
        CurrentSize -= name_len;

        if (CurrentSize < 2) { free(prop_name); break; }

        // Fuzz property value length and content
        cmsUInt32Number value_len = GetFuzzedUInt32(&CurrentData, &CurrentSize) % 20; // Max 20 chars for value
        if (value_len > CurrentSize) value_len = CurrentSize;
        char* prop_value = (char*)malloc(value_len + 1);
        if (!prop_value) { free(prop_name); break; }
        memcpy(prop_value, CurrentData, value_len);
        prop_value[value_len] = '\0';
        CurrentData += value_len;
        CurrentSize -= value_len;

        cmsIT8SetPropertyStr(it8, prop_name, prop_value);
        free(prop_name);
        free(prop_value);
    }

    // First pass: call cmsIT8SaveToMem with NULL buffer to get the required size
    void* Buffer = NULL;
    cmsUInt32Number BufferSize = 0;
    cmsIT8SaveToMem(it8, NULL, &BufferSize);

    if (BufferSize > 0) {
        // Allocate buffer based on the size obtained from the first pass
        Buffer = malloc(BufferSize);
        if (Buffer) {
            // Second pass: call cmsIT8SaveToMem to actually save data to the allocated buffer
            cmsIT8SaveToMem(it8, Buffer, &BufferSize);
            free(Buffer); // Free the buffer allocated for saving
        }
    }

    cmsIT8Free(it8); // Free the IT8 object
}

// LLVMFuzzerTestOneInput is the main entry point for the fuzzer.
// It receives a pointer to the fuzzer input data and its size.
// Fix: Remove extern "C" as this is a C file.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize the global lcms context if it hasn't been already.
    // This ensures the context is created only once per fuzzer process lifetime.
    if (g_Context == NULL) {
        g_Context = cmsCreateContext(NULL, NULL);
        if (g_Context == NULL) {
            return 0; // If context creation fails, nothing can be done.
        }
    }

    // Create a mutable copy of Data and Size for helper functions to consume.
    const uint8_t *CurrentData = Data;
    size_t CurrentSize = Size;

    // Use a fuzzed value from the input to select which API function to call.
    // Ensure there's enough data for at least one cmsUInt32Number for the choice.
    if (CurrentSize < sizeof(cmsUInt32Number)) return 0;
    cmsUInt32Number api_choice = GetFuzzedUInt32(&CurrentData, &CurrentSize);

    // Call one of the selected diverse API functions based on the fuzzed choice.
    switch (api_choice % 3) { // Modulo 3 to select one of the three fuzz targets
        case 0:
            FuzzCreateLinearizationDeviceLinkTHR(CurrentData, CurrentSize);
            break;
        case 1:
            FuzzTransform2DeviceLink(CurrentData, CurrentSize);
            break;
        case 2:
            FuzzIT8SaveToMem(CurrentData, CurrentSize);
            break;
        default:
            // This case should ideally not be reached due to the modulo operation.
            break;
    }

    // No need to delete g_Context here, as it's a global resource intended
    // to persist across fuzzing inputs within the same process.
    // It will be cleaned up when the fuzzer process exits.

    return 0; // Indicate successful execution
}