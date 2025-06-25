#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy, strlen

// Include necessary lcms headers with full project-relative paths
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h" // Contains declarations for internal functions like _cmsChain2Lab, _cmsDefaultICCintents, etc.

/**
 * @brief Helper function to consume bytes from the fuzzer data and create a null-terminated string.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @param max_len The maximum length of the string to create (excluding null terminator).
 * @return A dynamically allocated, null-terminated string, or NULL if not enough data or allocation fails.
 *         The caller is responsible for freeing the returned string.
 */
char* get_fuzzed_string(const uint8_t** Data, size_t* Size, size_t max_len) {
    if (*Size == 0) {
        return NULL;
    }
    size_t len = *Size > max_len ? max_len : *Size;
    char* str = (char*)malloc(len + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, *Data, len);
    str[len] = '\0';
    *Data += len;
    *Size -= len;
    return str;
}

/**
 * @brief Helper function to consume bytes from the fuzzer data and interpret them as a cmsUInt32Number.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return The fuzzed cmsUInt32Number value, or 0 if not enough data.
 */
cmsUInt32Number get_fuzzed_uint32(const uint8_t** Data, size_t* Size) {
    cmsUInt32Number val = 0;
    if (*Size >= sizeof(cmsUInt32Number)) {
        memcpy(&val, *Data, sizeof(cmsUInt32Number));
        *Data += sizeof(cmsUInt32Number);
        *Size -= sizeof(cmsUInt32Number);
    } else {
        // Not enough data, consume all remaining and return 0
        *Data += *Size;
        *Size = 0;
    }
    return val;
}

/**
 * @brief Helper function to consume bytes from the fuzzer data and interpret them as a cmsUInt16Number.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return The fuzzed cmsUInt16Number value, or 0 if not enough data.
 */
cmsUInt16Number get_fuzzed_uint16(const uint8_t** Data, size_t* Size) {
    cmsUInt16Number val = 0;
    if (*Size >= sizeof(cmsUInt16Number)) {
        memcpy(&val, *Data, sizeof(cmsUInt16Number));
        *Data += sizeof(cmsUInt16Number);
        *Size -= sizeof(cmsUInt16Number);
    } else {
        // Not enough data, consume all remaining and return 0
        *Data += *Size;
        *Size = 0;
    }
    return val;
}

/**
 * @brief Helper function to consume bytes from the fuzzer data and interpret them as a cmsFloat64Number.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return The fuzzed cmsFloat64Number value, or 0.0 if not enough data.
 */
cmsFloat64Number get_fuzzed_float64(const uint8_t** Data, size_t* Size) {
    cmsFloat64Number val = 0.0;
    if (*Size >= sizeof(cmsFloat64Number)) {
        memcpy(&val, *Data, sizeof(cmsFloat64Number));
        *Data += sizeof(cmsFloat64Number);
        *Size -= sizeof(cmsFloat64Number);
    } else {
        // Not enough data, consume all remaining and return 0.0
        *Data += *Size;
        *Size = 0;
    }
    return val;
}

/**
 * @brief Helper function to consume bytes from the fuzzer data and interpret them as a cmsInt32Number.
 *
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return The fuzzed cmsInt32Number value, or 0 if not enough data.
 */
cmsInt32Number get_fuzzed_int32(const uint8_t** Data, size_t* Size) {
    cmsInt32Number val = 0;
    if (*Size >= sizeof(cmsInt32Number)) {
        memcpy(&val, *Data, sizeof(cmsInt32Number));
        *Data += sizeof(cmsInt32Number);
        *Size -= sizeof(cmsInt32Number);
    } else {
        // Not enough data, consume all remaining and return 0
        *Data += *Size;
        *Size = 0;
    }
    return val;
}

/**
 * @brief Helper function to create a fuzzed cmsToneCurve object.
 *
 * @param ContextID The lcms context.
 * @param Data Pointer to the current position in the fuzzer input data.
 * @param Size Pointer to the remaining size of the fuzzer input data.
 * @return A new cmsToneCurve object, or NULL if creation fails due to lack of data or memory.
 *         The caller is responsible for freeing the returned tone curve using cmsFreeToneCurve.
 */
cmsToneCurve* create_fuzzed_tone_curve(cmsContext ContextID, const uint8_t** Data, size_t* Size) {
    if (*Size < sizeof(cmsUInt32Number)) return NULL; // Need at least 4 bytes for type

    cmsUInt32Number type = get_fuzzed_uint32(Data, Size) % 2; // 0 for tabulated, 1 for parametric
    cmsToneCurve* curve = NULL;

    if (type == 0) { // Tabulated Tone Curve
        if (*Size < sizeof(cmsUInt32Number)) return NULL; // Need 4 bytes for num_points
        cmsUInt32Number num_points = get_fuzzed_uint32(Data, Size) % 256 + 2; // At least 2 points, max 257

        // Check if enough data for the table and if malloc would overflow
        if (num_points > (SIZE_MAX / sizeof(cmsUInt16Number)) || *Size < num_points * sizeof(cmsUInt16Number)) {
            // Not enough data or potential overflow, consume remaining and return NULL
            *Data += *Size;
            *Size = 0;
            return NULL;
        }

        cmsUInt16Number* table = (cmsUInt16Number*)malloc(num_points * sizeof(cmsUInt16Number));
        if (table == NULL) return NULL; // Allocation failed

        for (cmsUInt32Number i = 0; i < num_points; ++i) {
            table[i] = get_fuzzed_uint16(Data, Size);
        }
        curve = cmsBuildTabulatedToneCurve16(ContextID, num_points, table);
        free(table); // Free the temporary table
    } else { // Parametric Tone Curve
        if (*Size < sizeof(cmsInt32Number)) return NULL; // Need 4 bytes for function_type
        cmsInt32Number function_type = get_fuzzed_int32(Data, Size) % 18; // Max 18 parametric types

        if (*Size < sizeof(cmsUInt32Number)) return NULL; // Need 4 bytes for num_params
        size_t num_params = get_fuzzed_uint32(Data, Size) % 6; // Up to 6 parameters for common types
        if (num_params > 10) num_params = 10; // Cap at max params array size (params[10])

        if (*Size < num_params * sizeof(cmsFloat64Number)) return NULL; // Not enough data for parameters

        cmsFloat64Number params[10] = {0}; // Max 10 parameters for parametric curves
        for (size_t i = 0; i < num_params; ++i) {
            params[i] = get_fuzzed_float64(Data, Size);
        }
        curve = cmsBuildParametricToneCurve(ContextID, function_type, params);
    }
    return curve;
}

/**
 * @brief Main fuzzing function called by the fuzzer engine.
 *
 * This function takes raw fuzzer input data and uses it to exercise various
 * lcms API functions, focusing on those with low coverage. It ensures proper
 * memory management to prevent leaks.
 *
 * @param Data Pointer to the fuzzer input data.
 * @param Size Size of the fuzzer input data.
 * @return 0 to indicate successful execution.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create a mutable copy of Data and Size to consume bytes
    const uint8_t* current_data = Data;
    size_t current_size = Size;

    // Initialize lcms context. This is the first resource to allocate.
    cmsContext ContextID = cmsCreateContext(NULL, NULL);
    if (ContextID == NULL) {
        return 0; // Cannot proceed without a context
    }

    // --- Fuzzing cmsGetPostScriptCRD ---
    // This function had 0.0% coverage. We aim to hit its internal branches.
    // Specifically, the `if (Buffer == NULL)` branch and the `if (!mem)` branch.
    // Ensure enough data for Intent and dwFlags
    if (current_size >= sizeof(cmsUInt32Number) * 2) {
        cmsHPROFILE hProfile_ps = NULL;
        // Create a standard sRGB profile for cmsGetPostScriptCRD.
        // This provides a more complete profile structure than a NULL profile,
        // which might prevent internal crashes in cmsGetPostScriptCRD.
        hProfile_ps = cmsCreate_sRGBProfileTHR(ContextID);

        if (hProfile_ps != NULL) {
            // Constrain Intent_ps to valid range [0, 3]
            cmsUInt32Number Intent_ps = get_fuzzed_uint32(&current_data, &current_size) % 4;
            // Constrain dwFlags_ps to lower 16 bits to avoid problematic high-value flags
            cmsUInt32Number dwFlags_ps = get_fuzzed_uint32(&current_data, &current_size) & 0x0000FFFF;

            // Scenario 1: Call with Buffer == NULL to cover the true branch of `if (Buffer == NULL)`
            cmsGetPostScriptCRD(ContextID, hProfile_ps, Intent_ps, dwFlags_ps, NULL, 0);

            // Scenario 2: Call with a fuzzed Buffer to cover the else branch
            // Ensure enough data for buffer_len_ps
            if (current_size >= sizeof(cmsUInt32Number)) {
                size_t buffer_len_ps = get_fuzzed_uint32(&current_data, &current_size) % 1024; // Max 1KB buffer size
                if (buffer_len_ps > 0) {
                    void* buffer_ps = malloc(buffer_len_ps);
                    if (buffer_ps != NULL) {
                        cmsGetPostScriptCRD(ContextID, hProfile_ps, Intent_ps, dwFlags_ps, buffer_ps, (cmsUInt32Number)buffer_len_ps);
                        free(buffer_ps); // Free the allocated buffer
                    }
                }
            }
            cmsCloseProfile(hProfile_ps); // Free the created profile
        }
    }

    // --- Fuzzing cmsCreateLinearizationDeviceLinkTHR ---
    // This function also had 0.0% coverage.
    // It requires a color space and an array of tone curves.
    // Ensure enough data for ColorSpace_lin
    if (current_size >= sizeof(cmsUInt32Number)) {
        cmsColorSpaceSignature ColorSpace_lin = get_fuzzed_uint32(&current_data, &current_size);
        // Restrict ColorSpace to common types to ensure valid channel counts and avoid excessive allocations
        switch (ColorSpace_lin) {
            case cmsSigGrayData:
            case cmsSigRgbData:
            case cmsSigCmykData:
                break;
            default:
                ColorSpace_lin = cmsSigRgbData; // Default to RGB if fuzzed value is not a common color space
                break;
        }

        cmsUInt32Number num_channels = cmsChannelsOfColorSpace(ColorSpace_lin);
        if (num_channels == 0) num_channels = 3; // Fallback to 3 channels if cmsChannelsOfColorSpace returns 0 (unknown signature)

        cmsToneCurve** curves_lin = (cmsToneCurve**)calloc(num_channels, sizeof(cmsToneCurve*));
        if (curves_lin != NULL) {
            cmsBool all_curves_created = 1;
            for (cmsUInt32Number i = 0; i < num_channels; ++i) {
                // Create individual tone curves using fuzzed data
                curves_lin[i] = create_fuzzed_tone_curve(ContextID, &current_data, &current_size);
                if (curves_lin[i] == NULL) {
                    all_curves_created = 0;
                    break; // Stop if any curve creation fails
                }
            }

            if (all_curves_created) {
                cmsHPROFILE hProfile_lin = cmsCreateLinearizationDeviceLinkTHR(ContextID, ColorSpace_lin, (const cmsToneCurve **)curves_lin);
                if (hProfile_lin != NULL) {
                    cmsCloseProfile(hProfile_lin); // Free the created profile
                }
            }
            // Always free the allocated tone curves and the array itself
            for (cmsUInt32Number i = 0; i < num_channels; ++i) {
                if (curves_lin[i] != NULL) {
                    cmsFreeToneCurve(curves_lin[i]);
                }
            }
            free(curves_lin); // Free the array of pointers
        }
    }

    // --- Fuzzing cmsCreateInkLimitingDeviceLinkTHR ---
    // This function also had 0.0% coverage.
    // It requires a color space and an ink limit value.
    // Ensure enough data for ColorSpace_ink and Limit_ink
    if (current_size >= sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number)) {
        cmsColorSpaceSignature ColorSpace_ink = get_fuzzed_uint32(&current_data, &current_size);
        // Restrict ColorSpace to common ink types
        switch (ColorSpace_ink) {
            case cmsSigCmykData:
            case cmsSig5colorData: case cmsSig6colorData: case cmsSig7colorData: case cmsSig8colorData:
            case cmsSig9colorData: case cmsSig10colorData: case cmsSig11colorData: case cmsSig12colorData:
            case cmsSig13colorData: case cmsSig14colorData: case cmsSig15colorData:
                break;
            default:
                ColorSpace_ink = cmsSigCmykData; // Default to CMYK if fuzzed value is not an ink color space
                break;
        }
        cmsFloat64Number Limit_ink = get_fuzzed_float64(&current_data, &current_size);

        // Clamp the ink limit to a reasonable range (e.g., 0.0 to 100.0 * number of channels)
        cmsUInt32Number ink_channels = cmsChannelsOfColorSpace(ColorSpace_ink);
        if (ink_channels == 0) ink_channels = 4; // Default to 4 channels if unknown, for limit calculation
        if (Limit_ink < 0.0) Limit_ink = 0.0;
        if (Limit_ink > 100.0 * ink_channels) Limit_ink = 100.0 * ink_channels;
        if (Limit_ink > 400.0) Limit_ink = 400.0; // Absolute upper cap

        cmsHPROFILE hProfile_ink = cmsCreateInkLimitingDeviceLinkTHR(ContextID, ColorSpace_ink, Limit_ink);
        if (hProfile_ink != NULL) {
            cmsCloseProfile(hProfile_ink); // Free the created profile
        }
    }

    // --- Fuzzing cmsIT8SetDataDbl and cmsIT8SetData ---
    // These functions had 0.0% coverage. They are used for setting data in IT8 tables.
    // Ensure enough data for at least one IT8 operation (e.g., two strings and a double)
    if (current_size > (32 + 32 + sizeof(cmsFloat64Number))) {
        cmsHANDLE hIT8 = cmsIT8Alloc(ContextID); // Allocate an IT8 handle
        if (hIT8 != NULL) {
            // Fuzz cmsIT8SetDataDbl: Sets a double value for a given patch and parameter
            char* cPatch_dbl = get_fuzzed_string(&current_data, &current_size, 32);
            char* cParam_dbl = get_fuzzed_string(&current_data, &current_size, 32);
            cmsFloat64Number dValue = get_fuzzed_float64(&current_data, &current_size);

            if (cPatch_dbl != NULL && cParam_dbl != NULL) {
                cmsIT8SetDataDbl(hIT8, cPatch_dbl, cParam_dbl, dValue);
            }
            free(cPatch_dbl); // Free allocated strings
            free(cParam_dbl);

            // Fuzz cmsIT8SetData: Sets a string value for a given patch and parameter
            char* cPatch_str = get_fuzzed_string(&current_data, &current_size, 32);
            char* cParam_str = get_fuzzed_string(&current_data, &current_size, 32);
            char* cValue_str = get_fuzzed_string(&current_data, &current_size, 64);

            if (cPatch_str != NULL && cParam_str != NULL && cValue_str != NULL) {
                cmsIT8SetData(hIT8, cPatch_str, cParam_str, cValue_str);
            }
            free(cPatch_str); // Free allocated strings
            free(cParam_str);
            free(cValue_str);

            cmsIT8Free(hIT8); // Free the IT8 handle
        }
    }

    // Clean up the lcms context. This must be the last cleanup.
    cmsDeleteContext(ContextID);

    return 0; // Indicate successful execution
}