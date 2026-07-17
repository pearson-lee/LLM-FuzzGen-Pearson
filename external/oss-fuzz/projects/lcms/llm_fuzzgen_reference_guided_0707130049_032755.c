/* BLOCKER_STRATEGY_CONTRACT
required_state: The `Scale` matrix in `ComputeAbsoluteIntent` must not be an identity matrix. This is achieved by ensuring the input and output profiles have different media white points.
state_constructor: The input profile is a standard sRGB profile (D65 white point). The output profile is a custom RGB profile created via `cmsCreateRGBProfileTHR` with an explicit D50 white point.
trigger_api: `cmsCreateExtendedTransform`
preserved_invariants: The top-level input consumption for `AdaptationState` is preserved. The transform is created between two RGB profiles with `INTENT_ABSOLUTE_COLORIMETRIC`.
END_BLOCKER_STRATEGY_CONTRACT */

#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    cmsHPROFILE input_profile = cmsCreate_sRGBProfileTHR(context);

    // BLOCKER-SPECIFIC CHANGE: Create a custom RGB output profile with a different
    // white point (D50) than the sRGB input profile (D65). This ensures the `Scale`
    // matrix in `ComputeAbsoluteIntent` is not an identity matrix, thus bypassing
    // the blocker at cmscnvrt.c:308.
    cmsHPROFILE output_profile = NULL;
    cmsCIExyY* d50_wp = cmsD50_xyY();
    cmsToneCurve* gamma_curves[3];
    gamma_curves[0] = cmsBuildGamma(context, 2.2);
    gamma_curves[1] = cmsBuildGamma(context, 2.2);
    gamma_curves[2] = cmsBuildGamma(context, 2.2);

    if (gamma_curves[0] && gamma_curves[1] && gamma_curves[2]) {
        cmsCIExyYTRIPLE srgb_primaries = {
            { 0.64, 0.33, 1.0 }, // Red
            { 0.30, 0.60, 1.0 }, // Green
            { 0.15, 0.06, 1.0 }  // Blue
        };
        output_profile = cmsCreateRGBProfileTHR(context, d50_wp, &srgb_primaries, gamma_curves);
    }

    if (gamma_curves[0]) cmsFreeToneCurve(gamma_curves[0]);
    if (gamma_curves[1]) cmsFreeToneCurve(gamma_curves[1]);
    if (gamma_curves[2]) cmsFreeToneCurve(gamma_curves[2]);


    if (!input_profile || !output_profile) {
        if (input_profile) cmsCloseProfile(input_profile);
        if (output_profile) cmsCloseProfile(output_profile);
        cmsDeleteContext(context);
        return 0;
    }

    cmsHPROFILE profiles[] = {input_profile, output_profile};
    cmsUInt32Number intents[] = {INTENT_ABSOLUTE_COLORIMETRIC, INTENT_ABSOLUTE_COLORIMETRIC};
    cmsBool bpc[] = {0, 0};
    
    double adaptation_state_double;
    if (size >= sizeof(double)) {
        memcpy(&adaptation_state_double, data, sizeof(double));
        // Ensure the value is in [0, 1) to trigger the 'else' branch.
        adaptation_state_double = fmod(fabs(adaptation_state_double), 1.0);
    } else {
        adaptation_state_double = 0.5;
    }
    
    cmsFloat64Number adaptation_states[] = {adaptation_state_double, adaptation_state_double};

    cmsHTRANSFORM transform = cmsCreateExtendedTransform(
        context, 2, profiles, bpc, intents, adaptation_states,
        NULL, 0, TYPE_RGB_8, TYPE_RGB_8, 0
    );

    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(input_profile);
    cmsCloseProfile(output_profile);
    cmsDeleteContext(context);

    return 0;
}
