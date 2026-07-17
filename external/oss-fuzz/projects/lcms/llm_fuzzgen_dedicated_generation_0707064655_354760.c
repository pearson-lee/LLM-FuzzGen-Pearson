/* BLOCKER_STRATEGY_CONTRACT
required_state: The `AdaptationState` parameter in `ComputeAbsoluteIntent` must not be 1.0.
state_constructor: Directly call `cmsCreateExtendedTransform` with a custom `AdaptationStates` array containing values other than 1.0. The intent is set to `INTENT_ABSOLUTE_COLORIMETRIC` to ensure `ComputeAbsoluteIntent` is called.
trigger_api: `cmsCreateExtendedTransform`
preserved_invariants: The `AdaptationStates` array must contain a value that is not 1.0. The intent must be `INTENT_ABSOLUTE_COLORIMETRIC`.
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
    cmsHPROFILE output_profile = cmsCreate_sRGBProfileTHR(context);

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