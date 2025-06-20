#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <stdlib.h>

// The maximum number of profiles to use in the fuzzing process.
#define MAX_PROFILES 4

// Helper function to consume data from the fuzzing input buffer.
static const uint8_t *consume_data(const uint8_t **data, size_t *size, size_t len) {
  if (*size < len) {
    return NULL;
  }
  const uint8_t *ret = *data;
  *data += len;
  *size -= len;
  return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *orig_data = data;
  size_t orig_size = size;

  // Consume the number of profiles from the fuzzing data.
  const uint8_t *n_profiles_data = consume_data(&data, &size, 1);
  if (!n_profiles_data) {
    return 0;
  }
  // We use a small number of profiles to avoid excessive memory allocation.
  cmsUInt32Number n_profiles = (*n_profiles_data % MAX_PROFILES) + 1;

  // Create arrays for profiles, intents, BPC flags, and adaptation states.
  cmsHPROFILE h_profiles[MAX_PROFILES] = {0};
  cmsUInt32Number intents[MAX_PROFILES];
  cmsBool bpc[MAX_PROFILES];
  cmsFloat64Number adaptation_states[MAX_PROFILES];

  // Consume data for intents, BPC flags, and adaptation states.
  const uint8_t *intents_data = consume_data(&data, &size, sizeof(intents[0]) * n_profiles);
  const uint8_t *bpc_data = consume_data(&data, &size, sizeof(bpc[0]) * n_profiles);
  const uint8_t *adaptation_states_data = consume_data(&data, &size, sizeof(adaptation_states[0]) * n_profiles);

  if (!intents_data || !bpc_data || !adaptation_states_data) {
    // Clean up any profiles that may have been created.
    for (cmsUInt32Number i = 0; i < n_profiles; i++) {
      if (h_profiles[i]) {
        cmsCloseProfile(h_profiles[i]);
      }
    }
    return 0;
  }

  // Populate the arrays with data from the fuzzer.
  for (cmsUInt32Number i = 0; i < n_profiles; i++) {
    intents[i] = ((cmsUInt32Number *)intents_data)[i];
    bpc[i] = ((cmsBool *)bpc_data)[i];
    adaptation_states[i] = ((cmsFloat64Number *)adaptation_states_data)[i];
  }

  // Create profiles for the fuzzing process.
  for (cmsUInt32Number i = 0; i < n_profiles; i++) {
    // Use a slice of the original fuzzer data to create a profile.
    // This increases the chances of finding parsing bugs in the profile creation.
    const uint8_t *profile_data = orig_data;
    size_t profile_size = orig_size;
    if (orig_size > (i + 1) * 100) {
        profile_data += i * 100;
        profile_size = 100;
    }
    h_profiles[i] = cmsOpenProfileFromMem(profile_data, profile_size);
    if (!h_profiles[i]) {
      // If profile creation fails, create a placeholder to continue fuzzing.
      h_profiles[i] = cmsCreate_sRGBProfile();
    }
  }

  // Fuzz the target functions.
  cmsPipeline *pipeline = _cmsDefaultICCintents(NULL, n_profiles, intents, h_profiles, bpc, adaptation_states, 0);
  if (pipeline) {
    cmsPipelineFree(pipeline);
  }

  cmsToneCurve *tone_curve = _cmsBuildKToneCurve(NULL, 256, n_profiles, intents, h_profiles, bpc, adaptation_states, 0);
  if (tone_curve) {
    cmsFreeToneCurve(tone_curve);
  }

  cmsHTRANSFORM transform = _cmsChain2Lab(NULL, n_profiles, TYPE_RGB_8, TYPE_Lab_8, intents, h_profiles, bpc, adaptation_states, 0);
  if (transform) {
    cmsDeleteTransform(transform);
  }

  cmsCIEXYZ black_point;
  if (h_profiles[0]) {
    cmsDetectDestinationBlackPoint(&black_point, h_profiles[0], intents[0], 0);
  }

  // Clean up all created profiles.
  for (cmsUInt32Number i = 0; i < n_profiles; i++) {
    if (h_profiles[i]) {
      cmsCloseProfile(h_profiles[i]);
    }
  }

  return 0;
}