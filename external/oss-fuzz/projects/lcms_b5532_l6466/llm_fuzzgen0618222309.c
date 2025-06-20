#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Helper to safely consume data from the fuzzing input.
// Returns a pointer to the consumed data, or NULL if not enough data is available.
// Advances the data pointer and decrements the size.
static const uint8_t *consume_data(const uint8_t **data, size_t *size, size_t len) {
  if (*size < len) {
    return NULL;
  }
  const uint8_t *ptr = *data;
  *data += len;
  *size -= len;
  return ptr;
}

// Fuzz target entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Initialize all resource handles to NULL for safe cleanup
  cmsContext context = NULL;
  cmsContext dup_context = NULL;
  cmsToneCurve *gamma1 = NULL;
  cmsToneCurve *gamma2 = NULL;
  cmsToneCurve *joined_curve = NULL;
  cmsHPROFILE rgb_profile = NULL;
  cmsHPROFILE lab_profile = NULL;
  cmsHPROFILE proof_profile = NULL;
  cmsHTRANSFORM transform = NULL;
  cmsHANDLE it8 = NULL;

  // Create a context for all lcms operations.
  context = cmsCreateContext(NULL, NULL);
  if (!context) {
    goto cleanup;
  }

  // Added call to cmsDupContext to improve coverage.
  dup_context = cmsDupContext(context, NULL);
  if (!dup_context) {
    goto cleanup;
  }

  // Consume data for two gamma values to build tone curves.
  const uint8_t *gamma_data = consume_data(&data, &size, sizeof(double) * 2);
  if (!gamma_data) {
    goto cleanup;
  }
  double gamma1_val, gamma2_val;
  memcpy(&gamma1_val, gamma_data, sizeof(double));
  memcpy(&gamma2_val, gamma_data + sizeof(double), sizeof(double));

  // Create two tone curves from the fuzzed gamma values.
  gamma1 = cmsBuildGamma(context, gamma1_val);
  gamma2 = cmsBuildGamma(context, gamma2_val);
  if (!gamma1 || !gamma2) {
    goto cleanup;
  }

  // Consume data for the number of points for joining curves.
  const uint8_t *points_data = consume_data(&data, &size, sizeof(uint32_t));
  if (!points_data) {
    goto cleanup;
  }
  uint32_t num_points;
  memcpy(&num_points, points_data, sizeof(uint32_t));

  // API 1: cmsJoinToneCurve
  // Join the two tone curves to create a new one.
  joined_curve = cmsJoinToneCurve(context, gamma1, gamma2, num_points % 4096 + 1);
  if (!joined_curve) {
    goto cleanup;
  }

  // Consume data for white point and primaries for the RGB profile.
  const uint8_t *profile_data = consume_data(&data, &size, sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE));
  if (!profile_data) {
    goto cleanup;
  }
  cmsCIExyY white_point;
  cmsCIExyYTRIPLE primaries;
  memcpy(&white_point, profile_data, sizeof(cmsCIExyY));
  memcpy(&primaries, profile_data + sizeof(cmsCIExyY), sizeof(cmsCIExyYTRIPLE));

  cmsToneCurve *curves[3] = {joined_curve, joined_curve, joined_curve};

  // API 2: cmsCreateRGBProfile
  // Create a virtual RGB profile using the fuzzed white point, primaries, and the joined tone curve.
  rgb_profile = cmsCreateRGBProfile(&white_point, &primaries, curves);
  if (!rgb_profile) {
    goto cleanup;
  }

  // Added call to cmsMD5computeID to improve coverage in cmsmd5.c
  cmsMD5computeID(rgb_profile);

  // API 3: cmsDetectTAC
  // Detect the Total Area Coverage (TAC) of the created profile.
  cmsDetectTAC(rgb_profile);

  // Create a Lab profile to be used in the proofing transform.
  lab_profile = cmsCreateLab4Profile(NULL);
  if (!lab_profile) {
    goto cleanup;
  }

  // Create an sRGB profile to be used as the proofing device.
  proof_profile = cmsCreate_sRGBProfile();
  if (!proof_profile) {
    goto cleanup;
  }

  // Consume data for intents and flags for the proofing transform.
  const uint8_t *transform_data = consume_data(&data, &size, sizeof(uint32_t) * 3);
  if (!transform_data) {
    goto cleanup;
  }
  uint32_t intent, proofing_intent, flags;
  memcpy(&intent, transform_data, sizeof(uint32_t));
  memcpy(&proofing_intent, transform_data + sizeof(uint32_t), sizeof(uint32_t));
  memcpy(&flags, transform_data + 2 * sizeof(uint32_t), sizeof(uint32_t));

  // API 4: cmsCreateProofingTransform
  // Create a proofing transform using the created profiles and fuzzed parameters.
  transform = cmsCreateProofingTransform(rgb_profile, TYPE_RGB_8, lab_profile, TYPE_Lab_8, proof_profile, intent % 16, proofing_intent % 16, flags);

  // IT8 (Color Measurement Data) handling.
  it8 = cmsIT8Alloc(context);
  if (it8) {
    const uint8_t *it8_data = consume_data(&data, &size, 21);
    if (it8_data) {
      char key1[6];
      char key2[6];
      char value[11];
      memcpy(key1, it8_data, 5);
      key1[5] = '\0';
      memcpy(key2, it8_data + 5, 5);
      key2[5] = '\0';
      memcpy(value, it8_data + 10, 10);
      value[10] = '\0';
      // API 5: cmsIT8SetData
      // Set data in the IT8 handle using fuzzed keys and value.
      cmsIT8SetData(it8, key1, key2, value);
      // Added call to cmsIT8SetDataDbl to improve coverage.
      const uint8_t *dbl_data = consume_data(&data, &size, sizeof(double));
      if (dbl_data) {
        double dbl_val;
        memcpy(&dbl_val, dbl_data, sizeof(double));
        cmsIT8SetDataDbl(it8, key1, key2, dbl_val);
      }
    }
  }

cleanup:
  // Free all allocated resources to prevent memory leaks.
  // This block is executed regardless of where the function exits.
  if (it8)
    cmsIT8Free(it8);
  if (transform)
    cmsDeleteTransform(transform);
  if (proof_profile)
    cmsCloseProfile(proof_profile);
  if (lab_profile)
    cmsCloseProfile(lab_profile);
  if (rgb_profile)
    cmsCloseProfile(rgb_profile);
  if (joined_curve)
    cmsFreeToneCurve(joined_curve);
  if (gamma2)
    cmsFreeToneCurve(gamma2);
  if (gamma1)
    cmsFreeToneCurve(gamma1);
  // Added cleanup for duplicated context to prevent memory leaks.
  if (dup_context)
    cmsDeleteContext(dup_context);
  if (context)
    cmsDeleteContext(context);

  return 0;
}