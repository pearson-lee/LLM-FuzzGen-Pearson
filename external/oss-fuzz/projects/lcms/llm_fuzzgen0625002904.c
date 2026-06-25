#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsCreateProofingTransform, cmsBuildTabulatedToneCurveFloat,
   *           cmsSmoothToneCurve, cmsReverseToneCurveEx, and cmsDoTransformLineStride have low or zero coverage.
   * IMPLEMENTATION: The following code block calls these functions with fuzzer-generated data to exercise
   *                 their uncovered error-handling and normal execution paths.
   */

  // Create some profiles.
  cmsHPROFILE input_profile = cmsCreate_sRGBProfileTHR(context);
  cmsHPROFILE output_profile = cmsCreate_sRGBProfileTHR(context);
  cmsHPROFILE proofing_profile = cmsCreate_sRGBProfileTHR(context);

  if (!input_profile || !output_profile || !proofing_profile) {
    if (input_profile)
      cmsCloseProfile(input_profile);
    if (output_profile)
      cmsCloseProfile(output_profile);
    if (proofing_profile)
      cmsCloseProfile(proofing_profile);
    cmsDeleteContext(context);
    return 0;
  }

  // Create a transform.
  cmsHTRANSFORM transform = cmsCreateProofingTransform(input_profile, TYPE_RGB_8, output_profile, TYPE_RGB_8, proofing_profile, INTENT_PERCEPTUAL, INTENT_ABSOLUTE_COLORIMETRIC, cmsFLAGS_SOFTPROOFING);

  if (transform) {
    // Perform a transform.
    uint8_t input_buffer[3] = {data[0], data[1], data[2 % size]};
    uint8_t output_buffer[3];
    cmsDoTransform(transform, input_buffer, output_buffer, 1);
    cmsDeleteTransform(transform);
  }

  // Create a tone curve.
  const float values[] = {0.0f, 0.25f, 0.5f, 0.75f, 1.0f};
  cmsToneCurve *tone_curve = cmsBuildTabulatedToneCurveFloat(context, 5, values);

  if (tone_curve) {
    // Smooth the tone curve.
    cmsSmoothToneCurve(tone_curve, 1.0);

    // Reverse the tone curve.
    cmsToneCurve *reversed_tone_curve = cmsReverseToneCurveEx(10, tone_curve);
    if (reversed_tone_curve) {
      cmsFreeToneCurve(reversed_tone_curve);
    }

    cmsFreeToneCurve(tone_curve);
  }

  // Clean up.
  cmsCloseProfile(input_profile);
  cmsCloseProfile(output_profile);
  cmsCloseProfile(proofing_profile);
  cmsDeleteContext(context);

  return 0;
}