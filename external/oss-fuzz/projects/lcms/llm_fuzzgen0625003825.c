#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsSetAlarmCodes and cmsGetAlarmCodes had zero coverage.
   * IMPLEMENTATION: The following code block calls these functions to set and then get alarm codes,
   *                 using data from the fuzzer to populate the codes.
   */
  uint16_t alarm_codes[16];
  if (size >= sizeof(alarm_codes)) {
    memcpy(alarm_codes, data, sizeof(alarm_codes));
    cmsSetAlarmCodes(alarm_codes);
    cmsGetAlarmCodes(alarm_codes);
  }

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

  cmsHTRANSFORM transform = cmsCreateProofingTransform(input_profile, TYPE_RGB_8, output_profile, TYPE_RGB_8, proofing_profile, INTENT_PERCEPTUAL, INTENT_ABSOLUTE_COLORIMETRIC, cmsFLAGS_SOFTPROOFING);

  if (transform) {
    uint8_t input_buffer[3] = {data[0], data[1], data[2]};
    uint8_t output_buffer[3];
    cmsDoTransform(transform, input_buffer, output_buffer, 1);

    /*
     * ANALYSIS: The function-level coverage report showed cmsDoTransformLineStride had zero coverage.
     * IMPLEMENTATION: The following code block calls this function with simple parameters to exercise it.
     *                 The parameters are chosen for a single 3-byte pixel, similar to the cmsDoTransform call.
     */
    cmsDoTransformLineStride(transform, input_buffer, output_buffer, 1, 1, 3, 3, 0, 0);

    /*
     * ANALYSIS: The function-level coverage report showed cmsChangeBuffersFormat had zero coverage.
     * IMPLEMENTATION: The following code block calls this function to change the input and output
     *                 formats of the transform, using fuzzer data to select the new formats.
     */
    if (size > 8) {
        cmsChangeBuffersFormat(transform, data[4], data[5]);
    }

    cmsDeleteTransform(transform);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsCreateMultiprofileTransform had zero coverage.
   * IMPLEMENTATION: The following code block creates a multi-profile transform using the existing
   *                 input and output profiles. The resulting transform is used and then freed.
   */
  cmsHPROFILE profiles[] = {input_profile, output_profile};
  cmsHTRANSFORM multi_transform = cmsCreateMultiprofileTransform(profiles, 2, TYPE_RGB_8, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
  if (multi_transform) {
    uint8_t input_buffer[3] = {data[0], data[1], data[2]};
    uint8_t output_buffer[3];
    cmsDoTransform(multi_transform, input_buffer, output_buffer, 1);
    cmsDeleteTransform(multi_transform);
  }


  /*
   * ANALYSIS: The line-level coverage for cmsSmoothToneCurve showed that the smoothing logic
   *           was never executed because the provided tone curve was always linear. The function
   *           cmsIsToneCurveMonotonic was also un-exercised.
   * IMPLEMENTATION: A non-linear tone curve is created using 5 float values from the fuzzer input.
   *                 This allows cmsIsToneCurveLinear to return false, entering the smoothing path.
   *                 A call to cmsIsToneCurveMonotonic is also added.
   */
  float values[5];
  memcpy(values, data, sizeof(values));
  cmsToneCurve *tone_curve = cmsBuildTabulatedToneCurveFloat(context, 5, values);

  if (tone_curve) {
    cmsSmoothToneCurve(tone_curve, 1.0);
    cmsIsToneCurveMonotonic(tone_curve);
    
    /*
     * ANALYSIS: The function-level coverage report showed cmsGetToneCurveParametricType had zero coverage.
     * IMPLEMENTATION: The following code block calls this function on the created tone curve.
     */
    cmsGetToneCurveParametricType(tone_curve);

    cmsToneCurve *reversed_tone_curve = cmsReverseToneCurveEx(10, tone_curve);
    if (reversed_tone_curve) {
      /*
       * ANALYSIS: The function-level coverage report showed cmsJoinToneCurve has zero coverage.
       * IMPLEMENTATION: The following code block calls this function to join the original
       *                 tone curve and its reverse. The resulting curve is freed immediately.
       */
      cmsToneCurve *joined_curve = cmsJoinToneCurve(context, tone_curve, reversed_tone_curve, 256);
      if (joined_curve) {
        cmsFreeToneCurve(joined_curve);
      }
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