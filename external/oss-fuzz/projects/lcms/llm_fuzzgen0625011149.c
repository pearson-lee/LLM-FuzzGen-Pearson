#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

// Define the macro for the fuzzer name if it's not already defined.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0625004703"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 40) {
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

  /*
   * ANALYSIS: The function-level coverage report showed cmsSetHeaderManufacturer and cmsSetHeaderModel had zero coverage.
   * IMPLEMENTATION: The following code block calls these functions to set the manufacturer and model
   *                 in the profile header, using data from the fuzzer.
   */
  if (size > 8) {
    cmsSetHeaderManufacturer(input_profile, *(uint32_t *)(data + 4));
    cmsSetHeaderModel(input_profile, *(uint32_t *)(data + 8));
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
     * ANALYSIS: The function-level coverage report showed cmsDoTransformStride had zero coverage.
     * IMPLEMENTATION: The following code block calls this function with simple parameters to exercise it.
     *                 It's a variant of cmsDoTransform with stride parameters.
     */
    cmsDoTransformStride(transform, input_buffer, output_buffer, 1, 3);

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

  /*
   * ANALYSIS: The function-level coverage report showed that all functions in cmscam02.c were uncovered.
   * IMPLEMENTATION: The following block calls cmsCIECAM02Init, cmsCIECAM02Forward, and cmsCIECAM02Reverse
   *                 to exercise the CIECAM02 color appearance model.
   */
  cmsViewingConditions vc;
  // Use a portion of the fuzzing data to populate the viewing conditions
  if (size > 36) {
    vc.whitePoint.X = *(double *)(data + 20);
    vc.whitePoint.Y = *(double *)(data + 28);
    vc.whitePoint.Z = 1.0; // Z is often 1.0
    vc.La = 10.0;
    vc.Yb = 20.0;
    vc.surround = 1;
    void *cam = cmsCIECAM02Init(context, &vc);
    if (cam) {
      cmsCIEXYZ in_xyz = {0.3, 0.4, 0.5};
      cmsJCh out_jch;
      cmsCIECAM02Forward(cam, &in_xyz, &out_jch);
      cmsCIECAM02Reverse(cam, &out_jch, &in_xyz);
      cmsCIECAM02Done(cam);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsWhitePointFromTemp and cmsTempFromWhitePoint were uncovered.
   * IMPLEMENTATION: The following block calls these functions to exercise white point temperature conversions.
   */
  cmsCIExyY white_point;
  if (cmsWhitePointFromTemp(&white_point, 5000)) {
    cmsFloat64Number temp;
    cmsTempFromWhitePoint(&temp, &white_point);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsAdaptToIlluminant was uncovered.
   * IMPLEMENTATION: The following block calls this function to exercise chromatic adaptation.
   */
  if (size > sizeof(cmsCIEXYZ) * 2 + sizeof(cmsMAT3)) {
    cmsCIEXYZ src_wp, dst_wp, result_wp;
    cmsMAT3 adapt_matrix;
    memcpy(&src_wp, data, sizeof(cmsCIEXYZ));
    memcpy(&dst_wp, data + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
    memcpy(&adapt_matrix, data + sizeof(cmsCIEXYZ) * 2, sizeof(cmsMAT3));
    cmsAdaptToIlluminant(&result_wp, &src_wp, &dst_wp, &adapt_matrix);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsMLUsetUTF8 and cmsMLUgetUTF8 were uncovered.
   * IMPLEMENTATION: The following block creates a multi-lingual unicode object, sets a UTF-8 string,
   *                 and then reads it back.
   */
  cmsMLU *mlu = cmsMLUalloc(context, 1);
  if (mlu) {
    // Use a small part of the input as a UTF-8 string.
    char utf8_string[257];
    size_t utf8_len = size > sizeof(utf8_string) - 1 ? sizeof(utf8_string) - 1 : size;
    memcpy(utf8_string, data, utf8_len);
    utf8_string[utf8_len] = '\0';
    cmsMLUsetUTF8(mlu, "en", "US", utf8_string);
    char buffer[256];
    cmsMLUgetUTF8(mlu, "en", "US", buffer, sizeof(buffer));
    cmsMLUfree(mlu);
  }

  /*
   * ANALYSIS: The function-level coverage report showed all functions in cmsps2.c were uncovered.
   * IMPLEMENTATION: The following block calls cmsGetPostScriptColorResource to generate PostScript
   *                 output, exercising the functions in cmsps2.c. It uses a temporary file for the output.
   */
  char ps_path[256];
  snprintf(ps_path, sizeof(ps_path), "/tmp/%s.ps", _FUZZ_TARGET_NAME);
  cmsIOHANDLER *io = cmsOpenIOhandlerFromFile(context, ps_path, "w");
  if (io) {
    cmsGetPostScriptColorResource(context, cmsPS_RESOURCE_CRD, input_profile, 0, 0, io);
    cmsCloseIOhandler(io);
    unlink(ps_path);
  }

  // Clean up.
  cmsCloseProfile(input_profile);
  cmsCloseProfile(output_profile);
  cmsCloseProfile(proofing_profile);
  cmsDeleteContext(context);

  return 0;
}