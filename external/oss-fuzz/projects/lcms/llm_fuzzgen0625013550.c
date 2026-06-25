#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

// Define the macro for the fuzzer name if it's not already defined.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "llm_fuzzgen0625012804"
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
   * ANALYSIS: The function-level coverage report showed cmsDupContext in cmsplugin.c had zero coverage.
   * IMPLEMENTATION: The following block calls cmsDupContext to exercise the context duplication logic.
   *                 The duplicated context is immediately freed to prevent memory leaks.
   */
  cmsContext dup_context = cmsDupContext(context, NULL);
  if (dup_context) {
    cmsDeleteContext(dup_context);
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
   * ANALYSIS: The function-level coverage report showed several header accessor functions in cmsio0.c had zero coverage.
   * IMPLEMENTATION: The following code block calls these functions to set and get various header fields,
   *                 such as manufacturer, model, flags, attributes, and profile ID.
   */
  if (size > 16) {
    cmsSetHeaderManufacturer(input_profile, *(uint32_t *)(data + 4));
    cmsSetHeaderModel(input_profile, *(uint32_t *)(data + 8));
    cmsGetHeaderManufacturer(input_profile);
    cmsGetHeaderModel(input_profile);
    cmsSetHeaderFlags(input_profile, *(uint32_t *)(data + 12));
    cmsGetHeaderFlags(input_profile);
    cmsSetHeaderAttributes(input_profile, *(uint64_t *)(data));
    cmsUInt64Number header_attributes;
    cmsGetHeaderAttributes(input_profile, &header_attributes);
    cmsUInt8Number profile_id[16];
    memcpy(profile_id, data, 16);
    cmsSetHeaderProfileID(input_profile, profile_id);
    cmsGetHeaderProfileID(input_profile, profile_id);
    cmsGetHeaderCreator(input_profile);
    cmsGetHeaderRenderingIntent(input_profile);
  }

  cmsHTRANSFORM transform = cmsCreateProofingTransform(input_profile, TYPE_RGB_8, output_profile, TYPE_RGB_8, proofing_profile, INTENT_PERCEPTUAL, INTENT_ABSOLUTE_COLORIMETRIC, cmsFLAGS_SOFTPROOFING);

  if (transform) {
    uint8_t input_buffer[3] = {data[0], data[1], data[2]};
    uint8_t output_buffer[3];
    cmsDoTransform(transform, input_buffer, output_buffer, 1);
    cmsDoTransformLineStride(transform, input_buffer, output_buffer, 1, 1, 3, 3, 0, 0);
    cmsDoTransformStride(transform, input_buffer, output_buffer, 1, 3);
    if (size > 8) {
      cmsChangeBuffersFormat(transform, data[4], data[5]);
    }
    cmsDeleteTransform(transform);
  }
  
  cmsHTRANSFORM extra_channels_transform = cmsCreateProofingTransform(input_profile, TYPE_RGBA_8, output_profile, TYPE_RGBA_8, proofing_profile, INTENT_PERCEPTUAL, INTENT_ABSOLUTE_COLORIMETRIC, cmsFLAGS_COPY_ALPHA);
  if (extra_channels_transform) {
    uint8_t input_buffer[4] = {data[0], data[1], data[2], data[3]};
    uint8_t output_buffer[4];
    cmsDoTransform(extra_channels_transform, input_buffer, output_buffer, 1);
    cmsDeleteTransform(extra_channels_transform);
  }

  cmsHPROFILE profiles[] = {input_profile, output_profile};
  cmsHTRANSFORM multi_transform = cmsCreateMultiprofileTransform(profiles, 2, TYPE_RGB_8, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
  if (multi_transform) {
    uint8_t input_buffer[3] = {data[0], data[1], data[2]};
    uint8_t output_buffer[3];
    cmsDoTransform(multi_transform, input_buffer, output_buffer, 1);
    cmsDeleteTransform(multi_transform);
  }

  if (size >= sizeof(float) * 5) {
    float values[5];
    memcpy(values, data, sizeof(values));
    cmsToneCurve *tone_curve = cmsBuildTabulatedToneCurveFloat(context, 5, values);

    if (tone_curve) {
      cmsSmoothToneCurve(tone_curve, 1.0);
      cmsIsToneCurveMonotonic(tone_curve);
      cmsGetToneCurveParametricType(tone_curve);

      cmsToneCurve *reversed_tone_curve = cmsReverseToneCurveEx(10, tone_curve);
      if (reversed_tone_curve) {
        cmsToneCurve *joined_curve = cmsJoinToneCurve(context, tone_curve, reversed_tone_curve, 256);
        if (joined_curve) {
          cmsFreeToneCurve(joined_curve);
        }
        cmsFreeToneCurve(reversed_tone_curve);
      }

      cmsFreeToneCurve(tone_curve);
    }
  }

  if (size > 36) {
    cmsViewingConditions vc;
    vc.whitePoint.X = *(double *)(data + 20);
    vc.whitePoint.Y = *(double *)(data + 28);
    vc.whitePoint.Z = 1.0; 
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

  cmsCIExyY white_point;
  if (cmsWhitePointFromTemp(&white_point, 5000)) {
    cmsFloat64Number temp;
    cmsTempFromWhitePoint(&temp, &white_point);
  }

  cmsCIEXYZ src_wp, dst_wp, result_wp;
  cmsMAT3 adapt_matrix;
  if (size >= sizeof(cmsCIEXYZ) * 2 + sizeof(cmsMAT3)) {
    memcpy(&src_wp, data, sizeof(cmsCIEXYZ));
    memcpy(&dst_wp, data + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
    memcpy(&adapt_matrix, data + sizeof(cmsCIEXYZ) * 2, sizeof(cmsMAT3));
  } else {
    memset(&src_wp, 0, sizeof(cmsCIEXYZ));
    memset(&dst_wp, 0, sizeof(cmsCIEXYZ));
    memset(&adapt_matrix, 0, sizeof(cmsMAT3));
  }
  cmsAdaptToIlluminant(&result_wp, &src_wp, &dst_wp, &adapt_matrix);

  cmsMLU *mlu = cmsMLUalloc(context, 1);
  if (mlu) {
    char utf8_string[257];
    size_t utf8_len = size > sizeof(utf8_string) - 1 ? sizeof(utf8_string) - 1 : size;
    memcpy(utf8_string, data, utf8_len);
    utf8_string[utf8_len] = '\0';
    cmsMLUsetUTF8(mlu, "en", "US", utf8_string);
    char buffer[256];
    cmsMLUgetUTF8(mlu, "en", "US", buffer, sizeof(buffer));
    cmsMLUfree(mlu);
  }

  char ps_path[256];
  snprintf(ps_path, sizeof(ps_path), "/tmp/%s.ps", _FUZZ_TARGET_NAME);
  cmsIOHANDLER *io = cmsOpenIOhandlerFromFile(context, ps_path, "w");
  if (io) {
    cmsGetPostScriptColorResource(context, cmsPS_RESOURCE_CRD, input_profile, 0, 0, io);
    cmsCloseIOhandler(io);
    unlink(ps_path);
  }
  
  cmsCIEXYZ black_point;
  cmsDetectDestinationBlackPoint(&black_point, input_profile, INTENT_PERCEPTUAL, 0);

  if (size >= sizeof(double)) {
    double limit = *(double *)data;
    cmsHPROFILE ink_limit_profile = cmsCreateInkLimitingDeviceLink(cmsSigCmykData, limit);
    if (ink_limit_profile) {
      cmsCloseProfile(ink_limit_profile);
    }
  }

  cmsDetectTAC(input_profile);

  /*
   * ANALYSIS: The function-level coverage report showed cmsGetProfileInfo in cmsio1.c was uncovered.
   * IMPLEMENTATION: The following block calls cmsGetProfileInfo with various info types to exercise
   *                 the profile info reading logic.
   */
  wchar_t wbuffer[128];
  cmsGetProfileInfo(input_profile, cmsInfoDescription, "en", "US", wbuffer, sizeof(wbuffer));
  cmsGetProfileInfo(input_profile, cmsInfoManufacturer, "en", "US", wbuffer, sizeof(wbuffer));
  cmsGetProfileInfo(input_profile, cmsInfoModel, "en", "US", wbuffer, sizeof(wbuffer));
  cmsGetProfileInfo(input_profile, cmsInfoCopyright, "en", "US", wbuffer, sizeof(wbuffer));

  /*
   * ANALYSIS: The function-level coverage report showed cmsSaveProfileToMem in cmsio0.c was uncovered.
   * IMPLEMENTATION: The following block calls cmsSaveProfileToMem to exercise the logic for saving a
   *                 profile to a memory buffer. It first determines the required size, then allocates
   *                 and saves. The buffer is freed immediately.
   */
  cmsUInt32Number bytes_needed = 0;
  cmsSaveProfileToMem(input_profile, NULL, &bytes_needed);
  if (bytes_needed > 0) {
    void *buffer = malloc(bytes_needed);
    if (buffer) {
      cmsSaveProfileToMem(input_profile, buffer, &bytes_needed);
      free(buffer);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the cmsDict* family of
   *           functions in cmsnamed.c were uncovered.
   * IMPLEMENTATION: The following block calls cmsDictAlloc, cmsDictAddEntry, cmsDictDup,
   *                 and cmsDictFree to exercise the dictionary API. Fuzzer data is used
   *                 to create a key-value pair.
   */
  cmsHANDLE dict = cmsDictAlloc(context);
  if (dict) {
    if (size > 16) {
      char key[9];
      char value[9];
      memcpy(key, data, 8);
      key[8] = '\0';
      memcpy(value, data + 8, 8);
      value[8] = '\0';
      wchar_t wkey[9];
      wchar_t wvalue[9];
      mbstowcs(wkey, key, 9);
      mbstowcs(wvalue, value, 9);
      cmsDictAddEntry(dict, wkey, wvalue, NULL, NULL);
    }
    cmsHANDLE dup_dict = cmsDictDup(dict);
    if (dup_dict) {
      cmsDictFree(dup_dict);
    }
    cmsDictFree(dict);
  }

  // Clean up.
  cmsCloseProfile(input_profile);
  cmsCloseProfile(output_profile);
  cmsCloseProfile(proofing_profile);
  cmsDeleteContext(context);

  return 0;
}