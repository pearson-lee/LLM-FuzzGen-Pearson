#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/lcms/include/lcms2.h"

// Helper function to create a cmsToneCurve from fuzzer data.
// This function consumes data from the input buffer to create a tabulated tone curve.
// The number of entries is limited to a reasonable range to avoid excessive memory allocation.
static cmsToneCurve *create_tone_curve(const uint8_t **data, size_t *size) {
  if (*size < sizeof(uint32_t)) {
    return NULL;
  }
  // Consume data to determine the number of entries in the tone curve.
  uint32_t n_entries = *(const uint32_t *)*data;
  *data += sizeof(uint32_t);
  *size -= sizeof(uint32_t);

  // Limit the number of entries to a reasonable value (2 to 257) to prevent OOM.
  n_entries = (n_entries % 256) + 2;

  if (*size < n_entries * sizeof(cmsUInt16Number)) {
    return NULL;
  }

  // Consume data for the tone curve table.
  const cmsUInt16Number *table = (const cmsUInt16Number *)*data;
  *data += n_entries * sizeof(cmsUInt16Number);
  *size -= n_entries * sizeof(cmsUInt16Number);

  // Create the tone curve. The context is NULL, so the default context is used.
  cmsToneCurve *curve = cmsBuildTabulatedToneCurve16(NULL, n_entries, table);
  return curve;
}

// The main fuzzing function.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Create a context for all lcms operations.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  const uint8_t *orig_data = data;
  size_t orig_size = size;

  // --- Target 1: cmsCreateGrayProfileTHR ---
  if (size > sizeof(cmsCIExyY)) {
    const cmsCIExyY *white_point = (const cmsCIExyY *)data;
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);
    // Create a tone curve from fuzzer data.
    cmsToneCurve *gray_gamma = create_tone_curve(&data, &size);
    if (gray_gamma != NULL) {
      // Create a gray profile using the generated tone curve.
      cmsHPROFILE gray_profile = cmsCreateGrayProfileTHR(ctx, white_point, gray_gamma);
      if (gray_profile != NULL) {
        // Clean up the created profile.
        cmsCloseProfile(gray_profile);
      }
      // Clean up the tone curve.
      cmsFreeToneCurve(gray_gamma);
    }
  }

  // Reset data pointer and size for the next target.
  data = orig_data;
  size = orig_size;

  // --- Target 2: cmsCreateLinearizationDeviceLinkTHR ---
  if (size > sizeof(uint32_t)) {
    // Determine the number of curves to create from fuzzer data.
    uint32_t num_curves = *(const uint32_t *)data % 4 + 1; // 1 to 4 curves
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    cmsToneCurve *curves[4] = {NULL, NULL, NULL, NULL};
    int created_curves = 0;
    for (uint32_t i = 0; i < num_curves; i++) {
      curves[i] = create_tone_curve(&data, &size);
      if (curves[i] != NULL) {
        created_curves++;
      }
    }

    if (created_curves > 0) {
      // Create a linearization device link profile with the generated curves.
      cmsHPROFILE lin_profile = cmsCreateLinearizationDeviceLinkTHR(ctx, cmsSigGrayData, curves);
      if (lin_profile != NULL) {
        cmsCloseProfile(lin_profile);
      }
    }

    // Clean up all created tone curves.
    for (int i = 0; i < 4; i++) {
      if (curves[i]) {
        cmsFreeToneCurve(curves[i]);
      }
    }
  }

  data = orig_data;
  size = orig_size;

  // --- Target 3: cmsCreateInkLimitingDeviceLinkTHR ---
  if (size > sizeof(double)) {
    // Use fuzzer data for the ink limit.
    double limit = *(const double *)data;
    // Create an ink limiting device link profile.
    cmsHPROFILE ink_limit_profile = cmsCreateInkLimitingDeviceLinkTHR(ctx, cmsSigCmykData, limit);
    if (ink_limit_profile != NULL) {
      cmsCloseProfile(ink_limit_profile);
    }
  }

  data = orig_data;
  size = orig_size;

  // --- Target 4: cmsTransform2DeviceLink ---
  // Create standard profiles to build a transform.
  cmsHPROFILE srgb_profile = cmsCreate_sRGBProfileTHR(ctx);
  cmsHPROFILE lab_profile = cmsCreateLab4ProfileTHR(ctx, NULL);

  if (srgb_profile != NULL && lab_profile != NULL) {
    // Create a transform between the two profiles.
    cmsHTRANSFORM xform = cmsCreateTransformTHR(ctx, srgb_profile, TYPE_RGB_8, lab_profile, TYPE_Lab_DBL, INTENT_PERCEPTUAL, 0);
    if (xform != NULL) {
      if (size > sizeof(uint32_t)) {
        // Use fuzzer data for the version number.
        uint32_t version = *(const uint32_t *)data;
        // Convert the transform to a device link profile.
        cmsHPROFILE devicelink = cmsTransform2DeviceLink(xform, (double)version / 100.0, 0);
        if (devicelink != NULL) {
          cmsCloseProfile(devicelink);
        }
      }
      cmsDeleteTransform(xform);
    }
  }
  // Clean up profiles.
  if (srgb_profile != NULL)
    cmsCloseProfile(srgb_profile);
  if (lab_profile != NULL)
    cmsCloseProfile(lab_profile);

  data = orig_data;
  size = orig_size;

  // --- Target 5: cmsCreateBCHSWabstractProfileTHR ---
  if (size > sizeof(uint32_t) + 4 * sizeof(double) + sizeof(cmsCIEXYZ)) {
    // Consume data for the function parameters.
    uint32_t n_channels = *(const uint32_t *)data % 16 + 1;
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    double brightness = *(const double *)data;
    data += sizeof(double);
    size -= sizeof(double);
    double contrast = *(const double *)data;
    data += sizeof(double);
    size -= sizeof(double);
    double hue = *(const double *)data;
    data += sizeof(double);
    size -= sizeof(double);
    double saturation = *(const double *)data;
    data += sizeof(double);
    size -= sizeof(double);

    const cmsCIEXYZ *white_point = (const cmsCIEXYZ *)data;

    // Create the abstract profile.
    cmsHPROFILE bchsw_profile = cmsCreateBCHSWabstractProfileTHR(ctx, n_channels, brightness, contrast, hue, saturation, white_point, 5000.0);
    if (bchsw_profile != NULL) {
      cmsCloseProfile(bchsw_profile);
    }
  }

  // Clean up the context, which frees all associated memory.
  cmsDeleteContext(ctx);
  return 0;
}