#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// A simple data provider to consume data from the fuzzer input.
typedef struct {
  const uint8_t *data;
  size_t size;
  size_t offset;
} FuzzData;

// Initializes the data provider.
static void FuzzDataInit(FuzzData *f, const uint8_t *data, size_t size) {
  f->data = data;
  f->size = size;
  f->offset = 0;
}

// Consumes 'size' bytes from the fuzz data.
// Returns a pointer to the data, or a static buffer if not enough data is available.
static const void *FuzzDataConsume(FuzzData *f, size_t size) {
  static const uint8_t dummy_data[4096] = {0};

  if (size > sizeof(dummy_data)) {
    size = sizeof(dummy_data);
  }

  if (f->offset + size > f->size) {
    return dummy_data;
  }

  const void *ptr = f->data + f->offset;
  f->offset += size;
  return ptr;
}

// Helper macro to consume a value of a specific type.
#define CONSUME_T(f, t) (*(const t *)FuzzDataConsume(f, sizeof(t)))

// The main fuzzing function.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzData f;
  FuzzDataInit(&f, data, size);

  // The context can be reused across multiple operations.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return 0;
  }

  // --- Target 1: cmsCreateInkLimitingDeviceLink ---
  // This function creates a device link profile for ink limiting.
  cmsColorSpaceSignature cs = (cmsColorSpaceSignature)CONSUME_T(&f, uint32_t);
  double limit = CONSUME_T(&f, double);
  cmsHPROFILE ink_limit_profile = cmsCreateInkLimitingDeviceLink(cs, limit);
  // All created profiles must be closed to avoid memory leaks.
  if (ink_limit_profile) {
    cmsCloseProfile(ink_limit_profile);
  }

  // --- Target 2: cmsTransform2DeviceLink ---
  // This requires creating profiles and a transform first.

  // Create building blocks for the profiles.
  cmsCIExyY white_point;
  memcpy(&white_point, FuzzDataConsume(&f, sizeof(white_point)), sizeof(white_point));

  cmsToneCurve *gamma_curve = cmsBuildGamma(ctx, CONSUME_T(&f, double));
  if (!gamma_curve) {
    cmsDeleteContext(ctx);
    return 0;
  }

  cmsToneCurve *gamma_curves[3];
  gamma_curves[0] = cmsBuildGamma(ctx, CONSUME_T(&f, double));
  gamma_curves[1] = cmsBuildGamma(ctx, CONSUME_T(&f, double));
  gamma_curves[2] = cmsBuildGamma(ctx, CONSUME_T(&f, double));
  if (!gamma_curves[0] || !gamma_curves[1] || !gamma_curves[2]) {
    cmsFreeToneCurve(gamma_curve);
    if (gamma_curves[0])
      cmsFreeToneCurve(gamma_curves[0]);
    if (gamma_curves[1])
      cmsFreeToneCurve(gamma_curves[1]);
    if (gamma_curves[2])
      cmsFreeToneCurve(gamma_curves[2]);
    cmsDeleteContext(ctx);
    return 0;
  }

  cmsCIExyYTRIPLE primaries;
  memcpy(&primaries, FuzzDataConsume(&f, sizeof(primaries)), sizeof(primaries));

  // Create various profiles to be used in the transform.
  // Target 3: cmsCreateGrayProfile
  cmsHPROFILE in_profile = cmsCreateGrayProfile(&white_point, gamma_curve);
  // Target 4: cmsCreateRGBProfile
  cmsHPROFILE out_profile = cmsCreateRGBProfile(&white_point, &primaries, gamma_curves);
  // Target 5: cmsCreateNULLProfile
  cmsHPROFILE null_profile = cmsCreateNULLProfile();

  // If profile creation fails, we are responsible for freeing the curves.
  // Otherwise, the profile takes ownership and they are freed with cmsCloseProfile.
  if (!in_profile) {
    cmsFreeToneCurve(gamma_curve);
  }
  if (!out_profile) {
    cmsFreeToneCurve(gamma_curves[0]);
    cmsFreeToneCurve(gamma_curves[1]);
    cmsFreeToneCurve(gamma_curves[2]);
  }

  if (in_profile && out_profile) {
    // Create a transform between the two profiles.
    cmsUInt32Number input_format = TYPE_GRAY_8;
    cmsUInt32Number output_format = TYPE_RGB_8;
    cmsUInt32Number intent = CONSUME_T(&f, cmsUInt32Number) & 0xF;
    cmsUInt32Number flags = CONSUME_T(&f, cmsUInt32Number);

    cmsHTRANSFORM transform = cmsCreateTransform(in_profile, input_format, out_profile, output_format, intent, flags);

    if (transform) {
      // Finally, call the target function cmsTransform2DeviceLink.
      double adaptation = CONSUME_T(&f, double);
      cmsUInt32Number devicelink_flags = CONSUME_T(&f, cmsUInt32Number);
      cmsHPROFILE devicelink_profile = cmsTransform2DeviceLink(transform, adaptation, devicelink_flags);

      // Clean up the created device link profile.
      if (devicelink_profile) {
        cmsCloseProfile(devicelink_profile);
      }
      // Clean up the transform.
      cmsDeleteTransform(transform);
    }
  }

  // Clean up all created profiles.
  if (in_profile)
    cmsCloseProfile(in_profile);
  if (out_profile)
    cmsCloseProfile(out_profile);
  if (null_profile)
    cmsCloseProfile(null_profile);

  // Clean up the context.
  cmsDeleteContext(ctx);

  return 0;
}