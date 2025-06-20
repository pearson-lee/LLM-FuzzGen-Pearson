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

  // Using valid primaries to ensure cmsCreateRGBProfile succeeds, which is required for cmsTransform2DeviceLink coverage.
  cmsCIExyYTRIPLE primaries = {
      {0.6400, 0.3300, 1.0}, // Red
      {0.3000, 0.6000, 1.0}, // Green
      {0.1500, 0.0600, 1.0}  // Blue
  };

  // Create various profiles to be used in the transform.
  // Target 3: cmsCreateGrayProfile
  cmsHPROFILE in_profile = cmsCreateGrayProfile(&white_point, gamma_curve);
  // Target 4: cmsCreateRGBProfile
  cmsHPROFILE out_profile = cmsCreateRGBProfile(&white_point, &primaries, gamma_curves);
  // Target 5: cmsCreateNULLProfile
  cmsHPROFILE null_profile = cmsCreateNULLProfile();

  // Added call to cmsCreateLinearizationDeviceLink based on coverage report.
  // This profile must be closed to prevent memory leaks.
  cmsHPROFILE linearization_profile = cmsCreateLinearizationDeviceLink(cmsSigRgbData, (const cmsToneCurve **)&gamma_curves);
  if (linearization_profile) {
    cmsCloseProfile(linearization_profile);
  }

  // Added call to cmsCreateLab2Profile based on coverage report.
  // This profile must be closed to prevent memory leaks.
  cmsHPROFILE lab2_profile = cmsCreateLab2Profile(&white_point);
  if (lab2_profile) {
    cmsCloseProfile(lab2_profile);
  }

  // Added call to cmsCreateBCHSWabstractProfile based on coverage report.
  // This profile must be closed to prevent memory leaks.
  cmsHPROFILE bchsw_profile = cmsCreateBCHSWabstractProfile(CONSUME_T(&f, cmsUInt32Number), CONSUME_T(&f, cmsFloat64Number), CONSUME_T(&f, cmsFloat64Number), CONSUME_T(&f, cmsFloat64Number), CONSUME_T(&f, cmsFloat64Number), CONSUME_T(&f, cmsUInt32Number), CONSUME_T(&f, cmsUInt32Number));
  if (bchsw_profile) {
    cmsCloseProfile(bchsw_profile);
  }

  // Added call to cmsCreate_OkLabProfile based on coverage report.
  // This profile must be closed to prevent memory leaks.
  cmsHPROFILE oklab_profile = cmsCreate_OkLabProfile(ctx);
  if (oklab_profile) {
    cmsCloseProfile(oklab_profile);
  }

  // Added calls to IT8 API to improve coverage of cmscgats.c.
  // All resources are properly freed to prevent memory leaks.
  cmsHANDLE it8 = cmsIT8Alloc(ctx);
  if (it8) {
    cmsIT8SetSheetType(it8, "LCMS_IT8_V2");
    cmsIT8SetPropertyDbl(it8, "NUMBER_OF_FIELDS", 3);
    cmsIT8SetDataFormat(it8, 0, "SAMPLE_ID");
    cmsIT8SetDataFormat(it8, 1, "RGB_R");
    cmsIT8SetDataFormat(it8, 2, "RGB_G");
    cmsIT8SetDataRowColDbl(it8, 0, 0, 1.0);

    // Save to memory to exercise the writing functions.
    // The memory is allocated and freed to prevent leaks.
    size_t required_bytes = 0;
    if (cmsIT8SaveToMem(it8, NULL, &required_bytes)) {
      void *mem = malloc(required_bytes);
      if (mem) {
        cmsIT8SaveToMem(it8, mem, &required_bytes);
        free(mem);
      }
    }
    // Added call to cmsIT8SaveToFile to improve coverage of file I/O functions in cmscgats.c
    cmsIT8SaveToFile(it8, "/tmp/fuzz.it8");
    cmsIT8Free(it8);
  }

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

  if (in_profile) {
    // Added calls to cmsGetProfileInfoASCII to improve coverage of profile metadata functions.
    char info_buffer[128];
    cmsGetProfileInfoASCII(in_profile, cmsInfoDescription, "en", "US", info_buffer, sizeof(info_buffer));
    cmsGetProfileInfoASCII(in_profile, cmsInfoManufacturer, "en", "US", info_buffer, sizeof(info_buffer));
    cmsGetProfileInfoASCII(in_profile, cmsInfoModel, "en", "US", info_buffer, sizeof(info_buffer));
    cmsGetProfileInfoASCII(in_profile, cmsInfoCopyright, "en", "US", info_buffer, sizeof(info_buffer));
    // Added call to cmsMD5computeID to improve coverage of cmsmd5.c
    cmsMD5computeID(in_profile);
  }

  if (null_profile) {
    // Added calls to cmsWriteRawTag and cmsReadRawTag to improve coverage of raw tag handling.
    cmsTagSignature tag_sig = (cmsTagSignature)CONSUME_T(&f, uint32_t);
    uint8_t tag_data_buffer[32];
    memcpy(tag_data_buffer, FuzzDataConsume(&f, sizeof(tag_data_buffer)), sizeof(tag_data_buffer));
    if (cmsWriteRawTag(null_profile, tag_sig, tag_data_buffer, sizeof(tag_data_buffer))) {
      uint8_t read_buffer[32];
      cmsReadRawTag(null_profile, tag_sig, read_buffer, sizeof(read_buffer));
    }

    // Added call to cmsLinkTag to improve coverage of tag linking functionality.
    cmsTagSignature sig1 = (cmsTagSignature)CONSUME_T(&f, uint32_t);
    cmsTagSignature sig2 = (cmsTagSignature)CONSUME_T(&f, uint32_t);
    cmsLinkTag(null_profile, sig1, sig2);
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

  // Added calls to save and open profile from file to improve coverage of file I/O functions in cmsio0.c
  if (out_profile) {
    const char *temp_profile_path = "/tmp/fuzz_profile.icc";
    if (cmsSaveProfileToFile(out_profile, temp_profile_path)) {
      cmsHPROFILE opened_profile = cmsOpenProfileFromFile(temp_profile_path, "r");
      if (opened_profile) {
        cmsCloseProfile(opened_profile);
      }
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