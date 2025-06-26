#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Helper structure to manage fuzzing data consumption.
typedef struct {
  const uint8_t *data;
  size_t size;
  size_t offset;
} FuzzData;

// Checks if there is enough data to consume.
static int FuzzHasData(FuzzData *f, size_t len) {
  return (f && f->offset + len <= f->size);
}

// Consumes a block of data of a given length.
static const void *FuzzConsume(FuzzData *f, size_t len) {
  if (!FuzzHasData(f, len)) {
    return NULL;
  }
  const void *ret = f->data + f->offset;
  f->offset += len;
  return ret;
}

// Consumes an integer from the fuzzing data.
static int FuzzConsumeInt(FuzzData *f) {
  const int *ret = FuzzConsume(f, sizeof(int));
  return ret ? *ret : 0;
}

// Consumes a tag signature from the fuzzing data.
static cmsTagSignature FuzzConsumeTagSignature(FuzzData *f) {
  const cmsTagSignature *ret = FuzzConsume(f, sizeof(cmsTagSignature));
  return ret ? *ret : 0;
}

// Fuzz target entry point.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzData fuzz_data = {data, size, 0};

  // This function has 0% coverage, so we call it here.
  cmsGetEncodedCMMversion();

  // Create a context for all lcms operations.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return 0;
  }

  // Create a white point from fuzzer data.
  const cmsCIExyY *wp_data = FuzzConsume(&fuzz_data, sizeof(cmsCIExyY));
  if (!wp_data) {
    cmsDeleteContext(ctx);
    return 0;
  }
  cmsCIExyY white_point = *wp_data;

  // Create a segmented tone curve with a variable number of segments.
  int n_segments = FuzzConsumeInt(&fuzz_data) % 10;
  if (n_segments < 0)
    n_segments = 0;

  cmsToneCurve *tone_curve = NULL;
  if (n_segments > 0) {
    cmsCurveSegment *segments = malloc(sizeof(cmsCurveSegment) * n_segments);
    if (!segments) {
      cmsDeleteContext(ctx);
      return 0;
    }
    memset(segments, 0, sizeof(cmsCurveSegment) * n_segments);

    for (int i = 0; i < n_segments; i++) {
      const cmsCurveSegment *seg_data =
          FuzzConsume(&fuzz_data, sizeof(cmsCurveSegment));
      if (!seg_data) {
        free(segments);
        cmsDeleteContext(ctx);
        return 0;
      }
      segments[i] = *seg_data;

      // Enforce continuity: segments must be contiguous.
      if (i > 0) {
        segments[i].x0 = segments[i - 1].x1;
      }

      // Enforce monotonicity: x0 must be <= x1.
      if (segments[i].x0 > segments[i].x1) {
        segments[i].x1 = segments[i].x0;
      }

      // Force a valid type to prevent crashes with invalid parametric curve types.
      // Type -1 is a simple linear curve, always valid, and has no parameters.
      segments[i].Type = -1;
    }

    tone_curve = cmsBuildSegmentedToneCurve(ctx, n_segments, segments);
    free(segments);
  }

  // Create profiles, sometimes with a NULL whitepoint to increase coverage.
  cmsCIExyY *pWP = &white_point;
  if (FuzzConsumeInt(&fuzz_data) % 2) {
    pWP = NULL;
  }

  cmsHPROFILE gray_profile = cmsCreateGrayProfileTHR(ctx, pWP, tone_curve);
  if (gray_profile) {
    // Link a tag to another to exercise cmsLinkTag.
    cmsLinkTag(gray_profile, FuzzConsumeTagSignature(&fuzz_data),
               FuzzConsumeTagSignature(&fuzz_data));
  }

  cmsHPROFILE lab_profile = cmsCreateLab4ProfileTHR(ctx, pWP);
  cmsHPROFILE proofing_profile = cmsCreateLab4ProfileTHR(ctx, NULL);

  // Create and use a proofing transform if all profiles were created.
  if (gray_profile && lab_profile && proofing_profile) {
    uint32_t input_format = TYPE_GRAY_8;
    uint32_t output_format = TYPE_Lab_8;
    uint32_t intent = FuzzConsumeInt(&fuzz_data) % 14;
    uint32_t proofing_intent = FuzzConsumeInt(&fuzz_data) % 14;
    uint32_t flags = FuzzConsumeInt(&fuzz_data);

    cmsHTRANSFORM transform = cmsCreateProofingTransformTHR(
        ctx, gray_profile, input_format, lab_profile, output_format,
        proofing_profile, intent, proofing_intent, flags);
    if (transform) {
      uint8_t in_pixel[1] = {0};
      uint8_t out_pixel[3] = {0};
      const uint8_t *pixel_data = FuzzConsume(&fuzz_data, 1);
      if (pixel_data) {
        in_pixel[0] = *pixel_data;
      }
      cmsDoTransform(transform, in_pixel, out_pixel, 1);
      cmsDeleteTransform(transform);
    }
  }

  // Cleanup all allocated resources.
  if (tone_curve)
    cmsFreeToneCurve(tone_curve);
  if (gray_profile)
    cmsCloseProfile(gray_profile);
  if (lab_profile)
    cmsCloseProfile(lab_profile);
  if (proofing_profile)
    cmsCloseProfile(proofing_profile);
  cmsDeleteContext(ctx);

  return 0;
}