#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Manually define missing tag signatures to ensure compilation.
#define cmsSigDictTag ((cmsTagSignature)0x64696374)
#define cmsSigMpeCurveType ((cmsTagSignature)0x6d666376)

// This fuzzer targets several Type_*_Read and Type_*_Write functions
// by creating, writing, saving, loading, and reading
// various tag types in an ICC profile.

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 400) {
    // Increased size requirement for additional tag structures.
    return 0;
  }

  // Create a context.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (!ctx) {
    return 0;
  }

  // Suppress error messages.
  cmsSetLogErrorHandler(NULL);

  // Create a real sRGB profile instead of a placeholder.
  // The placeholder profile was causing cmsGetPostScriptCSA to return 0,
  // leaving the PostScript generation functions in cmsps2.c uncovered.
  // An sRGB profile has the necessary properties (like a defined colorspace)
  // to allow PostScript generation to proceed.
  cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
  if (!hProfile) {
    cmsDeleteContext(ctx);
    return 0;
  }

  // --- Dictionary Tag (cmsSigDictTag) ---
  // The dictionary plugin is not available in the build environment, which
  // causes a linker error for `cmsPluginDict`. This section is disabled
  // to allow the fuzzer to compile.
  /*
  cmsHANDLE hDict = cmsDictAlloc(ctx);
  if (hDict) {
    // Use fuzzer data to create wide character strings for dictionary entries.
    size_t wcs_len = 16;
    wchar_t wcs_name[wcs_len];
    wchar_t wcs_value[wcs_len];

    memcpy(wcs_name, Data, (wcs_len - 1) * sizeof(wchar_t));
    wcs_name[wcs_len - 1] = 0;
    memcpy(wcs_value, Data + (wcs_len - 1) * sizeof(wchar_t), (wcs_len - 1) * sizeof(wchar_t));
    wcs_value[wcs_len - 1] = 0;

    cmsDictAddEntry(hDict, wcs_name, wcs_value, NULL, NULL);

    // Write the dictionary tag to the profile.
    cmsWriteTag(hProfile, cmsSigDictTag, hDict);
    // The dictionary is duplicated by the write function, so we can free ours.
    cmsDictFree(hDict);
  }
  */

  // --- Vcgt Tag (cmsSigVcgtTag) ---
  // Targets Type_vcgt_Write and Type_vcgt_Read.
  double gamma;
  memcpy(&gamma, Data, sizeof(double));
  // Keep gamma in a reasonable range to avoid math errors.
  if (gamma > 0.1 && gamma < 10.0) {
    cmsToneCurve *gamma_curves[3];
    gamma_curves[0] = cmsBuildGamma(ctx, gamma);
    gamma_curves[1] = cmsBuildGamma(ctx, gamma);
    gamma_curves[2] = cmsBuildGamma(ctx, gamma);

    if (gamma_curves[0] && gamma_curves[1] && gamma_curves[2]) {
      cmsWriteTag(hProfile, cmsSigVcgtTag, gamma_curves);
    }

    // Free the created tone curves.
    if (gamma_curves[0])
      cmsFreeToneCurve(gamma_curves[0]);
    if (gamma_curves[1])
      cmsFreeToneCurve(gamma_curves[1]);
    if (gamma_curves[2])
      cmsFreeToneCurve(gamma_curves[2]);
  }

  // --- UcrBg Tag (cmsSigUcrBgTag) ---
  // Targets Type_UcrBg_Write and Type_UcrBg_Read.
  double ucr_gamma, bg_gamma;
  memcpy(&ucr_gamma, Data, sizeof(double));
  memcpy(&bg_gamma, Data + sizeof(double), sizeof(double));

  if (ucr_gamma > 0.1 && ucr_gamma < 10.0 && bg_gamma > 0.1 && bg_gamma < 10.0) {
    cmsUcrBg ucrbg;
    ucrbg.Ucr = cmsBuildGamma(ctx, ucr_gamma);
    ucrbg.Bg = cmsBuildGamma(ctx, bg_gamma);
    ucrbg.Desc = cmsMLUalloc(ctx, 1);
    if (ucrbg.Desc) {
      cmsMLUsetASCII(ucrbg.Desc, "en", "US", "Fuzzer UcrBg");
    }

    if (ucrbg.Ucr && ucrbg.Bg && ucrbg.Desc) {
      cmsWriteTag(hProfile, cmsSigUcrBgTag, &ucrbg);
    }

    // Free the allocated components.
    if (ucrbg.Ucr)
      cmsFreeToneCurve(ucrbg.Ucr);
    if (ucrbg.Bg)
      cmsFreeToneCurve(ucrbg.Bg);
    if (ucrbg.Desc)
      cmsMLUfree(ucrbg.Desc);
  }

  // --- MPE Curve Tag (cmsSigMpeCurveType) ---
  cmsCurveSegment segments[2];
  memcpy(segments, Data, sizeof(cmsCurveSegment) * 2);
  // Set some fields to valid values to guide the fuzzer.
  segments[0].x0 = 0;
  segments[0].x1 = 0.5;
  segments[1].x0 = 0.5;
  segments[1].x1 = 1.0;
  segments[0].Type = 6;
  segments[1].Type = 6;

  cmsToneCurve *segmented_curve = cmsBuildSegmentedToneCurve(ctx, 2, segments);
  if (segmented_curve) {
    cmsWriteTag(hProfile, cmsSigMpeCurveType, segmented_curve);
    cmsFreeToneCurve(segmented_curve);
  }

  // --- Screening Tag ---
  cmsScreening screening;
  screening.Flag = (cmsInt32Number)Data[10];
  screening.nChannels = 1; // Keep it simple for the fuzzer
  memcpy(&screening.Channels[0].Frequency, Data + 128, sizeof(double));
  memcpy(&screening.Channels[0].ScreenAngle, Data + 136, sizeof(double));
  screening.Channels[0].SpotShape = (cmsInt32Number)Data[144] % 5;
  cmsWriteTag(hProfile, cmsSigScreeningTag, &screening);

  // --- CrdInfo Tag ---
  cmsMLU *crd_info = cmsMLUalloc(ctx, 1);
  if (crd_info) {
    cmsMLUsetASCII(crd_info, "en", "US", "Fuzzer CrdInfo");
    cmsWriteTag(hProfile, cmsSigCrdInfoTag, crd_info);
    cmsMLUfree(crd_info); // cmsWriteTag dups the object
  }

  // --- Viewing Conditions Tag ---
  // Added to target Type_ViewingConditions_Read and Type_ViewingConditions_Write (both 0% coverage).
  cmsICCViewingConditions vc;
  memcpy(&vc.IlluminantXYZ, Data + 200, sizeof(cmsCIEXYZ));
  memcpy(&vc.SurroundXYZ, Data + 200 + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
  vc.IlluminantType = (cmsUInt32Number)Data[0];
  cmsWriteTag(hProfile, cmsSigViewingConditionsTag, &vc);

  // --- Color Transform ---
  // Added to target cmsxform.c, cmspack.c, and cmsintrp.c, which had low coverage.
  cmsHPROFILE hLabProfile = cmsCreateLab4Profile(NULL);
  if (hLabProfile) {
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hLabProfile, TYPE_Lab_8, INTENT_PERCEPTUAL, 0);
    if (hTransform) {
      uint8_t input_buffer[3];
      uint8_t output_buffer[3];
      memcpy(input_buffer, Data + 150, 3);
      cmsDoTransform(hTransform, input_buffer, output_buffer, 1);
      cmsDeleteTransform(hTransform);
    }
    cmsCloseProfile(hLabProfile);
  }

  // --- PostScript Generation ---
  cmsUInt32Number ps_intent = Data[0] % 4;
  cmsUInt32Number ps_flags = (cmsUInt32Number)Data[1];
  cmsUInt32Number csa_size = cmsGetPostScriptCSA(ctx, hProfile, ps_intent, ps_flags, NULL, 0);
  if (csa_size > 0 && csa_size < 1024 * 1024) { // Limit allocation size
    void *csa_buffer = malloc(csa_size);
    if (csa_buffer) {
      cmsGetPostScriptCSA(ctx, hProfile, ps_intent, ps_flags, csa_buffer, csa_size);
      free(csa_buffer);
    }
  }

  // Save the profile with all written tags to an in-memory buffer.
  cmsUInt32Number ProfileSize = 0;
  if (cmsSaveProfileToMem(hProfile, NULL, &ProfileSize) && ProfileSize > 0) {
    void *ProfileData = malloc(ProfileSize);
    if (ProfileData) {
      if (cmsSaveProfileToMem(hProfile, ProfileData, &ProfileSize)) {
        // Open the profile from the memory buffer to test reading.
        cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(ProfileData, ProfileSize);
        if (hProfileRead) {
          // Reading the tags exercises the Type_*_Read functions.
          // cmsReadTag(hProfileRead, cmsSigDictTag); // Disabled as it's not written
          cmsReadTag(hProfileRead, cmsSigVcgtTag);
          cmsReadTag(hProfileRead, cmsSigUcrBgTag);
          cmsReadTag(hProfileRead, cmsSigMpeCurveType);
          cmsReadTag(hProfileRead, cmsSigScreeningTag);
          cmsReadTag(hProfileRead, cmsSigCrdInfoTag);
          cmsReadTag(hProfileRead, cmsSigViewingConditionsTag);

          cmsCloseProfile(hProfileRead);
        }
      }
      free(ProfileData);
    }
  }

  // Clean up resources.
  cmsCloseProfile(hProfile);
  cmsDeleteContext(ctx);

  return 0;
}