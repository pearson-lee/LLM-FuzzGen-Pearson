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

  // Create a placeholder profile.
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(ctx);
  if (!hProfile) {
    cmsDeleteContext(ctx);
    return 0;
  }

  // --- Dictionary Tag (cmsSigDictTag) ---
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
  // Added to target Type_Screening_Read and Type_Screening_Write (both 0% coverage).
  cmsScreening screening;
  screening.Flag = (cmsInt32Number)Data[10];
  screening.nChannels = 1; // Keep it simple for the fuzzer
  memcpy(&screening.Channels[0].Frequency, Data + 128, sizeof(double));
  memcpy(&screening.Channels[0].ScreenAngle, Data + 136, sizeof(double));
  screening.Channels[0].SpotShape = (cmsInt32Number)Data[144] % 5;
  cmsWriteTag(hProfile, cmsSigScreeningTag, &screening);

  // --- CrdInfo Tag ---
  // Added to target Type_CrdInfo_Write and Type_CrdInfo_Read (both 0% coverage).
  cmsMLU *crd_info = cmsMLUalloc(ctx, 1);
  if (crd_info) {
    cmsMLUsetASCII(crd_info, "en", "US", "Fuzzer CrdInfo");
    cmsWriteTag(hProfile, cmsSigCrdInfoTag, crd_info);
    cmsMLUfree(crd_info); // cmsWriteTag dups the object
  }

  // --- PostScript Generation ---
  // Added to target functions in cmsps2.c (e.g., GenerateCSA) with low coverage.
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
          // The returned pointers are owned by the profile and freed by cmsCloseProfile.
          cmsReadTag(hProfileRead, cmsSigDictTag);
          cmsReadTag(hProfileRead, cmsSigVcgtTag);
          cmsReadTag(hProfileRead, cmsSigUcrBgTag);
          cmsReadTag(hProfileRead, cmsSigMpeCurveType);
          cmsReadTag(hProfileRead, cmsSigScreeningTag);
          cmsReadTag(hProfileRead, cmsSigCrdInfoTag);

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