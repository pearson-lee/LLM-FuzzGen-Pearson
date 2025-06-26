#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Manually define missing tag signatures to ensure compilation.
#define cmsSigDictTag ((cmsTagSignature)0x64696374)
#define cmsSigMpeCurveType ((cmsTagSignature)0x6d666376)
#define cmsSigNamedColor2Tag ((cmsTagSignature)0x6e636c32)
#define cmsSigDataTag ((cmsTagSignature)0x64617461)
#define cmsSigSignatureTag ((cmsTagSignature)0x73696720)


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

  // --- CGATS parsing to improve coverage in cmscgats.c ---
  // Added to target satob, NoMeta, BuildAbsolutePath, isabsolutepath which were at 0% coverage.
  const char* it8_data =
      "CGATS.17\n"
      "KEYWORD\t\"TEST_KEY\"\n"
      "BEGIN_DATA_FORMAT\n"
      "SampleID\tRGB_R\tRGB_G\tRGB_B\n"
      "END_DATA_FORMAT\n"
      "BEGIN_DATA\n"
      "1\t0.1\t0.2\t0.3\n"
      "END_DATA\n";
  cmsHANDLE hIT8 = cmsIT8LoadFromMem(ctx, (const void*)it8_data, strlen(it8_data));
  if (hIT8) {
    // Exercise saving functions to increase coverage.
    size_t mem_size = 0;
    if (cmsIT8SaveToMem(hIT8, NULL, &mem_size) && mem_size > 0 && mem_size < 1024*1024) {
        void* mem_buf = malloc(mem_size);
        if (mem_buf) {
            cmsIT8SaveToMem(hIT8, mem_buf, &mem_size);
            free(mem_buf);
        }
    }
    cmsIT8Free(hIT8);
  }

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

  // --- Vcgt Tag (cmsSigVcgtTag) ---
  // Targets Type_vcgt_Write and Type_vcgt_Read.
  // The original condition was never met; this ensures the code is executed by generating a valid gamma.
  double gamma = 0.1 + fmod(fabs(*(const double*)Data), 9.8);
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

  // --- UcrBg Tag (cmsSigUcrBgTag) ---
  // Targets Type_UcrBg_Write and Type_UcrBg_Read.
  // The original condition was never met; this ensures the code is executed by generating valid gamma values.
  double ucr_gamma = 0.1 + fmod(fabs(*(const double*)(Data + 8)), 9.8);
  double bg_gamma = 0.1 + fmod(fabs(*(const double*)(Data + 16)), 9.8);

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
  cmsICCViewingConditions vc;
  memcpy(&vc.IlluminantXYZ, Data + 200, sizeof(cmsCIEXYZ));
  memcpy(&vc.SurroundXYZ, Data + 200 + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
  vc.IlluminantType = (cmsUInt32Number)Data[0];
  cmsWriteTag(hProfile, cmsSigViewingConditionsTag, &vc);

  // --- Named Color Tag ---
  // Added to target Type_NamedColor_Write (0% coverage).
  cmsNAMEDCOLORLIST* nc = cmsAllocNamedColorList(ctx, 1, 1, "prefix", "suffix");
  if (nc) {
      cmsUInt16Number PCS[3] = {0};
      cmsUInt16Number Colorant[1] = {0};
      memcpy(PCS, Data + 250, sizeof(PCS) > Size - 250 ? Size - 250 : sizeof(PCS));
      memcpy(Colorant, Data + 256, sizeof(Colorant) > Size - 256 ? Size - 256 : sizeof(Colorant));
      cmsAppendNamedColor(nc, "FuzzerColor", PCS, Colorant);
      cmsWriteTag(hProfile, cmsSigNamedColor2Tag, nc);
      cmsFreeNamedColorList(nc);
  }

  // --- Data Tag ---
  // Added to target Type_Data_Write (0% coverage).
  if (Size > 332) {
      // The cmsICCData struct is defined with a 1-byte data array, following
      // the flexible array member idiom. The original code's attempt to assign
      // a pointer to this array (`data_tag.data = ...`) is a compile error.
      // To fix this, we define a local struct that has the correct memory layout
      // (header + space for the data) and copy the fuzzer data into it.
      // This structure is layout-compatible with what the cmsWriteTag handler
      // for cmsSigDataTag expects.
      struct {
          cmsUInt32Number len;
          cmsUInt32Number flag;
          cmsUInt8Number  data[32];
      } data_tag;

      data_tag.len = 32;
      data_tag.flag = Data[300];
      memcpy(data_tag.data, Data + 301, 32);
      cmsWriteTag(hProfile, cmsSigDataTag, &data_tag);
  }

  // --- Signature Tag ---
  // Added to target Type_Signature_Write (0% coverage).
  if (Size > 354) {
      cmsSignature sig_tag;
      memcpy(&sig_tag, Data + 350, sizeof(cmsSignature));
      cmsWriteTag(hProfile, cmsSigSignatureTag, &sig_tag);
  }

  // --- Named Color Transform ---
  // Added to target CreateNamedColorDevicelink (0% coverage) by setting the device class.
  cmsSetDeviceClass(hProfile, cmsSigNamedColorClass);
  cmsHPROFILE hDestProfile = cmsCreateLab4Profile(NULL);
  if (hDestProfile) {
      cmsHTRANSFORM hTransformNC = cmsCreateTransform(hProfile, TYPE_NAMED_COLOR_INDEX, hDestProfile, TYPE_Lab_8, INTENT_PERCEPTUAL, 0);
      if (hTransformNC) {
          cmsUInt16Number input = Data[1];
          uint8_t output_buffer[3];
          cmsDoTransform(hTransformNC, &input, output_buffer, 1);
          cmsDeleteTransform(hTransformNC);
      }
      cmsCloseProfile(hDestProfile);
  }
  // Reset device class to not interfere with other operations.
  cmsSetDeviceClass(hProfile, cmsSigDisplayClass);

  // --- Color Transform ---
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
  if (cmsSaveProfileToMem(hProfile, NULL, &ProfileSize) && ProfileSize > 0 && ProfileSize < 1024*1024) {
    void *ProfileData = malloc(ProfileSize);
    if (ProfileData) {
      if (cmsSaveProfileToMem(hProfile, ProfileData, &ProfileSize)) {
        // Open the profile from the memory buffer to test reading.
        cmsHPROFILE hProfileRead = cmsOpenProfileFromMem(ProfileData, ProfileSize);
        if (hProfileRead) {
          // Reading the tags exercises the Type_*_Read functions.
          cmsReadTag(hProfileRead, cmsSigVcgtTag);
          cmsReadTag(hProfileRead, cmsSigUcrBgTag);
          cmsReadTag(hProfileRead, cmsSigMpeCurveType);
          cmsReadTag(hProfileRead, cmsSigScreeningTag);
          cmsReadTag(hProfileRead, cmsSigCrdInfoTag);
          cmsReadTag(hProfileRead, cmsSigViewingConditionsTag);
          // Added to read the newly written tags.
          cmsReadTag(hProfileRead, cmsSigNamedColor2Tag);
          cmsReadTag(hProfileRead, cmsSigDataTag);
          cmsReadTag(hProfileRead, cmsSigSignatureTag);

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