#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Fuzz target to exercise various low-coverage APIs in lcms.
// It focuses on profile parsing, reading specific uncovered tag types,
// PostScript generation, and color manipulation functions.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  // Main entry point for fuzzing: attempt to open the input data as a profile.
  // This will exercise a large part of the I/O and parsing logic.
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
  if (hProfile != NULL) {

    // Target the family of Type_*_Read functions in cmstypes.c, which have very
    // low coverage. We do this by calling cmsReadTag with specific signatures.
    // The returned data is owned by the profile and is freed by cmsCloseProfile.
    cmsReadTag(hProfile, cmsSigcicpTag);
    cmsReadTag(hProfile, cmsSigVcgtTag);
    cmsReadTag(hProfile, cmsSigProfileSequenceIdTag);
    cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);
    cmsReadTag(hProfile, cmsSigUcrBgTag);
    cmsReadTag(hProfile, cmsSigChromaticityTag);
    cmsReadTag(hProfile, cmsSigColorantOrderTag);
    cmsReadTag(hProfile, cmsSigNamedColor2Tag);

    // Target cmsGetProfileInfo and cmsGetProfileInfoASCII, which have 0%
    // coverage.
    wchar_t bufferW[256];
    cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", bufferW, 256);
    char bufferA[256];
    cmsGetProfileInfoASCII(hProfile, cmsInfoDescription, "en", "US", bufferA,
                           256);

    // Target PostScript generation functions in cmsps2.c, which have low
    // coverage.
    cmsUInt32Number intent = data[0] % 4; // Use fuzzer data for intent
    cmsUInt32Number flags = data[1];      // and flags

    // Correctly call cmsGetPostScriptCSA by first getting the size, then
    // allocating a buffer and filling it.
    cmsUInt32Number ps_size_csa =
        cmsGetPostScriptCSA(NULL, hProfile, intent, flags, NULL, 0);
    if (ps_size_csa > 0) {
      void *ps_buffer = malloc(ps_size_csa);
      if (ps_buffer != NULL) {
        cmsGetPostScriptCSA(NULL, hProfile, intent, flags, ps_buffer,
                            ps_size_csa);
        free(ps_buffer);
      }
    }

    // Correctly call cmsGetPostScriptCRD.
    cmsUInt32Number ps_size_crd =
        cmsGetPostScriptCRD(NULL, hProfile, intent, flags, NULL, 0);
    if (ps_size_crd > 0) {
      void *ps_buffer = malloc(ps_size_crd);
      if (ps_buffer != NULL) {
        cmsGetPostScriptCRD(NULL, hProfile, intent, flags, ps_buffer,
                            ps_size_crd);
        free(ps_buffer);
      }
    }

    // Clean up the profile handle and all associated resources.
    cmsCloseProfile(hProfile);
  }

  // Target cmsDesaturateLab in cmsgmt.c, which has 0% coverage.
  if (size >= sizeof(cmsCIELab) + 4 * sizeof(double)) {
    cmsCIELab Lab;
    // Use data from the end of the buffer to avoid interfering with profile
    // parsing.
    const uint8_t *tail_data =
        data + size - (sizeof(cmsCIELab) + 4 * sizeof(double));
    memcpy(&Lab, tail_data, sizeof(cmsCIELab));

    double da[4];
    memcpy(da, tail_data + sizeof(cmsCIELab), sizeof(da));

    cmsDesaturateLab(&Lab, da[0], da[1], da[2], da[3]);
  }

  // Target cmsGetSupportedIntents in cmscnvrt.c, which has 0% coverage.
  cmsUInt32Number nSupportedIntents = cmsGetSupportedIntents(0, NULL, NULL);
  if (nSupportedIntents > 0) {
    // Allocate buffers to hold the codes and the pointers to the descriptions.
    cmsUInt32Number *intent_codes =
        (cmsUInt32Number *)calloc(nSupportedIntents, sizeof(cmsUInt32Number));
    char **intent_descs = (char **)calloc(nSupportedIntents, sizeof(char *));

    if (intent_codes != NULL && intent_descs != NULL) {
      cmsGetSupportedIntents(nSupportedIntents, intent_codes, intent_descs);
    }

    // The strings pointed to by intent_descs are internal and must not be
    // freed, but the lists of pointers/codes itself must be.
    free(intent_codes);
    free(intent_descs);
  }

  return 0;
}