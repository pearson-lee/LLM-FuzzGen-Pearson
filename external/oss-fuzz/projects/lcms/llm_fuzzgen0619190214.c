#include "lcms2.h"
#include <stdint.h>
#include <stdlib.h>

// A list of tags to be fuzzed.
static const cmsTagSignature tags_to_fuzz[] = {
    cmsSigLutAtoBType,
    cmsSigLutBtoAType,
    cmsSigRedColorantTag,
    cmsSigGreenColorantTag,
    cmsSigBlueColorantTag,
    cmsSigMediaWhitePointTag,
    cmsSigCopyrightTag,
    cmsSigProfileDescriptionTag,
    cmsSigDeviceMfgDescTag,
    cmsSigDeviceModelDescTag,
    cmsSigViewingCondDescTag,
    cmsSigViewingConditionsTag,
    cmsSigTechnologyTag,
    cmsSigCharTargetTag,
    cmsSigColorantTableTag,
    cmsSigColorantTableOutTag,
    cmsSigNamedColor2Tag,
    cmsSigProfileSequenceDescTag,
    cmsSigCrdInfoTag,
    cmsSigS15Fixed16ArrayType,
    cmsSigU16Fixed16ArrayType,
    cmsSigTextType,
    cmsSigDateTimeType,
    cmsSigLut8Type,
    cmsSigMeasurementType,
    cmsSigDataType,
    cmsSigSignatureType,
    cmsSigGamutTag,
    cmsSigAToB0Tag,
    cmsSigAToB1Tag,
    cmsSigAToB2Tag,
    cmsSigBToA0Tag,
    cmsSigBToA1Tag,
    cmsSigBToA2Tag,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create a memory-based IO handler from the fuzzer input.
  cmsIOHANDLER *io = cmsOpenIOhandlerFromMem(NULL, (void *)data, size, "r");
  if (io == NULL) {
    return 0;
  }

  // Try to open a profile from the IO handler.
  // cmsOpenProfileFromIOhandlerTHR takes ownership of the IO handler
  // and will close it, even on failure.
  cmsHPROFILE profile = cmsOpenProfileFromIOhandlerTHR(NULL, io);
  if (profile == NULL) {
    // If the profile creation fails, the IO handler has already been
    // closed by cmsOpenProfileFromIOhandlerTHR. We must not close it again.
    return 0;
  }

  // Iterate through the list of tags and try to read each one from the profile.
  // This will exercise the different Type_*_Read functions.
  // The memory returned by cmsReadTag is owned by the profile and should not be
  // freed separately. It will be freed when cmsCloseProfile is called.
  for (size_t i = 0; i < sizeof(tags_to_fuzz) / sizeof(tags_to_fuzz[0]); i++) {
    cmsReadTag(profile, tags_to_fuzz[i]);
  }

  // Clean up resources. cmsCloseProfile will also close the IO handler
  // associated with the profile.
  cmsCloseProfile(profile);

  return 0;
}