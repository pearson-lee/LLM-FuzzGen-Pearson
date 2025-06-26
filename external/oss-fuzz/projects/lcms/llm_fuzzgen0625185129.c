#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) {
    return 0;
  }

  // Create a dummy profile from the fuzzer input to get a cmsHPROFILE.
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(Data, Size);
  if (hProfile == NULL) {
    return 0;
  }

  // The memory for tags read via cmsReadTag is owned by the profile handle
  // and will be freed by cmsCloseProfile. We should not free it manually.

  // Target 1: Fuzz the BToA0 tag parser (covers Type_LUTB2A_Read logic)
  cmsReadTag(hProfile, cmsSigBToA0Tag);

  // Target 2: Fuzz the profile sequence descriptor tag parser (covers Type_ProfileSequenceDesc_Read logic)
  cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);

  // Target 3: Fuzz the dictionary tag parser (covers Type_Dictionary_Read logic)
  cmsReadTag(hProfile, cmsSigMetaTag);

  // Target 4: Fuzz the vcgt tag parser (covers Type_vcgt_Read logic)
  cmsReadTag(hProfile, cmsSigVcgtTag);

  // Target 5: Fuzz cmsSmoothToneCurve
  // This part is independent of the profile handle and requires manual memory management.
  if (Size > sizeof(cmsUInt16Number) * 256 + sizeof(double)) {
    cmsToneCurve *curve = NULL;
    double smoothing_param;

    memcpy(&smoothing_param, Data + sizeof(cmsUInt16Number) * 256, sizeof(double));

    curve = cmsBuildTabulatedToneCurve16(NULL, 256, (cmsUInt16Number *)Data);
    if (curve != NULL) {
      cmsSmoothToneCurve(curve, smoothing_param);
      cmsFreeToneCurve(curve);
    }
  }

  // Clean up the profile handle and all associated tags.
  cmsCloseProfile(hProfile);

  return 0;
}