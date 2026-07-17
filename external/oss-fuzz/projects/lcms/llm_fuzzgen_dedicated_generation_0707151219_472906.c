/* BLOCKER_STRATEGY_CONTRACT
required_state: The hRoundTrip transform object must not be NULL inside BlackPointUsingPerceptualBlack. This requires CreateRoundtripXForm to succeed.
state_constructor: A CMYK output profile is created. Both cmsSigAToB0Tag (4-in, 3-out pipeline for CMYK->Lab) and cmsSigBToA0Tag (3-in, 4-out pipeline for Lab->CMYK) are written to the profile. This provides the necessary lookup tables for the roundtrip transformation (PCS->Device->PCS) required by CreateRoundtripXForm when using INTENT_PERCEPTUAL. The previous attempt only provided the AToB tag, causing the roundtrip transform creation to fail.
trigger_api: cmsDetectDestinationBlackPoint is called with INTENT_RELATIVE_COLORIMETRIC on the crafted profile. This specific intent on a CMYK output profile triggers a call to BlackPointUsingPerceptualBlack.
preserved_invariants: The profile must be a CMYK output profile. Both cmsSigAToB0Tag and cmsSigBToA0Tag must be present with valid pipelines to allow the roundtrip transform to be created.
END_BLOCKER_STRATEGY_CONTRACT */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  uint32_t flags = *(const uint32_t *)data;

  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (!hProfile) {
    return 0;
  }

  cmsSetColorSpace(hProfile, cmsSigCmykData);
  cmsSetPCS(hProfile, cmsSigLabData);
  cmsSetDeviceClass(hProfile, cmsSigOutputClass);

  // Create and write AToB0Tag (Device to PCS)
  // For CMYK -> Lab, this is a 4-in, 3-out pipeline
  cmsPipeline* LutAToB = cmsPipelineAlloc(NULL, 4, 3);
  if (LutAToB) {
    cmsWriteTag(hProfile, cmsSigAToB0Tag, LutAToB);
    cmsPipelineFree(LutAToB);
  }

  // Create and write BToA0Tag (PCS to Device)
  // For Lab -> CMYK, this is a 3-in, 4-out pipeline. This was missing
  // in the previous attempt and is required for the roundtrip transform.
  cmsPipeline* LutBToA = cmsPipelineAlloc(NULL, 3, 4);
  if (LutBToA) {
    cmsWriteTag(hProfile, cmsSigBToA0Tag, LutBToA);
    cmsPipelineFree(LutBToA);
  }

  cmsCIEXYZ blackPoint;
  // Use INTENT_RELATIVE_COLORIMETRIC to trigger the call to BlackPointUsingPerceptualBlack
  cmsDetectDestinationBlackPoint(&blackPoint, hProfile, INTENT_RELATIVE_COLORIMETRIC, flags);

  cmsCloseProfile(hProfile);

  return 0;
}