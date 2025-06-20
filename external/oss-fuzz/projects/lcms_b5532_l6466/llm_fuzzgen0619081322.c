#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stddef.h>

// Fuzzing target for various tag reading functions to improve coverage.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create an in-memory ICC profile from the fuzzer-provided data.
  // This is the primary object we will be working with.
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
  if (hProfile == NULL) {
    // The data is not a valid profile, so we can't do anything with it.
    return 0;
  }

  // The following calls to cmsReadTag are intended to trigger the reading of
  // specific tag types. The type handlers for these tags contain the functions
  // we want to cover, as identified by the coverage report.
  // The memory returned by cmsReadTag is owned by the profile and is freed
  // when cmsCloseProfile is called, so we don't need to manage it ourselves.

  // Target: ReadSegmentedCurve (via Type_MPEcurve_Read)
  // The 'mpe ' tag (Multi-Process Element) can contain segmented curves.
  cmsReadTag(hProfile, cmsSigAToB0Tag);

  // Target: Type_MHC2_Read
  // The 'mhc2' tag is a specific tag type.
  cmsReadTag(hProfile, cmsSigMHC2Tag);

  // Target: Type_Screening_Read
  // The 'scrn' tag contains screening information.
  cmsReadTag(hProfile, cmsSigScreeningTag);

  // Target: Type_VideoSignal_Read
  // The 'vids' tag contains video signal information.
  cmsReadTag(hProfile, cmsSigDeviceSettingsTag);

  // Target: _cmsReadProfileSequence (via cmsReadTag on ProfileSequenceDesc)
  // The 'pseq' tag describes a sequence of profiles.
  cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);

  // Clean up: close the profile. This is crucial to prevent memory leaks,
  // as it frees all resources associated with the profile, including any
  // tags that were read.
  cmsCloseProfile(hProfile);

  return 0;
}