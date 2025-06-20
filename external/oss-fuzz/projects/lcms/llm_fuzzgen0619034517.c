#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stddef.h>

// This fuzz target attempts to exercise several of the `Type_*_Read` functions
// from cmstypes.c, which have 0% coverage. It does this by creating an in-memory
// profile from the fuzzer data and then attempting to read various tags from it.
// The lcms library will then dispatch to the appropriate type handler's `Read`
// function based on the tag signature.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create a profile from the fuzzer-provided data.
  // cmsOpenProfileFromMem is robust against invalid profile data and will
  // return NULL if the profile cannot be parsed.
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
  if (hProfile) {
    // By calling cmsReadTag with different tag signatures, we can trigger
    // the execution of the corresponding, previously uncovered `Type_*_Read`
    // functions.

    // Target: Type_ProfileSequenceDesc_Read
    // The data returned by cmsReadTag is owned by the profile and will be
    // freed when cmsCloseProfile is called. We don't need to store the
    // return value if we don't intend to use it.
    cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);

    // Target: Type_UcrBg_Read
    cmsReadTag(hProfile, cmsSigUcrBgTag);

    // Target: Type_vcgt_Read
    cmsReadTag(hProfile, cmsSigVcgtTag);

    // Target: Type_CrdInfo_Read
    cmsReadTag(hProfile, cmsSigCrdInfoTag);

    // Target: Type_NamedColor_Read (via cmsSigNamedColor2Tag)
    cmsReadTag(hProfile, cmsSigNamedColor2Tag);

    // Close the profile. This is a crucial step for memory safety, as it
    // deallocates the profile handle and all associated resources, including
    // any data read from the tags. This prevents memory leaks.
    cmsCloseProfile(hProfile);
  }
  return 0;
}