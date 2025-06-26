#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

// This fuzzer targets the parsing of various ICC profile tags by leveraging
// the cmsReadTag API. This avoids linker errors with internal functions
// and correctly uses the library's memory management.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a profile handle from the fuzzer-provided data.
    // This is the main entry point for fuzzing the profile parsing logic.
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // By calling cmsReadTag with specific tag signatures, we trigger the
    // corresponding internal Type_*_Read functions that we want to fuzz.
    // The library handles memory management for the returned tag data,
    // which is freed when cmsCloseProfile is called.

    // Target: Type_Dictionary_Read (via cmsSigDictTag)
    cmsReadTag(hProfile, (cmsTagSignature)0x64696374); // 'dict'

    // Target: Type_MPE_Read (via cmsSigLutAtoBType)
    cmsReadTag(hProfile, cmsSigLutAtoBType);

    // Target: Type_vcgt_Read (via cmsSigVcgtTag)
    cmsReadTag(hProfile, cmsSigVcgtTag);

    // Target: Type_ProfileSequenceDesc_Read (via cmsSigProfileSequenceDescTag)
    cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);

    // Target: Type_UcrBg_Read (via cmsSigUcrBgTag)
    cmsReadTag(hProfile, cmsSigUcrBgTag);

    // Clean up all resources associated with the profile.
    cmsCloseProfile(hProfile);

    return 0;
}