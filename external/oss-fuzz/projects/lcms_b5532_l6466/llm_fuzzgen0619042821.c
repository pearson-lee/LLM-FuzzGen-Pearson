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

    // The data returned by cmsReadTag is owned by the profile and will be
    // freed when cmsCloseProfile is called. We don't need to store the
    // return value if we don't intend to use it.

    // Target: Type_ProfileSequenceDesc_Read
    cmsReadTag(hProfile, cmsSigProfileSequenceDescTag);

    // Target: Type_UcrBg_Read
    cmsReadTag(hProfile, cmsSigUcrBgTag);

    // Target: Type_vcgt_Read
    cmsReadTag(hProfile, cmsSigVcgtTag);

    // Target: Type_CrdInfo_Read
    cmsReadTag(hProfile, cmsSigCrdInfoTag);

    // Target: Type_NamedColor_Read (via cmsSigNamedColor2Tag)
    cmsReadTag(hProfile, cmsSigNamedColor2Tag);

    // Added call to uncovered function Type_ProfileSequenceId_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigProfileSequenceIdTag);

    // Added call to uncovered function Type_Chromaticity_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigChromaticityTag);

    // Added call to uncovered function Type_ColorantOrderType_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigColorantOrderTag);

    // Added call to uncovered function Type_Text_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigProfileDescriptionTag);

    // Added call to uncovered function Type_DateTime_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigDateTimeTag);

    // Added call to uncovered function Type_Measurement_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigMeasurementTag);

    // Added call to uncovered function Type_Screening_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigScreeningTag);

    // Added call to uncovered function Type_ViewingConditions_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigViewingConditionsTag);

    // Added call to uncovered function Type_XYZ_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigMediaWhitePointTag);

    // Added call to uncovered function Type_MLU_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigCopyrightTag);

    // Added call to uncovered function Type_LUT8_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigAToB0Tag);

    // Added call to uncovered function Type_LUTB2A_Read based on coverage report.
    cmsReadTag(hProfile, cmsSigBToA0Tag);
    
    // Added call to uncovered function cmsMD5computeID based on coverage report.
    cmsMD5computeID(hProfile);

    // Added calls to uncovered functions from cmscam02.c based on coverage report.
    // The viewing conditions data is owned by the profile and is freed by cmsCloseProfile.
    cmsViewingConditions* vc = (cmsViewingConditions*)cmsReadTag(hProfile, cmsSigViewingConditionsTag);
    if (vc) {
        cmsHANDLE hCIECAM02 = cmsCIECAM02Init(NULL, vc);
        if (hCIECAM02) {
            // The handle created by cmsCIECAM02Init must be freed to avoid memory leaks.
            cmsCIECAM02Done(hCIECAM02);
        }
    }

    // Close the profile. This is a crucial step for memory safety, as it
    // deallocates the profile handle and all associated resources, including
    // any data read from the tags. This prevents memory leaks.
    cmsCloseProfile(hProfile);
  }
  return 0;
}