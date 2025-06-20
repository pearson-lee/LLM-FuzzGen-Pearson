#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>

// This fuzzer targets several Type_*_Read functions from cmstypes.c, which are
// responsible for parsing different tag types in an ICC profile.
// All of these functions have 0% code coverage.
// The fuzzer creates a placeholder profile, writes raw tags with fuzzer data,
// and then reads them back. This exercises the parsing logic of the
// Type_*_Read functions. Closing the profile exercises the corresponding
// Type_*_Free functions, ensuring no memory leaks.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Create a placeholder profile.
  cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
  if (hProfile == NULL) {
    return 0;
  }

  // An array of tag signatures to fuzz. These correspond to the target
  // Type_*_Read functions.
  const cmsTagSignature tags_to_fuzz[] = {
      cmsSigLutAtoBType,          // For Type_LUTA2B_Read
      cmsSigColorantTableType,    // For Type_ColorantTable_Read
      cmsSigCurveType,            // For Type_Curve_Read
      cmsSigParametricCurveType,  // For Type_ParametricCurve_Read
      cmsSigXYZType               // For Type_XYZ_Read
  };
  const int num_tags = sizeof(tags_to_fuzz) / sizeof(tags_to_fuzz[0]);

  for (int i = 0; i < num_tags; i++) {
    // Write the fuzzer data as a raw tag into the profile.
    // This allows us to provide arbitrary data to the tag parsers.
    if (cmsWriteRawTag(hProfile, tags_to_fuzz[i], data, size)) {
      // Read the tag back. This will trigger the corresponding Type_*_Read
      // function to parse the raw data we just wrote. The returned data is
      // managed by the profile.
      cmsReadTag(hProfile, tags_to_fuzz[i]);
    }
  }

  // Closing the profile is crucial. It deallocates all resources associated
  // with the profile, including the data read by cmsReadTag. This will call
  // the corresponding Type_*_Free functions, preventing memory leaks.
  cmsCloseProfile(hProfile);

  return 0;
}