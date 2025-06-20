#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(cmsUInt32Number) * 4) {
    return 0;
  }

  // Create a memory-based profile from the fuzzer data.
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
  if (hProfile) {
    // Exercise tag-related functions.
    cmsInt32Number tag_count = cmsGetTagCount(hProfile);
    if (tag_count > 0) {
      // Get the signature of the first tag.
      cmsTagSignature sig = cmsGetTagSignature(hProfile, 0);

      // Attempt to read the tag. The memory is managed by the profile.
      cmsReadTag(hProfile, sig);
    }

    // Get profile description.
    wchar_t info_buffer[256];
    cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", info_buffer, sizeof(info_buffer));

    // Close the profile to free resources.
    cmsCloseProfile(hProfile);
  }

  // Use the fuzzer data to create parameters for cmsStageAllocCLutFloat.
  cmsContext null_context = cmsCreateContext(NULL, NULL);
  cmsUInt32Number clut_points = *(const cmsUInt32Number *)(data);
  data += sizeof(cmsUInt32Number);
  size -= sizeof(cmsUInt32Number);
  cmsUInt32Number input_channels = *(const cmsUInt32Number *)(data);
  data += sizeof(cmsUInt32Number);
  size -= sizeof(cmsUInt32Number);
  cmsUInt32Number output_channels = *(const cmsUInt32Number *)(data);
  data += sizeof(cmsUInt32Number);
  size -= sizeof(cmsUInt32Number);

  // Basic validation to prevent excessive memory allocation.
  if (clut_points > 0 && clut_points < 256 && input_channels > 0 &&
      input_channels < 16 && output_channels > 0 && output_channels < 16) {
    
    size_t num_entries = 1;
    for (cmsUInt32Number i = 0; i < input_channels; i++) {
        if (__builtin_mul_overflow(num_entries, clut_points, &num_entries)) {
            cmsDeleteContext(null_context);
            return 0;
        }
    }

    size_t total_floats;
    if (__builtin_mul_overflow(num_entries, output_channels, &total_floats)) {
        cmsDeleteContext(null_context);
        return 0;
    }
    
    size_t table_size;
    if (__builtin_mul_overflow(total_floats, sizeof(cmsFloat32Number), &table_size)) {
        cmsDeleteContext(null_context);
        return 0;
    }

    if (size >= table_size) {
      // Allocate and then free a CLUT stage.
      cmsStage *clut_stage = cmsStageAllocCLutFloat(
          null_context, clut_points, input_channels, output_channels,
          (const cmsFloat32Number *)data);
      if (clut_stage) {
        cmsStageFree(clut_stage);
      }
    }
  }

  cmsDeleteContext(null_context);

  return 0;
}