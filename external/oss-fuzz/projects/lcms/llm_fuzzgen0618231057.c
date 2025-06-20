#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(cmsUInt32Number) * 4) {
    return 0;
  }

  const uint8_t *initial_data = data;
  size_t initial_size = size;

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

    // Added call to cmsDetectTAC to improve coverage in cmsgmt.c. This function had 0% coverage.
    cmsDetectTAC(hProfile);

    // Added call to cmsSaveProfileToMem to improve coverage in cmsio0.c. This function had 0% coverage.
    cmsUInt32Number bytes_written = 0;
    // First, call with a NULL buffer to determine the required size.
    if (cmsSaveProfileToMem(hProfile, NULL, &bytes_written) && bytes_written > 0) {
        void* buffer = malloc(bytes_written);
        if (buffer) {
            // If size calculation was successful, allocate a buffer and save the profile.
            cmsSaveProfileToMem(hProfile, buffer, &bytes_written);
            free(buffer); // Ensure memory is freed to prevent leaks.
        }
    }

    // Close the profile to free resources.
    cmsCloseProfile(hProfile);
  }

  // Use the fuzzer data to create parameters for cmsStageAllocCLutFloat.
  cmsContext null_context = cmsCreateContext(NULL, NULL);
  
  // Added call to cmsIT8LoadFromMem to improve coverage in cmscgats.c. This function had 0% coverage.
  cmsHANDLE it8_handle = cmsIT8LoadFromMem(null_context, initial_data, initial_size);
  if (it8_handle) {
    cmsIT8Free(it8_handle); // Ensure the handle is freed to prevent memory leaks.
  }

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

  // Added tone curve creation and manipulation to improve coverage in cmsgamma.c.
  // cmsBuildTabulatedToneCurve16 and cmsSmoothToneCurve had 0% coverage.
  if (initial_size >= 256 * sizeof(cmsUInt16Number) + sizeof(cmsUInt32Number) * 3) {
    cmsToneCurve* tone_curve = cmsBuildTabulatedToneCurve16(null_context, 256, (const cmsUInt16Number*)(initial_data + sizeof(cmsUInt32Number) * 3));
    if (tone_curve) {
      cmsSmoothToneCurve(tone_curve, 1.5);
      cmsFreeToneCurve(tone_curve); // Ensure the tone curve is freed to prevent memory leaks.
    }
  }

  cmsDeleteContext(null_context);

  return 0;
}