#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"

// Forward declaration of a local helper function to replace the internal
// `_cmsChannelsToColorSpace` function, which is not part of the public API
// and causes a linker error.
static cmsColorSpaceSignature channels_to_color_space(int nChannels);

// Fuzz target entry point.
// The function is designed to be memory-safe, ensuring that all allocated
// resources are properly freed before returning.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // --- Test cmsCreateBCHSWabstractProfile ---
  // This section tests the creation of an abstract profile for Brightness,
  // Contrast, Hue, and Saturation adjustments.
  if (size >= sizeof(cmsFloat64Number) * 4 + sizeof(cmsUInt32Number) * 3) {
    cmsFloat64Number Brightness, Contrast, Hue, Saturation;
    cmsUInt32Number TempSrc, TempDest, nEntries;

    memcpy(&nEntries, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);
    memcpy(&Brightness, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    memcpy(&Contrast, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    memcpy(&Hue, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    memcpy(&Saturation, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    memcpy(&TempSrc, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);
    memcpy(&TempDest, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Create the abstract profile.
    cmsHPROFILE bchsProfile = cmsCreateBCHSWabstractProfile(
        nEntries % 10000, // Limit nEntries to prevent excessive allocations
        Brightness, Contrast, Hue, Saturation, TempSrc, TempDest);

    if (bchsProfile) {
      // If profile creation is successful, compute its MD5 ID.
      cmsMD5computeID(bchsProfile);
      // Free the allocated profile.
      cmsCloseProfile(bchsProfile);
    }
  }

  // --- Test cmsCreateLinearizationDeviceLink ---
  // This section tests the creation of a linearization profile from tone curves.
  if (size > sizeof(cmsUInt32Number) * 2) {
    cmsUInt32Number nEntries, nCurves;
    memcpy(&nEntries, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);
    memcpy(&nCurves, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Limit the number of entries and curves to prevent excessive allocations.
    nEntries = nEntries % 4096 + 1;
    nCurves = nCurves % 16 + 1; // Max 16 channels

    if (size >= sizeof(cmsFloat32Number) * nEntries * nCurves) {
      cmsToneCurve *curves[16];
      for (cmsUInt32Number i = 0; i < nCurves; i++) {
        // Build a tone curve from fuzzer-provided data.
        curves[i] = cmsBuildTabulatedToneCurveFloat(NULL, nEntries, (const cmsFloat32Number *)data);
        data += sizeof(cmsFloat32Number) * nEntries;
        size -= sizeof(cmsFloat32Number) * nEntries;
      }

      // Create the linearization profile using the generated tone curves.
      cmsHPROFILE linProfile = cmsCreateLinearizationDeviceLink(
          channels_to_color_space(nCurves),
          (const cmsToneCurve **)curves);

      if (linProfile) {
        // If profile creation is successful, compute its MD5 ID.
        cmsMD5computeID(linProfile);
        // Free the allocated profile.
        cmsCloseProfile(linProfile);
      }

      // Free all allocated tone curves.
      for (cmsUInt32Number i = 0; i < nCurves; i++) {
        if (curves[i]) {
          cmsFreeToneCurve(curves[i]);
        }
      }
    }
  }

  // --- Test IT8 parsing and saving ---
  // This section tests the library's ability to handle in-memory IT8 data.
  if (size > 0) {
    // Attempt to load an IT8 object from the fuzzer data.
    cmsHANDLE it8 = cmsIT8LoadFromMem(NULL, data, size);
    if (it8) {
      cmsUInt32Number out_size = 0;
      // Determine the required buffer size for saving.
      if (cmsIT8SaveToMem(it8, NULL, &out_size)) {
        if (out_size > 0) {
          void *out_buf = malloc(out_size);
          if (out_buf) {
            // Save the IT8 data to a new buffer.
            cmsIT8SaveToMem(it8, out_buf, &out_size);
            free(out_buf);
          }
        }
      }
      // Free the IT8 handle.
      cmsIT8Free(it8);
    }
  }

  return 0;
}

// This helper function replicates the logic of the internal `_cmsChannelsToColorSpace`
// function. Using this local implementation avoids the "undefined reference" linker
// error because `_cmsChannelsToColorSpace` is not part of the public lcms API.
static cmsColorSpaceSignature channels_to_color_space(int nChannels) {
  switch (nChannels) {
  case 1:
    return cmsSigGrayData;
  case 2:
    return cmsSig2colorData;
  case 3:
    return cmsSigRgbData;
  case 4:
    return cmsSigCmykData;
  case 5:
    return cmsSig5colorData;
  case 6:
    return cmsSig6colorData;
  case 7:
    return cmsSig7colorData;
  case 8:
    return cmsSig8colorData;
  case 9:
    return cmsSig9colorData;
  case 10:
    return cmsSig10colorData;
  case 11:
    return cmsSig11colorData;
  case 12:
    return cmsSig12colorData;
  case 13:
    return cmsSig13colorData;
  case 14:
    return cmsSig14colorData;
  case 15:
    return cmsSig15colorData;
  default:
    return (cmsColorSpaceSignature)0;
  }
}