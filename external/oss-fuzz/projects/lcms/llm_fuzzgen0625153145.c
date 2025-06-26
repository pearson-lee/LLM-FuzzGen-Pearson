#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

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

      // Added calls to target uncovered PostScript functions in cmsps2.c
      cmsUInt32Number intent = 0, flags = 0;
      if (size >= sizeof(cmsUInt32Number) * 2) {
        memcpy(&intent, data, sizeof(cmsUInt32Number));
        data += sizeof(cmsUInt32Number);
        size -= sizeof(cmsUInt32Number);
        memcpy(&flags, data, sizeof(cmsUInt32Number));
        data += sizeof(cmsUInt32Number);
        size -= sizeof(cmsUInt32Number);
      }
      // First call with NULL buffer to get the size for cmsGetPostScriptCRD, which was uncovered.
      cmsUInt32Number crd_size = cmsGetPostScriptCRD(NULL, bchsProfile, intent, flags, NULL, 0);
      if (crd_size > 0) {
        void *crd_buf = malloc(crd_size);
        if (crd_buf) {
          // Second call to actually write the data. This ensures memory safety.
          cmsGetPostScriptCRD(NULL, bchsProfile, intent, flags, crd_buf, crd_size);
          free(crd_buf);
        }
      }

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
      // Added calls to uncovered IT8 functions to improve coverage in cmscgats.c
      cmsIT8TableCount(it8);
      cmsIT8SetPropertyStr(it8, "ORIGINATOR", "fuzzer");
      if (size > 10) {
        char comment[11];
        memcpy(comment, data, 10);
        comment[10] = '\0';
        cmsIT8SetComment(it8, comment);
      }

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

  // --- Test CIECAM02 ---
  // This section tests the CIECAM02 color appearance model, which was completely uncovered.
  if (size >= sizeof(cmsViewingConditions) + sizeof(cmsCIEXYZ)) {
    cmsViewingConditions vc;
    memcpy(&vc, data, sizeof(cmsViewingConditions));
    data += sizeof(cmsViewingConditions);
    size -= sizeof(cmsViewingConditions);

    // The adaptation state must be a valid enum value.
    cmsSetAdaptationState(vc.D_value);

    void *cam = cmsCIECAM02Init(NULL, &vc);
    if (cam) {
      cmsCIEXYZ xyz_in;
      memcpy(&xyz_in, data, sizeof(cmsCIEXYZ));

      cmsJCh jch;
      cmsCIECAM02Forward(cam, &xyz_in, &jch);

      cmsCIEXYZ xyz_out;
      cmsCIECAM02Reverse(cam, &jch, &xyz_out);

      // This call is crucial to free the allocated CIECAM02 model and maintain memory safety.
      cmsCIECAM02Done(cam);
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