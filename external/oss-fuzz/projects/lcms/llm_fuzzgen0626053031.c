#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>

// Target API: cmsOpenProfileFromMem
// This function parses an ICC profile from a memory buffer. It's a primary entry
// point for fuzzing the profile parsing logic, which involves numerous helper
// functions for reading different tag types (e.g., Type_Curve_Read,
// Type_MLU_Read, Type_LUT8_Read). Fuzzing this function helps uncover
// vulnerabilities in the complex parsing and validation logic of lcms2.

// Target API: cmsReadTag
// After a profile is successfully opened, this function can be used to read
// specific tags. This allows for targeted fuzzing of the handlers for
// individual tag types. In this fuzzer, we specifically read the profile
// description tag (cmsSigProfileDescriptionTag) to exercise the MLU (Multi-
// Localized Unicode) handling code.

// Target API: cmsCreateTransform
// This is a core function of lcms2 that creates a color transformation pipeline
// between two profiles. It exercises a vast amount of the library's code,
// including color space conversion, interpolation, matrix operations, and LUT
// optimization. By using a profile from the fuzzer input, we can test how the
// transform is built with potentially malformed profile data.

// Target API: cmsSaveProfileToMem
// This function writes a profile object to a memory buffer. It serves as the
// inverse of cmsOpenProfileFromMem and is crucial for testing the serialization
// logic. Fuzzing this helps find bugs in the functions that write different tag
// types (e.g., Type_Curve_Write, Type_MLU_Write), which often have different
// code paths than the reading functions.

// Target API: cmsMLUfree, cmsCloseProfile, cmsDeleteTransform, cmsDeleteContext
// These are resource management functions. It is critical to call them to
// prevent memory leaks and ensure the fuzzer runs cleanly. Correctly managing
// resources is a key part of a robust fuzzer.

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Create a context. A NULL context is also valid for many lcms functions,
  // but creating one is good practice.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  // Attempt to open an ICC profile from the fuzzer-provided data.
  // This is the main entry point for fuzzing the profile parsing logic.
  cmsHPROFILE hProfile = cmsOpenProfileFromMemTHR(ctx, Data, Size);
  if (hProfile == NULL) {
    // If the profile is invalid, that's a valid fuzzing outcome.
    // Clean up and exit.
    cmsDeleteContext(ctx);
    return 0;
  }

  // Read the profile description tag to exercise MLU (Multi-Localized Unicode)
  // handling. This targets functions like cmsMLUgetASCII, cmsMLUgetWide, etc.
  cmsMLU *mlu = (cmsMLU *)cmsReadTag(hProfile, cmsSigProfileDescriptionTag);
  if (mlu != NULL) {
    // Free the MLU structure to prevent memory leaks.
    cmsMLUfree(mlu);
  }

  // Create a destination profile to be used for creating a transform.
  // Using a standard Lab profile for this purpose.
  cmsHPROFILE hDestProfile = cmsCreateLab4Profile(NULL);
  if (hDestProfile != NULL) {
    // Determine the input format for the transform based on the color space
    // of the fuzzer-provided profile.
    cmsColorSpaceSignature colorSpace = cmsGetColorSpace(hProfile);
    cmsUInt32Number nChannels = cmsChannelsOfColorSpace(colorSpace);
    // We assume 8-bit input for simplicity.
    cmsUInt32Number inputFormat = CHANNELS_SH(nChannels) | BYTES_SH(1);

    // Create a color transform. This exercises a large part of the lcms2
    // engine, including gamut mapping and LUT optimization.
    cmsHTRANSFORM hTransform = cmsCreateTransform(
        hProfile, inputFormat, hDestProfile, TYPE_Lab_8, INTENT_PERCEPTUAL, 0);

    if (hTransform != NULL) {
      // Clean up the transform object.
      cmsDeleteTransform(hTransform);
    }
    // Clean up the destination profile.
    cmsCloseProfile(hDestProfile);
  }

  // Save the parsed profile back to a memory buffer. This exercises the
  // profile writing logic, which may have different bugs than the parsing
  // logic.
  cmsUInt32Number profileSize = 0;
  // First, get the required size.
  if (cmsSaveProfileToMem(hProfile, NULL, &profileSize)) {
    if (profileSize > 0) {
      // Allocate a buffer and save the profile.
      void *buffer = malloc(profileSize);
      if (buffer != NULL) {
        cmsSaveProfileToMem(hProfile, buffer, &profileSize);
        // Free the allocated buffer.
        free(buffer);
      }
    }
  }

  // Clean up the profile handle.
  cmsCloseProfile(hProfile);
  // Clean up the context.
  cmsDeleteContext(ctx);

  return 0;
}