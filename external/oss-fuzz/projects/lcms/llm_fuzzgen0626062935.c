#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
  if (Size == 0) {
    return 0;
  }

  // Create a context. A NULL context is also valid for many lcms functions,
  // but creating one is good practice.
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  if (ctx == NULL) {
    return 0;
  }

  // The input may be a CGATS file. Add a call to cmsIT8LoadFromMem to
  // exercise the IT8 API in cmscgats.c, which was previously uncovered.
  cmsHANDLE hIT8 = cmsIT8LoadFromMem(ctx, Data, Size);
  if (hIT8 != NULL) {
    cmsIT8Free(hIT8);
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

  // To ensure the code path for reading a profile description tag is exercised,
  // we write a dummy description to the profile first. This helps cover the
  // previously missed branch `if (mlu != NULL)`.
  cmsMLU *Description = cmsMLUalloc(ctx, 1);
  if (Description) {
    cmsMLUsetASCII(Description, "en", "US", "Dummy Description");
    cmsWriteTag(hProfile, cmsSigProfileDescriptionTag, Description);
    cmsMLUfree(Description); // cmsWriteTag makes a copy, so we can free this.
  }

  // Read the profile description tag to exercise MLU (Multi-Localized Unicode)
  // handling. This is now more likely to succeed due to the enhancement above.
  cmsMLU *mlu = (cmsMLU *)cmsReadTag(hProfile, cmsSigProfileDescriptionTag);
  if (mlu != NULL) {
    // Added calls to target uncovered functions from cmsnamed.c, now that we have a valid mlu.
    if (cmsMLUtranslationsCount(mlu) > 0) {
      char language_code[3];
      char country_code[3];
      cmsMLUtranslationsCodes(mlu, 0, language_code, country_code);
    }
    // DO NOT free 'mlu'. It is a pointer to internal data owned by hProfile.
    // It will be freed when cmsCloseProfile is called.
  }

  // To cover the 0%-covered Type_Signature_Write function, write a signature tag.
  // The original fuzzer used cmsSigSignatureType, which is a type, not a tag,
  // causing cmsWriteTag to fail. Using cmsSigTechnologyTag to fix this.
  cmsSignature sig = (cmsSignature)'fuzz';
  if (cmsWriteTag(hProfile, cmsSigTechnologyTag, &sig)) {
    // Reading the tag back to exercise the reader function.
    cmsReadTag(hProfile, cmsSigTechnologyTag);
  }

  // To cover the 0%-covered Type_Data_Write and Type_Data_Read functions,
  // we write and read a data tag.
  const char data_blob[] = "fuzz data";
  size_t blob_size = sizeof(data_blob);
  // The data for cmsSigDataType is a cmsICCData object.
  cmsICCData *icc_data = (cmsICCData *)malloc(sizeof(cmsICCData) + blob_size - 1);
  if (icc_data) {
    icc_data->len = (cmsUInt32Number)blob_size;
    icc_data->flag = 0; // 0 for ASCII data
    memcpy(icc_data->data, data_blob, blob_size);
    if (cmsWriteTag(hProfile, cmsSigDataType, icc_data)) {
      cmsReadTag(hProfile, cmsSigDataType);
    }
    free(icc_data);
  }

  // Create a destination profile to be used for creating a transform.
  // Using a Lab profile to improve the success rate of cmsCreateTransform.
  cmsHPROFILE hDestProfile = cmsCreateLab4ProfileTHR(ctx, NULL);
  if (hDestProfile != NULL) {
    // Determine the input format for the transform based on the color space
    // of the fuzzer-provided profile.
    cmsColorSpaceSignature colorSpace = cmsGetColorSpace(hProfile);
    cmsUInt32Number nChannels = cmsChannelsOfColorSpace(colorSpace);
    // We assume 8-bit input for simplicity.
    cmsUInt32Number inputFormat = CHANNELS_SH(nChannels) | BYTES_SH(1);

    // Create a color transform. Using TYPE_Lab_8 to match the Lab destination profile.
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, inputFormat, hDestProfile, TYPE_Lab_8, INTENT_PERCEPTUAL, 0);

    if (hTransform != NULL) {
      // This block was previously uncovered. Call cmsDoTransform to exercise
      // the transformation pipeline.
      uint8_t input_pixel[16] = {0};
      uint8_t output_pixel[16] = {0};
      cmsDoTransform(hTransform, input_pixel, output_pixel, 1);
      cmsDeleteTransform(hTransform);
    }
    // Clean up the destination profile.
    cmsCloseProfile(hDestProfile);
  }

  // To cover functions in cmsps2.c, call cmsGetPostScriptCSA.
  cmsUInt32Number ps_size = cmsGetPostScriptCSA(ctx, hProfile, INTENT_PERCEPTUAL, 0, NULL, 0);
  if (ps_size > 0) {
    void *ps_buffer = malloc(ps_size);
    if (ps_buffer != NULL) {
      cmsGetPostScriptCSA(ctx, hProfile, INTENT_PERCEPTUAL, 0, ps_buffer, ps_size);
      free(ps_buffer);
    }
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