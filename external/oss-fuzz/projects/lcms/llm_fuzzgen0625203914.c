#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// This fuzzer targets several Type_*_Read functions from cmstypes.c, which are
// responsible for parsing different ICC profile tag data types. All of the chosen
// functions have 0% code coverage.
//
// The fuzzing strategy is to construct a minimal, well-formed ICC profile in a
// memory buffer. This profile contains a header and a tag table with a single
// entry. The tag's data section is filled with the raw data from the fuzzer.
//
// By calling cmsOpenProfileFromMem() and then cmsReadTag(), we trigger the
// internal parsing logic of lcms, effectively directing the fuzzer's input
// to the targeted Type_*_Read functions. This approach uses the public API
// to exercise non-exported, static functions.
//
// A switch statement, controlled by the first byte of the input data, selects
// which tag type to fuzz in any given run, allowing for diverse testing of:
// 1. Type_ProfileSequenceDesc_Read (cmsSigProfileSequenceDescTag)
// 2. Type_UcrBg_Read (cmsSigUcrBgTag)
// 3. Type_vcgt_Read (cmsSigVcgtTag)
// 4. Type_CrdInfo_Read (cmsSigCrdInfoTag)
// 5. Type_Chromaticity_Read (cmsSigChromaticityTag)
//
// Memory is managed carefully: a single buffer is allocated for the profile,
// and all resources are released via cmsCloseProfile() and free(). The data
// returned by cmsReadTag is owned by the profile and is cleaned up by
// cmsCloseProfile, preventing memory leaks.

// Helper function to write a 32-bit unsigned integer in big-endian format.
// The ICC profile format requires network byte order (big-endian).
static void Write32BE(cmsUInt32Number val, uint8_t *ptr) {
  ptr[0] = (uint8_t)(val >> 24);
  ptr[1] = (uint8_t)(val >> 16);
  ptr[2] = (uint8_t)(val >> 8);
  ptr[3] = (uint8_t)(val);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // We need at least one byte to choose the target and some data for the tag.
  if (Size < 2) {
    return 0;
  }

  // Use the first byte to select which tag type to fuzz.
  const uint8_t choice = Data[0];
  const uint8_t *tagData = Data + 1;
  const size_t tagSize = Size - 1;

  cmsTagSignature tagSig;
  switch (choice % 5) {
  case 0:
    tagSig = cmsSigProfileSequenceDescTag;
    break;
  case 1:
    tagSig = cmsSigUcrBgTag;
    break;
  case 2:
    tagSig = cmsSigVcgtTag;
    break;
  case 3:
    tagSig = cmsSigCrdInfoTag;
    break;
  case 4:
    tagSig = cmsSigChromaticityTag;
    break;
  default:
    // Should not be reached
    return 0;
  }

  // Define the layout of our minimal ICC profile.
  const size_t headerSize = sizeof(cmsICCHeader);
  const size_t tagCountSize = sizeof(cmsUInt32Number);
  const size_t tagTableSize = sizeof(cmsTagEntry);
  const size_t profileSize = headerSize + tagCountSize + tagTableSize + tagSize;

  // Allocate a buffer for the entire profile.
  uint8_t *profile = (uint8_t *)malloc(profileSize);
  if (profile == NULL) {
    return 0;
  }

  // 1. Create a generic ICC header, ensuring fields are in big-endian format.
  cmsICCHeader *header = (cmsICCHeader *)profile;
  memset(header, 0, headerSize);
  
  // Use Write32BE to directly write big-endian values, avoiding the linker error.
  Write32BE(cmsMagicNumber, (uint8_t *)&header->magic);
  Write32BE(0x6C636D73, (uint8_t *)&header->cmmId); // 'lcms'
  Write32BE(0x04300000, (uint8_t *)&header->version); // ICC v4.3
  Write32BE(cmsSigInputClass, (uint8_t *)&header->deviceClass);
  Write32BE(cmsSigGrayData, (uint8_t *)&header->colorSpace);
  Write32BE(cmsSigLabData, (uint8_t *)&header->pcs);

  // 2. Write the tag count (always 1 in our case).
  uint8_t *p = profile + headerSize;
  Write32BE(1, p);
  p += tagCountSize;

  // 3. Create the tag table entry.
  const cmsUInt32Number tagOffset = headerSize + tagCountSize + tagTableSize;
  Write32BE(tagSig, p);
  Write32BE(tagOffset, p + 4);
  Write32BE((cmsUInt32Number)tagSize, p + 8);
  p += tagTableSize;

  // 4. Copy the fuzzer data to serve as the tag's content.
  memcpy(p, tagData, tagSize);

  // Open the profile from our constructed memory buffer.
  // This will parse the header and tag table.
  cmsHPROFILE hProfile = cmsOpenProfileFromMem(profile, profileSize);

  if (hProfile != NULL) {
    // Reading the tag will trigger the targeted Type_*_Read function.
    // The returned pointer is owned by the profile and does not need to be
    // freed separately.
    cmsReadTag(hProfile, tagSig);

    // Clean up the profile and all associated resources.
    cmsCloseProfile(hProfile);
  }

  // Free the memory buffer for the profile.
  free(profile);
  return 0;
}