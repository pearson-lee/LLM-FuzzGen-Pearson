#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include <stdio.h>

// Helper function to create a temporary file with the given data.
// Returns the filename or NULL on error.
static char *create_temp_file(const uint8_t *data, size_t size) {
  char *filename = tmpnam(NULL);
  if (!filename) {
    return NULL;
  }

  FILE *f = fopen(filename, "wb");
  if (!f) {
    return NULL;
  }

  if (fwrite(data, 1, size, f) != size) {
    fclose(f);
    remove(filename);
    return NULL;
  }

  fclose(f);
  return filename;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Create a temporary file with the fuzzer data.
  char *filename = create_temp_file(data, size);
  if (!filename) {
    return 0;
  }

  // Fuzz cmsCreateDeviceLinkFromCubeFile
  cmsHPROFILE hProfile = cmsCreateDeviceLinkFromCubeFile(filename);
  if (hProfile) {
    cmsCloseProfile(hProfile);
  }

  // Fuzz cmsIT8LoadFromFile
  cmsHANDLE hIT8 = cmsIT8LoadFromFile(NULL, filename);
  if (hIT8) {
    // Fuzz cmsIT8SetTableByLabel
    cmsIT8SetTableByLabel(hIT8, "SAMPLE_ID", "1", "1");

    // Fuzz cmsIT8EnumPropertyMulti
    const char **propertyNames;
    cmsUInt32Number propertyCount = cmsIT8EnumPropertyMulti(hIT8, "DESCRIPTOR", &propertyNames);
    if (propertyCount > 0 && propertyNames != NULL) {
      // The memory for propertyNames is managed by the cmsHANDLE and should not be freed separately.
    }

    // Fuzz cmsIT8GetDataRowColDbl
    cmsIT8GetDataRowColDbl(hIT8, 0, 0);

    // Fuzz cmsIT8GetPatchName
    char patchName[256];
    const char* patchNamePtr = cmsIT8GetPatchName(hIT8, 0, patchName);
    if (patchNamePtr) {
        // The memory for patchName is managed by the cmsHANDLE and should not be freed separately.
    }

    cmsIT8Free(hIT8);
  }

  remove(filename);
  return 0;
}