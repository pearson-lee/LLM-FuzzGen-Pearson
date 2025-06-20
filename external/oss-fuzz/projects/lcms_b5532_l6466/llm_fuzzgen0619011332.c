#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"
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
    // Added call to uncovered function cmsMD5computeID based on coverage report.
    cmsMD5computeID(hProfile);
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

  // Added calls to uncovered MD5 functions based on coverage report.
  // The handle returned by cmsMD5alloc is freed by cmsMD5finish.
  cmsHANDLE hMD5 = cmsMD5alloc(NULL);
  if (hMD5) {
    cmsMD5add(hMD5, data, size);
    cmsProfileID profileID;
    cmsMD5finish(&profileID, hMD5);
  }

  remove(filename);
  return 0;
}