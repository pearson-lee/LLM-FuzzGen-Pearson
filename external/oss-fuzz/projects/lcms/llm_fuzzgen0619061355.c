#include "/src/lcms/include/lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"
#include "/src/lcms/src/lcms2_internal.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Create a context.
  cmsContext context = cmsCreateContext(NULL, NULL);
  if (!context) {
    return 0;
  }

  // Create an IT8 handle from the fuzzer data.
  // This is the main entry point we are fuzzing.
  cmsHANDLE hIT8 = cmsIT8LoadFromMem(context, data, size);
  if (hIT8) {
    // If the IT8 handle is valid, we can call other functions on it.
    // These functions have been selected due to low or zero code coverage.

    // Call cmsIT8SetTable to exercise table setting logic.
    if (size >= sizeof(cmsUInt32Number)) {
      cmsIT8SetTable(hIT8, *(const cmsUInt32Number *)data);
    }

    // Call cmsIT8GetPropertyDbl to exercise property retrieval.
    // We use a portion of the input data as the property name.
    if (size > 128) {
      char prop_name[129];
      memcpy(prop_name, data, 128);
      prop_name[128] = '\0';
      cmsIT8GetPropertyDbl(hIT8, prop_name);
    }

    // Call cmsIT8SetDataDbl to exercise data setting.
    // We construct the arguments from the input data.
    if (size > 256 + sizeof(double)) {
      char patch_name[129];
      char sample_name[129];
      double val;

      memcpy(patch_name, data, 128);
      patch_name[128] = '\0';

      memcpy(sample_name, data + 128, 128);
      sample_name[128] = '\0';

      memcpy(&val, data + 256, sizeof(double));

      cmsIT8SetDataDbl(hIT8, patch_name, sample_name, val);
    }

    // Call cmsIT8GetSheetType to exercise sheet type retrieval.
    cmsIT8GetSheetType(hIT8);

    // Free the IT8 handle to prevent memory leaks.
    cmsIT8Free(hIT8);
  }

  // Clean up the context to prevent memory leaks.
  cmsDeleteContext(context);
  return 0;
}