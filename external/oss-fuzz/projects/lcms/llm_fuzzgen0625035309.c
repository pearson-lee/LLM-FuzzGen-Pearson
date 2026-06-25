#include "/src/lcms/include/lcms2.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  cmsContext context = cmsCreateContext(NULL, NULL);
  if (context == NULL) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed cmsIT8LoadFromMem
   *           had several missed branches. The line-level report confirmed this
   *           was in error handling paths.
   * IMPLEMENTATION: The following code block calls cmsIT8LoadFromMem with
   *                 the fuzzer data to exercise both successful and failing
   *                 parsing paths.
   */
  cmsHANDLE hIT8 = cmsIT8LoadFromMem(context, data, size);
  if (hIT8) {
    /*
     * ANALYSIS: The function-level coverage report showed
     *           cmsIT8SetTableByLabel had 0% coverage. The line-level report
     *           confirmed all branches were missed.
     * IMPLEMENTATION: The following code block calls cmsIT8SetTableByLabel
     *                 with fuzzer-generated strings to explore its logic.
     */
    char cSet[256];
    char cField[256];
    char expectedType[256];
    size_t remaining_size = size > sizeof(cSet) + sizeof(cField) + sizeof(expectedType) ? size - (sizeof(cSet) + sizeof(cField) + sizeof(expectedType)) : 0;
    if (remaining_size > 0) {
      memcpy(cSet, data, sizeof(cSet));
      cSet[sizeof(cSet) - 1] = '\0';
      memcpy(cField, data + sizeof(cSet), sizeof(cField));
      cField[sizeof(cField) - 1] = '\0';
      memcpy(expectedType, data + sizeof(cSet) + sizeof(cField), sizeof(expectedType));
      expectedType[sizeof(expectedType) - 1] = '\0';
      cmsIT8SetTableByLabel(hIT8, cSet, cField, expectedType);
    }

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8GetData and
     *           cmsIT8GetPatchName had 0% coverage.
     * IMPLEMENTATION: The following code block calls these functions with
     *                 fuzzer-generated strings to exercise their data
     *                 retrieval logic.
     */
    char patch[256];
    char sample[256];
    if (remaining_size > sizeof(patch) + sizeof(sample)) {
        memcpy(patch, data, sizeof(patch));
        patch[sizeof(patch)-1] = '\0';
        memcpy(sample, data + sizeof(patch), sizeof(sample));
        sample[sizeof(sample)-1] = '\0';
        cmsIT8GetData(hIT8, patch, sample);

        char patch_name[256];
        cmsIT8GetPatchName(hIT8, 0, patch_name);
    }

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8SetData had
     *           low coverage. The line-level report showed many missed
     *           branches.
     * IMPLEMENTATION: The following code block calls cmsIT8SetData with
     *                 fuzzer-generated strings to exercise its data
     *                 modification logic.
     */
    char val[256];
    if (remaining_size > sizeof(patch) + sizeof(sample) + sizeof(val)) {
        memcpy(val, data + sizeof(patch) + sizeof(sample), sizeof(val));
        val[sizeof(val)-1] = '\0';
        cmsIT8SetData(hIT8, patch, sample, val);
    }

    cmsIT8Free(hIT8);
  }

  cmsDeleteContext(context);
  return 0;
}