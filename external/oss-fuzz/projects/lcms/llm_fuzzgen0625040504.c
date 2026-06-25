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
    char str1[256];
    char str2[256];
    char str3[256];
    size_t offset = 0;

    // Consume data for the first string if available
    if (size > offset) {
        size_t len = size - offset > 255 ? 255 : size - offset;
        memcpy(str1, data + offset, len);
        str1[len] = '\0';
        offset += len;
    } else {
        str1[0] = '\0';
    }

    // Consume data for the second string if available
    if (size > offset) {
        size_t len = size - offset > 255 ? 255 : size - offset;
        memcpy(str2, data + offset, len);
        str2[len] = '\0';
        offset += len;
    } else {
        str2[0] = '\0';
    }

    // Consume data for the third string if available
    if (size > offset) {
        size_t len = size - offset > 255 ? 255 : size - offset;
        memcpy(str3, data + offset, len);
        str3[len] = '\0';
        offset += len;
    } else {
        str3[0] = '\0';
    }

    /*
     * ANALYSIS: The function-level coverage report showed
     *           cmsIT8SetTableByLabel had low coverage.
     * IMPLEMENTATION: The following code block calls cmsIT8SetTableByLabel
     *                 with fuzzer-generated strings to explore its logic.
     */
    cmsIT8SetTableByLabel(hIT8, str1, str2, str3);

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8GetData and
     *           cmsIT8GetPatchName had low coverage.
     * IMPLEMENTATION: The following code block calls these functions with
     *                 fuzzer-generated strings to exercise their data
     *                 retrieval logic.
     */
    cmsIT8GetData(hIT8, str1, str2);
    char patch_name[256];
    cmsIT8GetPatchName(hIT8, 0, patch_name);

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8SetData had
     *           low coverage.
     * IMPLEMENTATION: The following code block calls cmsIT8SetData with
     *                 fuzzer-generated strings to exercise its data
     *                 modification logic.
     */
    cmsIT8SetData(hIT8, str1, str2, str3);

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8TableCount,
     *           cmsIT8GetPatchByName, and cmsIT8SetIndexColumn had 0% coverage.
     * IMPLEMENTATION: The following calls exercise these uncovered functions.
     */
    cmsIT8TableCount(hIT8);
    cmsIT8GetPatchByName(hIT8, str1);
    cmsIT8SetIndexColumn(hIT8, str2);

    /*
     * ANALYSIS: The function-level coverage report showed cmsIT8GetPropertyDbl,
     *           cmsIT8GetDataDbl, and cmsIT8SetDataRowColDbl had 0% or low coverage.
     * IMPLEMENTATION: The following calls exercise these uncovered functions
     *                 with fuzzer-generated data.
     */
    cmsIT8GetPropertyDbl(hIT8, str1);
    cmsIT8GetDataDbl(hIT8, str1, str2);

    int row = 0;
    if (size >= offset + sizeof(int)) {
      memcpy(&row, data + offset, sizeof(int));
      offset += sizeof(int);
    }
    int col = 0;
    if (size >= offset + sizeof(int)) {
      memcpy(&col, data + offset, sizeof(int));
      offset += sizeof(int);
    }
    double val = 0.0;
    if (size >= offset + sizeof(double)) {
      memcpy(&val, data + offset, sizeof(double));
      offset += sizeof(double);
    }
    cmsIT8SetDataRowColDbl(hIT8, row, col, val);


    cmsIT8Free(hIT8);
  }

  cmsDeleteContext(context);
  return 0;
}