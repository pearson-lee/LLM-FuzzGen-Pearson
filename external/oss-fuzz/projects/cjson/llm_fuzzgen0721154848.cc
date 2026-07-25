#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  std::string json_str = fdp.ConsumeRandomLengthString(size);
  char *writable_str = (char *)malloc(json_str.length() + 1);
  if (!writable_str) {
    return 0;
  }
  memcpy(writable_str, json_str.c_str(), json_str.length());
  writable_str[json_str.length()] = '\0';

  cJSON *root = cJSON_Parse(writable_str);
  free(writable_str);

  if (root == nullptr) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed that `cJSON_Print` and
   *           `cJSON_PrintUnformatted` were never executed. These functions are the
   *           entry points for unbuffered printing and exercise the internal `print`
   *           function, which had very low coverage (55%).
   * IMPLEMENTATION: This block calls both `cJSON_Print` and `cJSON_PrintUnformatted`
   *                 on the root object. The returned strings are freed with `cJSON_free`
   *                 to prevent memory leaks. This directly addresses the coverage gap.
   */
  if (fdp.ConsumeBool()) {
    char *printed_json = cJSON_Print(root);
    if (printed_json) {
      cJSON_free(printed_json);
    }
    char *printed_unformatted_json = cJSON_PrintUnformatted(root);
    if (printed_unformatted_json) {
      cJSON_free(printed_unformatted_json);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed that `cJSON_Duplicate` and
   *           `cJSON_Compare` were completely uncovered. `cJSON_Duplicate` calls the
   *           recursive `cJSON_Duplicate_rec`, which also had poor coverage.
   * IMPLEMENTATION: This block calls `cJSON_Duplicate` to create a copy of the root
   *                 object. It then calls `cJSON_Compare` to compare the original and
   *                 the duplicate, which will exercise the "equal" paths in the
   *                 comparison logic. The duplicated object is deleted to prevent leaks.
   */
  if (fdp.ConsumeBool()) {
    cJSON *duplicate = cJSON_Duplicate(root, fdp.ConsumeBool());
    if (duplicate) {
      cJSON_Compare(root, duplicate, fdp.ConsumeBool());
      cJSON_Delete(duplicate);
    }
  }

  /*
   * ANALYSIS: The line-level report for `cJSON_ReplaceItemViaPointer` showed that the
   *           branch at line 374 (`if (item->parent != parent)`) was never taken. This
   *           is an error check to ensure the item being replaced is a child of the
   *           specified parent.
   * IMPLEMENTATION: This block creates two separate parent objects. An item is added
   *                 to the first parent. Then, `cJSON_ReplaceItemViaPointer` is called
   *                 with the second parent and the item from the first. This creates the
   *                 exact condition needed to trigger the uncovered error-handling branch.
   */
  if (fdp.ConsumeBool()) {
    cJSON *parent1 = cJSON_CreateObject();
    cJSON *parent2 = cJSON_CreateObject();
    cJSON *item1 = cJSON_CreateString("item1");
    cJSON *new_item = cJSON_CreateString("new_item");
    if (parent1 && parent2 && item1 && new_item) {
      cJSON_AddItemToObject(parent1, "key", item1);
      // This call should fail because item1's parent is parent1, not parent2.
      if (!cJSON_ReplaceItemViaPointer(parent2, item1, new_item)) {
        // If replacement fails, new_item is not consumed, so we must free it.
        cJSON_Delete(new_item);
      }
    } else {
      // Cleanup if any initial creation failed
      if (new_item) cJSON_Delete(new_item);
      if (item1) cJSON_Delete(item1);
    }
    if (parent1) cJSON_Delete(parent1);
    if (parent2) cJSON_Delete(parent2);
  }

  // Final cleanup: delete the root JSON object and all its children.
  cJSON_Delete(root);

  return 0;
}