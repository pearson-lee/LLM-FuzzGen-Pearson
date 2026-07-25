/* BLOCKER_STRATEGY_CONTRACT
required_state: The `input_buffer->hooks.allocate` function pointer must return `NULL` when called from within the `parse_string` function.
state_constructor: A controlled, stateful allocator (`controlled_failing_malloc`) is installed via `cJSON_InitHooks`. This allocator is designed to fail (return `NULL`) on a specific allocation attempt, with the target attempt number being drawn from the fuzzer's input via `FuzzedDataProvider`. This allows the fuzzer to discover which allocation number corresponds to the one inside `parse_string`.
trigger_api: `cJSON_Parse()`. The existing logic that parses a fuzzer-generated string is sufficient to call `parse_string` and thus trigger the custom allocator.
preserved_invariants: The fuzz target's original input consumption contract is preserved. The custom allocator is installed conditionally and reset after use, allowing the original fuzzing logic to proceed on subsequent runs or when the conditional block is not taken. The core `cJSON_Parse` call and subsequent operations on the parsed object remain intact.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/cjson/cJSON.h"

//
// BLOCKER-SPECIFIC DEFINITIONS
//
// State for the controlled failing allocator.
static int allocation_counter = 0;
static int allocation_fail_at = -1;

// A malloc wrapper that will fail at a predetermined allocation number.
void* controlled_failing_malloc(size_t size) {
  if (allocation_counter == allocation_fail_at) {
    allocation_counter++;
    return NULL; // Intentionally fail this allocation.
  }
  allocation_counter++;
  return malloc(size);
}

// A free wrapper to pair with the custom malloc.
void controlled_free(void* ptr) {
  free(ptr);
}
//
// END BLOCKER-SPECIFIC DEFINITIONS
//

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // BLOCKER-SPECIFIC LOGIC: Conditionally install a failing allocator
  // to trigger an allocation failure inside cJSON's parsing logic.
  if (fdp.ConsumeBool()) {
    allocation_counter = 0;
    // Let the fuzzer pick which allocation should fail. A small range is
    // sufficient to find the allocation within parse_string.
    allocation_fail_at = fdp.ConsumeIntegralInRange<int>(0, 10);
    cJSON_Hooks hooks = {controlled_failing_malloc, controlled_free};
    cJSON_InitHooks(&hooks);
  }

  std::string json_str = fdp.ConsumeRandomLengthString(size);
  char *writable_str = (char *)malloc(json_str.length() + 1);
  if (!writable_str) {
    // Reset hooks in case of early exit.
    cJSON_InitHooks(NULL);
    return 0;
  }
  memcpy(writable_str, json_str.c_str(), json_str.length());
  writable_str[json_str.length()] = '\0';

  cJSON *root = cJSON_Parse(writable_str);
  free(writable_str);

  // BLOCKER-SPECIFIC LOGIC: Reset the memory hooks to default so that
  // subsequent operations in the fuzz target behave as expected.
  cJSON_InitHooks(NULL);

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