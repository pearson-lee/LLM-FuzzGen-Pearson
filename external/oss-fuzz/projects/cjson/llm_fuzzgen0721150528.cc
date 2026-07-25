#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Main fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a base JSON object for various test scenarios
  cJSON *root = cJSON_CreateObject();
  if (!root) {
    // If root creation fails, we cannot proceed.
    return 0;
  }

  // Add some initial items to the object to make it non-trivial
  cJSON_AddItemToObject(root, "name", cJSON_CreateString(fdp.ConsumeRandomLengthString(16).c_str()));
  cJSON_AddItemToObject(root, "value", cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));

  /*
   * ANALYSIS: The function-level coverage report showed `cJSON_PrintBuffered` has low
   *           branch coverage (66.67%). The detailed line-level report revealed that the
   *           error handling block starting at line 1306 (`if (!print_value(item, &p))`)
   *           is never executed because `print_value` never returns `false`.
   *           Further analysis of `print_value` showed its `default` switch case
   *           (line 1459) is never hit, which would cause a `false` return.
   * IMPLEMENTATION: This block creates a cJSON item and manually sets its type to an
   *                 invalid value outside the standard cJSON types. This item is added to
   *                 the JSON object. When `cJSON_PrintBuffered` is called, `print_value`
   *                 will hit the `default` case for this invalid item, return `false`,
   *                 and trigger the previously uncovered error handling path in
   *                 `cJSON_PrintBuffered`.
   */
  if (fdp.ConsumeBool()) {
    cJSON *invalid_item = cJSON_CreateNull();
    if (invalid_item) {
      // Assign an invalid type not in the cJSON_Types enum
      invalid_item->type = fdp.ConsumeIntegralInRange<int>(20, 100);
      cJSON_AddItemToObject(root, "invalid_type_item", invalid_item);
    }
  }

  // Call cJSON_PrintBuffered, which may now fail due to the invalid item.
  // The returned buffer must be freed.
  char *buffered_print_output = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange<int>(256, 1024), fdp.ConsumeBool());
  if (buffered_print_output) {
    cJSON_free(buffered_print_output);
  }

  /*
   * ANALYSIS: The line-level coverage for the internal `ensure` function showed that the
   *           `if (p->noalloc)` branch at line 486 is almost never taken. This path is
   *           critical for handling buffer limits when printing to a pre-allocated buffer.
   *           The public API `cJSON_PrintPreallocated` sets this `noalloc` flag.
   * IMPLEMENTATION: This block calls `cJSON_PrintPreallocated` with a small, fixed-size
   *                 stack buffer. The JSON object is likely larger than this buffer, forcing
   *                 the call to `ensure` to fail when it checks the `noalloc` flag. This
   *                 exercises the important error handling path for pre-allocated printing.
   */
  if (fdp.ConsumeBool()) {
    char preallocated_buffer[64];
    cJSON_PrintPreallocated(root, preallocated_buffer, sizeof(preallocated_buffer), fdp.ConsumeBool());
  }

  /*
   * ANALYSIS: The coverage report for `case_insensitive_strcmp` indicated that
   *           null-input checks and the identical-pointer check were uncovered.
   *           This function is static and not directly callable. It is used by
   *           case-insensitive search functions like cJSON_GetObjectItem.
   * IMPLEMENTATION: This block calls `cJSON_GetObjectItem` with various inputs
   *                 to cover the identified gaps in the underlying
   *                 `case_insensitive_strcmp` function:
   *                 1. A NULL key to test the null-input check.
   *                 2. The key of an existing item to test the identical-pointer check.
   */
  if (fdp.ConsumeBool()) {
    std::string key_str = fdp.ConsumeRandomLengthString(16);
    const char *key = key_str.c_str();

    // Test normal comparison
    cJSON_GetObjectItem(root, key);

    // Test NULL input check
    cJSON_GetObjectItem(root, NULL);

    // Test identical pointer check
    cJSON *item = cJSON_GetObjectItem(root, "name");
    if (item && item->string) {
      cJSON_GetObjectItem(root, item->string);
    }
  }

  /*
   * ANALYSIS: The `create_reference` function's line-level coverage showed that the
   *           `if (item == NULL)` check at line 1967 was never executed. This internal
   *           function is called by the public APIs `cJSON_CreateObjectReference` and
   *           `cJSON_CreateArrayReference`.
   * IMPLEMENTATION: This block calls `cJSON_CreateObjectReference` and
   *                 `cJSON_CreateArrayReference` with a NULL argument. This directly
   *                 targets the uncovered null-check branch within `create_reference`,
   *                 ensuring this error path is tested. The returned objects are deleted.
   */
  if (fdp.ConsumeBool()) {
    cJSON *obj_ref = cJSON_CreateObjectReference(NULL);
    if (obj_ref) cJSON_Delete(obj_ref);

    cJSON *arr_ref = cJSON_CreateArrayReference(NULL);
    if (arr_ref) cJSON_Delete(arr_ref);
  }

  // Final cleanup: delete the root JSON object and all its children.
  cJSON_Delete(root);

  return 0;
}