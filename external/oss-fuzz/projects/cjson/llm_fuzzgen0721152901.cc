#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>

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

  /*
   * ANALYSIS: The function-level coverage report shows that many of the
   *           `cJSON_Add<Type>ToObject` functions have low branch coverage (50%).
   *           The detailed line-level report for `cJSON_AddNullToObject` reveals
   *           that the error handling path, where `add_item_to_object` returns
   *           false, is never taken. This is because `add_item_to_object`
   *           only fails if the root object is invalid (e.g., NULL).
   * IMPLEMENTATION: This block calls various `cJSON_Add<Type>ToObject`
   *                 functions with a NULL `object` argument. This directly
   *                 triggers the uncovered error handling path within these
   *                 functions, improving their branch coverage.
   */
  if (fdp.ConsumeBool()) {
    const char *key = "key";
    cJSON_AddNullToObject(NULL, key);
    cJSON_AddTrueToObject(NULL, key);
    cJSON_AddFalseToObject(NULL, key);
    cJSON_AddBoolToObject(NULL, key, fdp.ConsumeBool());
    cJSON_AddNumberToObject(NULL, key, fdp.ConsumeIntegral<int>());
    cJSON_AddStringToObject(NULL, key, "value");
    cJSON_AddRawToObject(NULL, key, "raw");
    cJSON_AddObjectToObject(NULL, key);
    cJSON_AddArrayToObject(NULL, key);
  }

  /*
   * ANALYSIS: The line-level coverage for `cJSON_SetValuestring` shows that the
   *           check for overlapping strings at line 425 is not fully covered.
   *           Specifically, the condition `object->valuestring + v2_len < valuestring`
   *           is never false, meaning the overlapping string case is not triggered.
   * IMPLEMENTATION: This block creates a string item and then calls
   *                 `cJSON_SetValuestring` with a pointer to the middle of the
   *                 item's own string. This creates an overlapping memory scenario
   *                 that triggers the previously uncovered error handling path.
   */
  if (fdp.ConsumeBool()) {
    cJSON *string_item = cJSON_CreateString("a long string to test overlap");
    if (string_item && string_item->valuestring) {
      cJSON_SetValuestring(string_item, string_item->valuestring + 5);
    }
    if (string_item) {
      cJSON_Delete(string_item);
    }
  }

  /*
   * ANALYSIS: The line-level coverage for `cJSON_CreateRaw` shows that the
   *           error handling path at line 2546 for a failed `cJSON_strdup` is
   *           never taken. This can be triggered by passing a NULL pointer.
   * IMPLEMENTATION: This block calls `cJSON_CreateRaw` with a NULL argument,
   *                 which causes the internal `cJSON_strdup` to fail, exercising
   *                 the uncovered error handling logic.
   */
  if (fdp.ConsumeBool()) {
    cJSON *raw_item = cJSON_CreateRaw(NULL);
    if (raw_item) {
      cJSON_Delete(raw_item);
    }
  }

  /*
   * ANALYSIS: The line-level coverage for `cJSON_CreateIntArray` and its
   *           related functions (`Float`, `Double`, `String`) shows that the
   *           case where the input `count` is zero is not tested. This prevents
   *           coverage of the path where an empty array is created.
   * IMPLEMENTATION: This block calls the various `cJSON_Create...Array`
   *                 functions with a `count` of 0. This ensures the logic
   *                 for handling empty array creation is exercised.
   */
  if (fdp.ConsumeBool()) {
    const int nums[] = {1, 2, 3};
    cJSON *arr = cJSON_CreateIntArray(nums, 0);
    if (arr) cJSON_Delete(arr);

    const float floats[] = {1.0f, 2.0f};
    arr = cJSON_CreateFloatArray(floats, 0);
    if (arr) cJSON_Delete(arr);
  }

  /*
   * ANALYSIS: The coverage for `cJSON_DetachItemViaPointer` shows that the
   *           case for detaching a middle item (not first or last) is not
   *           covered. Additionally, the null-check for the `parent` argument
   *           is not exercised.
   * IMPLEMENTATION: This block creates an object with three items, then
   *                 detaches the middle one to exercise that specific logic.
   *                 It also calls the function with a NULL parent to hit the
   *                 uncovered error-checking branch.
   */
  if (fdp.ConsumeBool()) {
    cJSON* parent = cJSON_CreateObject();
    if (parent) {
      cJSON_AddItemToObject(parent, "first", cJSON_CreateNumber(1));
      cJSON_AddItemToObject(parent, "second", cJSON_CreateNumber(2));
      cJSON_AddItemToObject(parent, "third", cJSON_CreateNumber(3));

      cJSON* second_item = cJSON_GetObjectItem(parent, "second");
      if (second_item) {
        cJSON* detached = cJSON_DetachItemViaPointer(parent, second_item);
        if (detached) {
          cJSON_Delete(detached);
        }
      }
      
      cJSON* first_item = cJSON_GetObjectItem(parent, "first");
      if (first_item) {
        cJSON_DetachItemViaPointer(NULL, first_item);
      }
      cJSON_Delete(parent);
    }
  }

  /*
   * ANALYSIS: The line-level coverage for `cJSON_Minify` indicates that the
   *           initial `if (json == NULL)` check is never taken. Also, the
   *           logic for skipping comments is not exercised.
   * IMPLEMENTATION: This block calls `cJSON_Minify` with NULL to hit the
   *                 uncovered null check. It also creates a writable string
   *                 containing comments and passes it to `cJSON_Minify` to
   *                 exercise the comment-skipping logic.
   */
  if (fdp.ConsumeBool()) {
    cJSON_Minify(NULL);
    std::string with_comments = "{\n// comment\n\"key\": /* another */ \"value\"\n}";
    char* writable_str = strdup(with_comments.c_str());
    if (writable_str) {
        cJSON_Minify(writable_str);
        free(writable_str);
    }
  }

  // Final cleanup: delete the root JSON object and all its children.
  cJSON_Delete(root);

  return 0;
}