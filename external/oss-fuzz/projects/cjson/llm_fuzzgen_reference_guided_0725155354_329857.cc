/* BLOCKER_STRATEGY_CONTRACT
required_state: The 'strings' array passed to cJSON_CreateStringArray must contain a NULL pointer, which causes the internal call to cJSON_CreateString to fail (return NULL).
state_constructor: A std::vector<const char*> is created and populated with valid strings. A fuzzer-determined element in this vector is then explicitly set to nullptr.
trigger_api: cJSON_CreateStringArray is called with the array containing the NULL pointer.
preserved_invariants: The FuzzedDataProvider consumption order of the original fuzz target is maintained for existing execution paths. The new logic is isolated in a new 'else if' branch to avoid invalidating existing seeds.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Target: cJSON_CreateStringArray, cJSON_CreateDoubleArray, cJSON_PrintBuffered, cJSON_SetValuestring, cJSON_Compare

  // Create a root object to attach other items to.
  cJSON *root = cJSON_CreateObject();
  if (!root) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_CreateStringArray
   *           had low branch coverage. The line-level report confirmed this was
   *           at line 2706 (count < 0) and line 2732 (empty array case).
   * IMPLEMENTATION: The following code block calls cJSON_CreateStringArray with
   *                 a negative count, a zero count, and a valid positive count
   *                 to exercise these uncovered paths.
   */
  if (fdp.ConsumeBool()) {
    // Target the count < 0 path. This is expected to return NULL.
    cJSON *string_array_neg = cJSON_CreateStringArray(nullptr, -1);
    if (string_array_neg) {
      cJSON_Delete(string_array_neg);
    }
  } else if (fdp.ConsumeBool()) {
    // Target the count = 0 path.
    const char* s_arr[1];
    cJSON *string_array_zero = cJSON_CreateStringArray(s_arr, 0);
     if (string_array_zero) {
      cJSON_Delete(string_array_zero);
    }
  } else if (fdp.ConsumeBool()) {
    /*
     * BLOCKER-SPECIFIC IMPLEMENTATION: The blocker at cJSON.c:2716 is hit
     * when cJSON_CreateString() returns NULL inside cJSON_CreateStringArray.
     * This is triggered by passing a NULL pointer within the 'strings' array.
     * This block creates an array of strings with one element set to NULL
     * to trigger this specific failure condition.
     */
    int count = fdp.ConsumeIntegralInRange<int>(1, 10);
    std::vector<std::string> strings;
    for (int i = 0; i < count; ++i) {
      strings.push_back(fdp.ConsumeRandomLengthString(10));
    }

    std::vector<const char*> c_strings;
    for (const auto& s : strings) {
        c_strings.push_back(s.c_str());
    }

    // Insert a NULL at a random position to trigger the blocker.
    int null_index = fdp.ConsumeIntegralInRange<int>(0, count - 1);
    c_strings[null_index] = nullptr;

    cJSON *string_array_null_element = cJSON_CreateStringArray(c_strings.data(), count);
    if (string_array_null_element) {
      // This should not be reached if the blocker is hit, but is good practice.
      cJSON_Delete(string_array_null_element);
    }
  } else {
    // Target the normal execution path.
    int count = fdp.ConsumeIntegralInRange<int>(1, 10);
    std::vector<std::string> strings;
    for (int i = 0; i < count; ++i) {
      strings.push_back(fdp.ConsumeRandomLengthString(20));
    }
    std::vector<const char*> c_strings;
    for (const auto& s : strings) {
        c_strings.push_back(s.c_str());
    }
    cJSON *string_array = cJSON_CreateStringArray(c_strings.data(), count);
    if (string_array) {
      cJSON_AddItemToObject(root, "string_array", string_array);
    }
  }

  /*
   * ANALYSIS: Similar to cJSON_CreateStringArray, cJSON_CreateDoubleArray
   *           showed low coverage in its error handling and empty array paths.
   * IMPLEMENTATION: The following code calls cJSON_CreateDoubleArray with
   *                 a negative count and a valid positive count to improve coverage.
   */
  if (fdp.ConsumeBool()) {
      // This is expected to return NULL.
      cJSON *double_array_neg = cJSON_CreateDoubleArray(nullptr, -1);
      if (double_array_neg) {
          cJSON_Delete(double_array_neg);
      }
  } else {
      int count = fdp.ConsumeIntegralInRange<int>(0, 10);
      std::vector<double> doubles;
      for (int i = 0; i < count; ++i) {
          doubles.push_back(fdp.ConsumeFloatingPoint<double>());
      }
      cJSON *double_array = cJSON_CreateDoubleArray(doubles.data(), count);
      if (double_array) {
          cJSON_AddItemToObject(root, "double_array", double_array);
      }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_CreateIntArray and
   *           cJSON_CreateFloatArray had low coverage in their error handling paths.
   * IMPLEMENTATION: The following code calls these functions with negative counts
   *                 to exercise the `count < 0` error-handling path.
   */
  if (fdp.ConsumeBool()) {
    cJSON* item = cJSON_CreateIntArray(nullptr, -1);
    if (item) cJSON_Delete(item);
  }
  if (fdp.ConsumeBool()) {
    cJSON* item = cJSON_CreateFloatArray(nullptr, -1);
    if (item) cJSON_Delete(item);
  }

  /*
   * ANALYSIS: The line-level coverage for cJSON_InsertItemInArray showed that
   *           the `which < 0` branch and the `i == array->child` branch
   *           (for insertion at the beginning) were not covered.
   * IMPLEMENTATION: An array is created and cJSON_InsertItemInArray is called
   *                 with `which = -1` and `which = 0` to cover these branches.
   */
  cJSON* array = cJSON_CreateArray();
  if (array) {
    cJSON_AddItemToArray(array, cJSON_CreateNumber(1));
    cJSON* item2 = cJSON_CreateNumber(2);
    if (!cJSON_InsertItemInArray(array, -1, item2)) { // `which < 0` case
        cJSON_Delete(item2);
    }
    cJSON_InsertItemInArray(array, 0, cJSON_CreateNumber(3));  // `i == array->child` case
    cJSON_AddItemToObject(root, "inserted_array", array);
  }

  /*
   * ANALYSIS: The line-level coverage for cJSON_SetValuestring showed that the
   *           branch at L414 `if (object->valuestring == NULL ...)` was never taken.
   * IMPLEMENTATION: A cJSON_String object is created, and its `valuestring` is
   *                 manually set to NULL before calling cJSON_SetValuestring to
   *                 exercise this specific error-handling path.
   */
  cJSON *string_obj = cJSON_CreateString("initial");
  if (string_obj && fdp.ConsumeBool()) {
    free(string_obj->valuestring);
    string_obj->valuestring = NULL;
    std::string new_val = fdp.ConsumeRandomLengthString(20);
    cJSON_SetValuestring(string_obj, new_val.c_str());
  }
  if (string_obj) {
    cJSON_AddItemToObject(root, "string_obj", string_obj);
  }

  /*
   * ANALYSIS: The line-level coverage for cJSON_Compare showed that cJSON_Raw
   *           types were never compared (L3045, L3076).
   * IMPLEMENTATION: Two cJSON_Raw objects are created with fuzzed data and
   *                 then compared using cJSON_Compare to cover this case.
   */
  std::string raw_str1 = fdp.ConsumeRandomLengthString(10);
  std::string raw_str2 = fdp.ConsumeRandomLengthString(10);
  cJSON *raw1 = cJSON_CreateRaw(raw_str1.c_str());
  cJSON *raw2 = cJSON_CreateRaw(raw_str2.c_str());
  if (raw1 && raw2) {
    cJSON_Compare(raw1, raw2, fdp.ConsumeBool());
  }
  if (raw1) cJSON_Delete(raw1);
  if (raw2) cJSON_Delete(raw2);

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_Duplicate_rec had
   *           low coverage. This function is called by cJSON_Duplicate.
   * IMPLEMENTATION: The following code calls cJSON_Duplicate with both recursive
   *                 and non-recursive modes on the main `root` object to improve
   *                 coverage of the duplication logic.
   */
  cJSON *duplicated_root = cJSON_Duplicate(root, fdp.ConsumeBool());
  if (duplicated_root) {
      cJSON_Delete(duplicated_root);
  }

  /*
   * ANALYSIS: The function-level coverage report showed low branch coverage for
   *           `add_item_to_object` and `replace_item_in_object`. This is to
   *           cover cases where a key already exists (for add) or doesn't exist (for replace).
   * IMPLEMENTATION: The following block creates an object and exercises these
   *                 specific edge cases, ensuring any un-added items are freed.
   */
  if (fdp.ConsumeBool()) {
    cJSON *test_obj = cJSON_CreateObject();
    if (test_obj) {
      cJSON_AddItemToObject(test_obj, "key", cJSON_CreateString("value1"));
      
      // Try to add another item with the same key. It should not be added.
      cJSON *item_to_not_add = cJSON_CreateString("value2");
      if (item_to_not_add) {
        if (!cJSON_AddItemToObject(test_obj, "key", item_to_not_add)) {
          // If item was not added, we must delete it.
          cJSON_Delete(item_to_not_add);
        }
      }
      
      // Try to replace an item for a key that doesn't exist. It should not be added.
      cJSON *item_to_not_replace = cJSON_CreateString("another_value");
      if (item_to_not_replace) {
        if (!cJSON_ReplaceItemInObject(test_obj, "non_existent_key", item_to_not_replace)) {
          cJSON_Delete(item_to_not_replace);
        }
      }
      cJSON_AddItemToObject(root, "test_obj", test_obj);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report indicates that `cJSON_Minify`,
   *           `cJSON_PrintUnformatted`, and `cJSON_PrintPreallocated` are not
   *           covered. `ensure` also has very low coverage.
   * IMPLEMENTATION: The following blocks call these functions.
   *           `cJSON_PrintPreallocated` is called with a small buffer to stress
   *           the `ensure` function's reallocation logic.
   */
  char *printed_for_minify = cJSON_Print(root);
  if (printed_for_minify) {
    cJSON_Minify(printed_for_minify); // In-place
    free(printed_for_minify);
  }

  char *unformatted = cJSON_PrintUnformatted(root);
  if (unformatted) {
    free(unformatted);
  }

  int prebuffer_size = fdp.ConsumeIntegralInRange<int>(1, 128);
  char* prealloc_buf = (char*)malloc(prebuffer_size);
  if (prealloc_buf) {
    cJSON_PrintPreallocated(root, prealloc_buf, prebuffer_size, fdp.ConsumeBool());
    free(prealloc_buf);
  }

  /*
   * ANALYSIS: The line-level coverage for cJSON_PrintBuffered showed that the
   *           `prebuffer < 0` check at L1289 was never hit.
   * IMPLEMENTATION: The code calls cJSON_PrintBuffered with a negative
   *                 prebuffer size to exercise this error path. This call is
   *                 expected to return NULL.
   */
  if (fdp.ConsumeBool()) {
      char *out_neg = cJSON_PrintBuffered(root, -1, fdp.ConsumeBool());
      if (out_neg) {
          free(out_neg);
      }
  }

  // Normal call to cJSON_PrintBuffered to exercise main logic.
  char *out = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange<int>(0, 1024), fdp.ConsumeBool());
  if (out) {
    free(out);
  }

  cJSON_Delete(root);

  return 0;
}
