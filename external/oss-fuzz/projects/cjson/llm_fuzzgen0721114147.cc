#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/cjson/cJSON.h"

// Custom malloc function for testing cJSON_InitHooks
void *custom_malloc(size_t size) {
    return malloc(size);
}

// Custom free function for testing cJSON_InitHooks
void custom_free(void *ptr) {
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Consume data for various operations
  std::string str1 = fdp.ConsumeRandomLengthString(100);
  std::string str2 = fdp.ConsumeRandomLengthString(100);
  const char *error_ptr = nullptr;

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_InitHooks had 0% coverage.
   *           The line-level report confirmed that branches for both NULL and non-NULL
   *           hooks, as well as setting individual allocation functions, were not covered.
   * IMPLEMENTATION: The following code block exercises cJSON_InitHooks. It sometimes
   *                 passes NULL to reset hooks to default. Other times, it passes a
   *                 cJSON_Hooks struct with malloc_fn and free_fn either set or not,
   *                 based on fuzzer input, to cover all branches.
   */
  if (fdp.ConsumeBool()) {
    cJSON_InitHooks(NULL);
  } else {
    cJSON_Hooks hooks;
    hooks.malloc_fn = fdp.ConsumeBool() ? custom_malloc : NULL;
    hooks.free_fn = fdp.ConsumeBool() ? custom_free : NULL;
    cJSON_InitHooks(&hooks);
  }

  // Create a variety of JSON objects for testing
  cJSON *json_num = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
  cJSON *json_str = cJSON_CreateString(fdp.ConsumeRandomLengthString(50).c_str());
  cJSON *json_bool = cJSON_CreateBool(fdp.ConsumeBool());
  cJSON *json_null = cJSON_CreateNull();

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_ParseWithOpts had low
   *           branch coverage. The line-level report confirmed the branch at line 1103,
   *           in the `if (NULL == value)` check, was never taken.
   * IMPLEMENTATION: The following code block sometimes passes a NULL pointer as the first
   *                 argument to cJSON_ParseWithOpts to exercise this uncovered error path.
   */
  cJSON *parsed_json1 = nullptr;
  if (fdp.ConsumeBool()) {
    parsed_json1 = cJSON_ParseWithOpts(NULL, &error_ptr, fdp.ConsumeBool());
  } else {
    parsed_json1 = cJSON_ParseWithOpts(str1.c_str(), &error_ptr, fdp.ConsumeBool());
  }

  cJSON *parsed_json2 = cJSON_Parse(str2.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_Compare had 0% coverage.
   *           The line-level report showed numerous uncovered paths, including NULL
   *           checks, type comparisons, and comparisons of identical objects.
   * IMPLEMENTATION: The following calls to cJSON_Compare are designed to cover these
   *                 paths by comparing various object combinations:
   *                 1. A parsed object against itself (for the identical object check).
   *                 2. Two different parsed objects.
   *                 3. A parsed object against NULL.
   *                 4. Two objects of different, known types.
   */
  if (parsed_json1) {
    cJSON_Compare(parsed_json1, parsed_json1, fdp.ConsumeBool());
  }
  cJSON_Compare(parsed_json1, parsed_json2, fdp.ConsumeBool());
  cJSON_Compare(parsed_json1, NULL, fdp.ConsumeBool());
  cJSON_Compare(json_num, json_str, fdp.ConsumeBool());

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_SetValuestring was
   *           completely uncovered. The line-level report indicated missed branches for
   *           object type checks, NULL value checks, and string length comparisons.
   * IMPLEMENTATION: The following code calls cJSON_SetValuestring on a string object
   *                 with a fuzzer-provided string to cover the main logic. It also
   *                 calls it on a non-string object (json_num) to trigger the type
   *                 check error path.
   */
  if (json_str) {
    std::string new_val = fdp.ConsumeRandomLengthString(50);
    cJSON_SetValuestring(json_str, new_val.c_str());
  }
  // Call on a non-string object to hit the type check branch
  cJSON_SetValuestring(json_num, "should fail");

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_SetNumberHelper was
   *           completely uncovered. Analysis of cJSON_SetNumberValue revealed that
   *           cJSON_SetNumberHelper is only called when cJSON_SetNumberValue is used
   *           on a non-number cJSON object.
   * IMPLEMENTATION: The following code calls cJSON_SetNumberValue on a string object
   *                 to trigger the call to the uncovered cJSON_SetNumberHelper function.
   */
  if (json_str) {
    cJSON_SetNumberValue(json_str, fdp.ConsumeFloatingPoint<double>());
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_PrintPreallocated was
   *           uncovered. The line-level report showed the initial check for a negative
   *           length or a NULL buffer was never executed.
   * IMPLEMENTATION: The code below calls cJSON_PrintPreallocated with a valid buffer,
   *                 a negative length, and a NULL buffer to ensure these specific
   *                 error-handling branches are exercised.
   */
  if (parsed_json1) {
    std::vector<char> buffer(1024);
    cJSON_PrintPreallocated(parsed_json1, buffer.data(), buffer.size(), fdp.ConsumeBool());
    // Test error conditions
    cJSON_PrintPreallocated(parsed_json1, buffer.data(), -1, fdp.ConsumeBool());
    cJSON_PrintPreallocated(parsed_json1, NULL, buffer.size(), fdp.ConsumeBool());
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_Version,
   *           cJSON_GetStringValue, cJSON_GetNumberValue, and the entire family of
   *           cJSON_Is<Type> functions were uncovered.
   * IMPLEMENTATION: The following code block adds direct calls to these simple
   *                 getter and type-checking functions to achieve coverage.
   */
  cJSON_Version();
  if (json_str) {
    cJSON_GetStringValue(json_str);
    cJSON_IsString(json_str);
  }
  if (json_num) {
    cJSON_GetNumberValue(json_num);
    cJSON_IsNumber(json_num);
  }
  if (json_bool) {
    cJSON_IsBool(json_bool);
    cJSON_IsTrue(json_bool);
    cJSON_IsFalse(json_bool);
  }
  if (json_null) {
    cJSON_IsNull(json_null);
  }

  cJSON *root_obj = cJSON_CreateObject();
  cJSON *root_arr = cJSON_CreateArray();

  if (root_obj) {
    cJSON_AddItemToObject(root_obj, "number", cJSON_CreateNumber(fdp.ConsumeIntegral<int>()));
    cJSON_GetObjectItem(root_obj, "number");

    /*
     * ANALYSIS: The coverage report showed 0% coverage for cJSON_HasObjectItem,
     *           cJSON_GetObjectItemCaseSensitive, and cJSON_ReplaceItemInObject.
     * IMPLEMENTATION: This block adds an item, checks for it using cJSON_HasObjectItem
     *                 and cJSON_GetObjectItemCaseSensitive, and then replaces it with
     *                 cJSON_ReplaceItemInObject to exercise these uncovered functions.
     */
    const char *key_to_replace = "key_to_replace";
    cJSON_AddItemToObject(root_obj, key_to_replace, cJSON_CreateString("original_value"));
    cJSON_HasObjectItem(root_obj, key_to_replace);
    cJSON_GetObjectItemCaseSensitive(root_obj, key_to_replace);
    cJSON_ReplaceItemInObject(root_obj, key_to_replace, cJSON_CreateString("new_value"));

    cJSON_DeleteItemFromObject(root_obj, "number"); // Test deletion
  }

  if (root_arr) {
    cJSON_AddItemToArray(root_arr, cJSON_CreateBool(fdp.ConsumeBool()));
    if (cJSON_GetArraySize(root_arr) > 0) {
      cJSON_GetArrayItem(root_arr, 0);
      // Detach an item, which must be manually deleted.
      cJSON *detached = cJSON_DetachItemFromArray(root_arr, 0);
      cJSON_Delete(detached);
    }
    // Add a new item to test replacement
    cJSON_AddItemToArray(root_arr, cJSON_CreateNull());
    if (cJSON_GetArraySize(root_arr) > 0) {
      // Replacement item's ownership is passed to the array.
      cJSON_ReplaceItemInArray(root_arr, 0, cJSON_CreateString("replacement"));
    }
    /*
     * ANALYSIS: The coverage report showed cJSON_InsertItemInArray was completely
     *           uncovered. Its source shows checks for negative, in-bounds, and
     *           out-of-bounds indices.
     * IMPLEMENTATION: This block calls cJSON_InsertItemInArray with an index from
     *                 the fuzzer to exercise all branching paths. If insertion fails
     *                 (returns false), the item to be inserted must be manually deleted.
     */
    cJSON *item_to_insert = cJSON_CreateString("inserted");
    int insert_idx = fdp.ConsumeIntegralInRange<int>(-1, 5);
    if (!cJSON_InsertItemInArray(root_arr, insert_idx, item_to_insert)) {
        cJSON_Delete(item_to_insert);
    }
  }

  // Check type and duplicate
  if (root_obj) {
    cJSON_IsObject(root_obj);
    cJSON *dupe = cJSON_Duplicate(root_obj, fdp.ConsumeBool());
    cJSON_Delete(dupe);
  }
  if (root_arr) {
    cJSON_IsArray(root_arr);
  }

  /*
   * ANALYSIS: The coverage report showed the cJSON_Create...Array family of functions
   *           (Int, Float, Double, String) were all completely uncovered.
   * IMPLEMENTATION: This block creates small C-style arrays with fuzzer data and
   *                 calls each of the cJSON_Create...Array functions to cover them.
   *                 The resulting cJSON objects are then deleted.
   */
  const int array_count = fdp.ConsumeIntegralInRange<int>(0, 5);
  if (array_count > 0) {
    std::vector<int> ints(array_count);
    for (int i = 0; i < array_count; i++) ints[i] = fdp.ConsumeIntegral<int>();
    cJSON *int_array = cJSON_CreateIntArray(ints.data(), array_count);
    cJSON_Delete(int_array);

    std::vector<float> floats(array_count);
    for (int i = 0; i < array_count; i++) floats[i] = fdp.ConsumeFloatingPoint<float>();
    cJSON *float_array = cJSON_CreateFloatArray(floats.data(), array_count);
    cJSON_Delete(float_array);

    std::vector<double> doubles(array_count);
    for (int i = 0; i < array_count; i++) doubles[i] = fdp.ConsumeFloatingPoint<double>();
    cJSON *double_array = cJSON_CreateDoubleArray(doubles.data(), array_count);
    cJSON_Delete(double_array);

    std::vector<std::string> strings;
    std::vector<const char*> c_strings;
    for (int i = 0; i < array_count; i++) strings.push_back(fdp.ConsumeRandomLengthString(20));
    for (const auto& s : strings) c_strings.push_back(s.c_str());
    cJSON *string_array = cJSON_CreateStringArray(c_strings.data(), array_count);
    cJSON_Delete(string_array);
  }

  /*
   * ANALYSIS: The coverage report showed cJSON_Minify was largely uncovered.
   * IMPLEMENTATION: This block prints a JSON object to a string, copies it to a
   *                 mutable buffer, and then calls cJSON_Minify on it to exercise
   *                 in-place minification. The original string from cJSON_Print is freed.
   */
  if (root_obj) {
      char *printed_obj = cJSON_Print(root_obj);
      if (printed_obj) {
          std::vector<char> minify_buffer(printed_obj, printed_obj + strlen(printed_obj) + 1);
          cJSON_Minify(minify_buffer.data());
          free(printed_obj);
      }
  }

  // Cleanup: All allocated cJSON objects must be deleted to prevent memory leaks.
  cJSON_Delete(json_num);
  cJSON_Delete(json_str);
  cJSON_Delete(json_bool);
  cJSON_Delete(json_null);
  if (parsed_json1) {
    cJSON_Delete(parsed_json1);
  }
  if (parsed_json2) {
    cJSON_Delete(parsed_json2);
  }
  cJSON_Delete(root_obj);
  cJSON_Delete(root_arr);
  
  // Reset hooks to default to avoid affecting other fuzz targets
  cJSON_InitHooks(NULL);

  return 0;
}