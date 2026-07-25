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

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_malloc was uncovered.
   *           This is a simple wrapper around the internal allocation function.
   * IMPLEMENTATION: The following code calls cJSON_malloc and cJSON_free to
   *                 exercise this wrapper.
   */
  void *mem = cJSON_malloc(128);
  if (mem) {
      cJSON_free(mem);
  }

  // Create a variety of JSON objects for testing
  cJSON *json_num = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
  cJSON *json_str = cJSON_CreateString(fdp.ConsumeRandomLengthString(50).c_str());
  cJSON *json_bool = cJSON_CreateBool(fdp.ConsumeBool());
  cJSON *json_null = cJSON_CreateNull();
  /*
   * ANALYSIS: The function-level coverage report showed cJSON_CreateTrue and
   *           cJSON_CreateFalse were uncovered.
   * IMPLEMENTATION: The following code calls these functions and stores the
   *                 result. The objects are deleted at the end of the test.
   */
  cJSON *json_true = cJSON_CreateTrue();
  cJSON *json_false = cJSON_CreateFalse();


  /*
   * ANALYSIS: The function-level coverage report showed cJSON_ParseWithOpts had low
   *           branch coverage. The line-level report confirmed the branch at line 1103,
   *           in the `if (NULL == value)` check, was never taken. The report also
   *           showed cJSON_GetErrorPtr was uncovered.
   * IMPLEMENTATION: The following code block sometimes passes a NULL pointer as the first
   *                 argument to cJSON_ParseWithOpts to exercise this uncovered error path.
   *                 It also calls cJSON_GetErrorPtr after a parse failure to improve coverage.
   */
  cJSON *parsed_json1 = nullptr;
  if (fdp.ConsumeBool()) {
    parsed_json1 = cJSON_ParseWithOpts(NULL, &error_ptr, fdp.ConsumeBool());
    cJSON_GetErrorPtr();
  } else {
    parsed_json1 = cJSON_ParseWithOpts(str1.c_str(), &error_ptr, fdp.ConsumeBool());
    if (!parsed_json1) {
      cJSON_GetErrorPtr();
    }
  }

  cJSON *parsed_json2 = cJSON_Parse(str2.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_ParseWithLength was
   *           completely uncovered.
   * IMPLEMENTATION: The following code calls cJSON_ParseWithLength with a substring
   *                 of the fuzzer input data to exercise this function.
   */
  std::string str3 = fdp.ConsumeRandomLengthString(100);
  cJSON *parsed_json3 = cJSON_ParseWithLength(str3.c_str(), str3.length());


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
   * ANALYSIS: The line-level coverage for cJSON_SetValuestring showed several
   *           uncovered branches: checking for a NULL object, a NULL value
   *           argument, and checking if the object is a reference.
   * IMPLEMENTATION: The following code calls cJSON_SetValuestring with a NULL
   *                 object and a NULL value to cover the error-handling paths.
   *                 It also creates a string reference and attempts to set its
   *                 value to cover the reference check.
   */
  cJSON_SetValuestring(NULL, "test");
  if (json_str) {
      cJSON_SetValuestring(json_str, NULL);
  }
  cJSON *str_ref_for_set = cJSON_CreateStringReference("ref");
  if (str_ref_for_set) {
      cJSON_SetValuestring(str_ref_for_set, "new_val");
      cJSON_Delete(str_ref_for_set);
  }

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
   *           length or a NULL buffer was never executed. It also showed that the error
   *           path in the internal 'ensure' function when a preallocated buffer is too
   *           small was not covered.
   * IMPLEMENTATION: The code below calls cJSON_PrintPreallocated with a valid buffer
   *                 of random size (to sometimes trigger the too-small condition), a
   *                 negative length, and a NULL buffer to ensure these specific
   *                 error-handling branches are exercised.
   */
  if (parsed_json1) {
    std::vector<char> buffer(fdp.ConsumeIntegralInRange<size_t>(1, 1024));
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
    /*
     * ANALYSIS: The line-level coverage report for cJSON_GetNumberValue showed
     *           the branch for handling a non-number item was not taken.
     * IMPLEMENTATION: The following code calls cJSON_GetNumberValue with a
     *                 string item to cover this error-handling path.
     */
    cJSON_GetNumberValue(json_str);
  }
  if (json_num) {
    cJSON_GetNumberValue(json_num);
    cJSON_IsNumber(json_num);
    /*
     * ANALYSIS: The line-level coverage report for cJSON_GetStringValue showed
     *           the branch for handling a non-string item was not taken.
     * IMPLEMENTATION: The following code calls cJSON_GetStringValue with a
     *                 number item to cover this error-handling path.
     */
    cJSON_GetStringValue(json_num);
  }
  if (json_bool) {
    cJSON_IsBool(json_bool);
    cJSON_IsTrue(json_bool);
    cJSON_IsFalse(json_bool);
  }
  if (json_null) {
    cJSON_IsNull(json_null);
  }
  /*
   * ANALYSIS: The line-level coverage report for all cJSON_Is<Type> functions
   *           showed that the initial `if (item == NULL)` check was never taken.
   * IMPLEMENTATION: The following code calls all cJSON_Is<Type> functions with
   *                 a NULL argument to cover this common error-handling path.
   */
  cJSON_IsInvalid(NULL);
  cJSON_IsFalse(NULL);
  cJSON_IsTrue(NULL);
  cJSON_IsBool(NULL);
  cJSON_IsNull(NULL);
  cJSON_IsNumber(NULL);
  cJSON_IsString(NULL);
  cJSON_IsArray(NULL);
  cJSON_IsObject(NULL);
  cJSON_IsRaw(NULL);


  cJSON *root_obj = cJSON_CreateObject();
  cJSON *another_obj = cJSON_CreateObject();
  cJSON *root_arr = cJSON_CreateArray();
  cJSON *item_to_ref = cJSON_CreateString("referenced string");

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

    /*
     * ANALYSIS: The coverage report showed 0% coverage for cJSON_AddItemToObjectCS
     *           and the cJSON_Add<Type>ToObject family of functions (e.g. cJSON_AddNullToObject).
     * IMPLEMENTATION: This block adds items using cJSON_AddNullToObject and
     *                 cJSON_AddItemToObjectCS to cover these previously uncovered functions.
     */
    cJSON_AddNullToObject(root_obj, "null_item_cs");
    cJSON_AddItemToObjectCS(root_obj, "cs_item", cJSON_CreateString("cs_value"));

    /*
     * ANALYSIS: The function-level coverage report showed the cJSON_Add<Type>ToObject
     *           family of functions (e.g., cJSON_AddTrueToObject) were uncovered.
     * IMPLEMENTATION: This block adds items using these helper functions to cover them.
     */
    cJSON_AddTrueToObject(root_obj, "true_item");
    cJSON_AddFalseToObject(root_obj, "false_item");
    cJSON_AddBoolToObject(root_obj, "bool_item", fdp.ConsumeBool());
    cJSON_AddNumberToObject(root_obj, "number_item", fdp.ConsumeIntegral<int>());
    cJSON_AddStringToObject(root_obj, "string_item", "value");

    /*
     * ANALYSIS: The coverage report showed 0% coverage for cJSON_CreateRaw,
     *           cJSON_IsRaw, and by extension cJSON_AddRawToObject.
     * IMPLEMENTATION: This block creates a raw JSON item, adds it to the object,
     *                 and checks its type to cover these functions.
     */
    cJSON *raw_item = cJSON_CreateRaw("{\"raw\": true}");
    if (raw_item) {
        cJSON_IsRaw(raw_item);
        cJSON_AddItemToObject(root_obj, "raw_item", raw_item);
    }

    /*
     * ANALYSIS: The coverage report showed cJSON_AddItemReferenceToObject was uncovered.
     *           This function does not take ownership of the added item.
     * IMPLEMENTATION: This block adds a pre-allocated item (item_to_ref) to the
     *                 object by reference. To prevent memory leaks, the referenced item
     *                 is manually deleted at the end of the test.
     */
    cJSON_AddItemReferenceToObject(root_obj, "ref_item", item_to_ref);
    /*
     * ANALYSIS: The line-level coverage report for cJSON_AddItemReferenceToObject showed
     *           the branch for handling a NULL object or string was not taken.
     * IMPLEMENTATION: The following code calls cJSON_AddItemReferenceToObject with a NULL
     *                 object and a NULL string to cover these error-handling paths.
     */
    cJSON_AddItemReferenceToObject(NULL, "ref_item", item_to_ref);
    cJSON_AddItemReferenceToObject(root_obj, NULL, item_to_ref);

    /*
     * ANALYSIS: The coverage report showed 0% coverage for
     *           cJSON_ReplaceItemInObjectCaseSensitive and cJSON_DeleteItemFromObjectCaseSensitive.
     * IMPLEMENTATION: This block adds items and then uses the case-sensitive versions
     *                 of Replace and Delete to exercise these uncovered functions.
     */
    const char *cs_replace_key = "CS_REPLACE";
    cJSON_AddItemToObject(root_obj, cs_replace_key, cJSON_CreateString("original_cs"));
    cJSON_ReplaceItemInObjectCaseSensitive(root_obj, cs_replace_key, cJSON_CreateString("replaced_cs"));

    const char *cs_delete_key = "CS_DELETE";
    cJSON_AddItemToObject(root_obj, cs_delete_key, cJSON_CreateString("to_delete_cs"));
    cJSON_DeleteItemFromObjectCaseSensitive(root_obj, cs_delete_key);
    /*
     * ANALYSIS: The line-level coverage report for cJSON_DetachItemFromObject and
     *           cJSON_DetachItemFromObjectCaseSensitive showed that the path for
     *           detaching a non-existent item was not taken.
     * IMPLEMENTATION: The following code calls these functions with a non-existent
     *           key, which returns NULL and covers this error path.
     */
    cJSON_DetachItemFromObject(root_obj, "non_existent_key");
    cJSON_DetachItemFromObjectCaseSensitive(root_obj, "non_existent_key_cs");


    /*
     * ANALYSIS: The function-level coverage report showed cJSON_AddObjectToObject,
     *           cJSON_AddArrayToObject, and cJSON_AddRawToObject were uncovered (0% coverage).
     * IMPLEMENTATION: The following code calls these helper functions to create and
     *                 add items to an object, covering these functions. The created
     *                 items are managed by root_obj and freed when it is deleted.
     */
    cJSON_AddObjectToObject(root_obj, "new_object");
    cJSON_AddArrayToObject(root_obj, "new_array");
    cJSON_AddRawToObject(root_obj, "new_raw", "{\"key\":\"value\"}");
    /*
     * ANALYSIS: The line-level coverage report for the cJSON_Add...ToObject family of
     *           functions showed that the failure path of the internal add_item_to_object
     *           call was not taken. This happens if the target 'object' is not an object.
     * IMPLEMENTATION: The following code calls cJSON_AddNullToObject on a non-object
     *                 item (json_str) to cover this error-handling path.
     */
    if (json_str) {
        cJSON_AddNullToObject(json_str, "should_fail");
    }


    cJSON_DeleteItemFromObject(root_obj, "number"); // Test deletion
    
    if (another_obj) {
        /*
         * ANALYSIS: The line-level coverage report for add_item_to_object showed
         *           the branch for handling an item with a const string key was
         *           not taken. This occurs when an item added with cJSON_AddItemToObjectCS
         *           (which sets the cJSON_StringIsConst flag) is detached and then
         *           added to a different object.
         * IMPLEMENTATION: The following code adds an item with a case-sensitive
         *                 (and therefore const) key, detaches it, and adds it to
         *                 another object, forcing the desired branch to be taken.
         */
        cJSON_AddItemToObjectCS(root_obj, "item_to_move_cs", cJSON_CreateString("move_me_cs"));
        cJSON *item_to_move = cJSON_DetachItemFromObjectCaseSensitive(root_obj, "item_to_move_cs");
        if (item_to_move) {
            cJSON_AddItemToObject(another_obj, "new_home_cs", item_to_move);
        }
    }

    /*
     * ANALYSIS: The line-level coverage report for cJSON_ReplaceItemViaPointer showed
     *           several uncovered branches: handling NULL inputs, and replacing an item
     *           that is not the last item in the list (i.e., `replacement->next != NULL`).
     * IMPLEMENTATION: The following code adds two items to an object and then replaces
     *                 the first one, covering the case where the replaced item is not
     *                 the tail. It also calls ReplaceItemInObject with NULL arguments to
     *                 cover the error-handling paths.
     */
    cJSON *replace_test_obj = cJSON_CreateObject();
    if (replace_test_obj) {
        cJSON_AddItemToObject(replace_test_obj, "key1", cJSON_CreateString("value1"));
        cJSON_AddItemToObject(replace_test_obj, "key2", cJSON_CreateString("value2"));
        cJSON_ReplaceItemInObject(replace_test_obj, "key1", cJSON_CreateString("new_value1"));
        cJSON_Delete(replace_test_obj);
    }
    cJSON *item1 = cJSON_CreateString("value");
    if (!cJSON_ReplaceItemInObject(root_obj, "non_existent", item1)) {
        cJSON_Delete(item1);
    }
    cJSON *item2 = cJSON_CreateString("value");
    if (!cJSON_ReplaceItemInObject(NULL, "key", item2)) {
        cJSON_Delete(item2);
    }


    /*
     * ANALYSIS: The line-level coverage report for cJSON_ReplaceItemViaPointer showed
     *           the branch for replacing an item with itself (item == replacement) was never taken.
     * IMPLEMENTATION: The following code adds an item and then attempts to replace it
     *                 with itself. The library has a specific check to handle this as a
     *                 safe no-op, and this call covers that branch.
     */
    cJSON_AddItemToObject(root_obj, "self_replace", cJSON_CreateString("self"));
    cJSON *item_to_self_replace = cJSON_GetObjectItem(root_obj, "self_replace");
    if (item_to_self_replace) {
        cJSON_ReplaceItemInObject(root_obj, "self_replace", item_to_self_replace);
    }
    /*
     * ANALYSIS: The line-level coverage report for add_item_to_object showed
     *           the branch for handling (object == item) was not taken.
     * IMPLEMENTATION: The following code calls cJSON_AddItemToObject with the object
     *                 itself as the item to be added, to cover this error-handling path.
     */
    cJSON_AddItemToObject(root_obj, "self", root_obj);
  }

  if (root_arr) {
    cJSON_AddItemToArray(root_arr, cJSON_CreateBool(fdp.ConsumeBool()));
    if (cJSON_GetArraySize(root_arr) > 0) {
      cJSON_GetArrayItem(root_arr, 0);
      /*
       * ANALYSIS: The coverage report showed cJSON_DeleteItemFromArray was uncovered.
       * IMPLEMENTATION: The original code used Detach+Delete. This is replaced with
       *                 a direct call to cJSON_DeleteItemFromArray to cover it.
       */
      cJSON_DeleteItemFromArray(root_arr, 0);
    }
    /*
     * ANALYSIS: The line-level coverage report for cJSON_GetArrayItem showed
     *           the branch for handling a negative index was not taken.
     * IMPLEMENTATION: The following code calls cJSON_GetArrayItem with a negative
     *                 index to cover this error-handling path.
     */
    cJSON_GetArrayItem(root_arr, -1);

    /*
     * ANALYSIS: The function-level coverage report for cJSON_DetachItemFromArray showed a
     *           missed branch for negative indices.
     * IMPLEMENTATION: The following code calls cJSON_DeleteItemFromArray with a negative
     *                 index to cover this error-handling path.
     */
    cJSON_DeleteItemFromArray(root_arr, -1);
    // Add a new item to test replacement
    cJSON_AddItemToArray(root_arr, cJSON_CreateNull());
    if (cJSON_GetArraySize(root_arr) > 0) {
      // Replacement item's ownership is passed to the array.
      cJSON_ReplaceItemInArray(root_arr, 0, cJSON_CreateString("replacement"));
    }
    /*
     * ANALYSIS: The line-level coverage report for cJSON_ReplaceItemInArray showed
     *           the branch for handling a negative index was not taken.
     * IMPLEMENTATION: The following code calls cJSON_ReplaceItemInArray with a
     *                 negative index to cover this error-handling path. The item
     *                 is deleted since the replacement fails.
     */
    cJSON *item_for_neg_replace = cJSON_CreateNull();
    if (!cJSON_ReplaceItemInArray(root_arr, -1, item_for_neg_replace)) {
        cJSON_Delete(item_for_neg_replace);
    }


    /*
     * ANALYSIS: The coverage report showed cJSON_AddItemReferenceToArray was uncovered.
     *           This function does not take ownership of the added item.
     * IMPLEMENTATION: This block adds a pre-allocated item (item_to_ref) to the
     *                 array by reference. To prevent memory leaks, the referenced item
     *                 is manually deleted at the end of the test.
     */
    cJSON_AddItemReferenceToArray(root_arr, item_to_ref);
    /*
     * ANALYSIS: The line-level coverage report for cJSON_AddItemReferenceToArray showed
     *           the branch for handling a NULL array was not taken.
     * IMPLEMENTATION: The following code calls cJSON_AddItemReferenceToArray with a NULL
     *                 array to cover this error-handling path.
     */
    cJSON_AddItemReferenceToArray(NULL, item_to_ref);

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
  /*
   * ANALYSIS: The line-level coverage report for cJSON_GetArraySize showed
   *           the branch for handling a NULL array was not taken.
   * IMPLEMENTATION: The following code calls cJSON_GetArraySize with a NULL
   *                 array to cover this error-handling path.
   */
  cJSON_GetArraySize(NULL);

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
   * ANALYSIS: The line-level coverage report for cJSON_Duplicate_rec showed
   *           the check for a NULL item was not covered. It also showed the
   *           check for circular references (depth >= CJSON_CIRCULAR_LIMIT)
   *           was never triggered.
   * IMPLEMENTATION: The following code calls cJSON_Duplicate with a NULL
   *                 pointer to cover the initial NULL check. It also creates a
   *                 deeply nested object to trigger the circular reference check
   *                 during duplication.
   */
  cJSON_Delete(cJSON_Duplicate(NULL, fdp.ConsumeBool()));

  cJSON *deep_obj = cJSON_CreateObject();
  if (deep_obj) {
      cJSON *current = deep_obj;
      // CJSON_CIRCULAR_LIMIT is 256, create a chain longer than that.
      for (int i = 0; i < 300; ++i) {
          cJSON *new_obj = cJSON_CreateObject();
          if (!new_obj) break;
          cJSON_AddItemToObject(current, "child", new_obj);
          current = new_obj;
      }
      cJSON *deep_dupe = cJSON_Duplicate(deep_obj, true);
      cJSON_Delete(deep_dupe);
      cJSON_Delete(deep_obj);
  }

  /*
   * ANALYSIS: The function-level coverage report showed the cJSON_Create...Array family of functions
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
   * ANALYSIS: The line-level coverage for the cJSON_Create...Array family of
   *           functions showed that branches for handling a negative count or a
   *           NULL data pointer were not being exercised.
   * IMPLEMENTATION: The following code calls the Create...Array functions with
   *                 a negative count and a NULL pointer to cover these error
   *                 conditions.
   */
  cJSON_Delete(cJSON_CreateIntArray(NULL, 10));
  cJSON_Delete(cJSON_CreateFloatArray(NULL, 10));
  cJSON_Delete(cJSON_CreateDoubleArray(NULL, 10));
  cJSON_Delete(cJSON_CreateStringArray(NULL, 10));
  const int numbers[] = {1,2,3};
  cJSON_Delete(cJSON_CreateIntArray(numbers, -1));


  /*
   * ANALYSIS: The function-level coverage report showed cJSON_Minify was largely uncovered.
   * IMPLEMENTATION: This block prints a JSON object to a string, copies it to a
   *                 mutable buffer, and then calls cJSON_Minify on it to exercise
   *                 in-place minification. The original string from cJSON_Print is freed.
   */
  if (root_obj) {
      char *printed_obj = cJSON_Print(root_obj);
      if (printed_obj) {
          std::vector<char> minify_buffer(printed_obj, printed_obj + strlen(printed_obj) + 1);
          cJSON_Minify(minify_buffer.data());
          cJSON_free(printed_obj);
      }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_PrintUnformatted was uncovered.
   * IMPLEMENTATION: This block calls cJSON_PrintUnformatted to cover this function.
   *                 The returned buffer is freed with cJSON_free.
   */
  if (root_obj) {
      char *unformatted_print = cJSON_PrintUnformatted(root_obj);
      if (unformatted_print) {
          cJSON_free(unformatted_print);
      }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_PrintBuffered had low coverage.
   * IMPLEMENTATION: This block calls cJSON_PrintBuffered with a fuzzer-controlled
   *                 prebuffer size and format flag. This will exercise the buffered
   *                 printing logic, including cases where the buffer needs to be
   *                 reallocated. The returned buffer is freed with cJSON_free.
   */
  if (root_obj) {
      int prebuffer = fdp.ConsumeIntegralInRange<int>(0, 1024);
      char *buffered_print = cJSON_PrintBuffered(root_obj, prebuffer, fdp.ConsumeBool());
      if (buffered_print) {
          cJSON_free(buffered_print);
      }
      /*
       * ANALYSIS: The line-level coverage report for cJSON_PrintBuffered showed
       *           the branch for handling a negative prebuffer size was not taken.
       * IMPLEMENTATION: The following code calls cJSON_PrintBuffered with a negative
       *                 prebuffer size to cover this error-handling path. The return
       *                 value is checked and freed, although it is expected to be NULL.
       */
      char *buffered_print_neg = cJSON_PrintBuffered(root_obj, -1, fdp.ConsumeBool());
      if (buffered_print_neg) {
          cJSON_free(buffered_print_neg);
      }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_CreateStringReference,
   *           cJSON_CreateObjectReference, and cJSON_CreateArrayReference were uncovered.
   * IMPLEMENTATION: The following code calls these functions to create reference items.
   *                 The created items are then deleted. Note that these functions do not
   *                 copy the passed-in data, so the lifetime of the source data must
   *                 exceed the lifetime of the created cJSON object.
   */
  const char *ref_str = "referenced_string";
  cJSON *str_ref = cJSON_CreateStringReference(ref_str);
  cJSON_Delete(str_ref);

  if (root_obj) {
    cJSON *obj_ref = cJSON_CreateObjectReference(root_obj);
    cJSON_Delete(obj_ref);
  }
  if (root_arr) {
    cJSON *arr_ref = cJSON_CreateArrayReference(root_arr);
    cJSON_Delete(arr_ref);
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_IsInvalid was uncovered.
   *           The source for cJSON_CreateBool shows it can return an invalid item.
   * IMPLEMENTATION: The following code calls cJSON_CreateBool with a value that is
   *                 not 0 or 1, which creates an invalid object. cJSON_IsInvalid is
   *                 then called on this object to cover the function.
   */
  cJSON *invalid_item = cJSON_CreateBool(fdp.ConsumeIntegralInRange<int>(2, 10));
  if (invalid_item) {
      cJSON_IsInvalid(invalid_item);
      cJSON_Delete(invalid_item);
  }


  // Cleanup: All allocated cJSON objects must be deleted to prevent memory leaks.
  cJSON_Delete(json_num);
  cJSON_Delete(json_str);
  cJSON_Delete(json_bool);
  cJSON_Delete(json_null);
  cJSON_Delete(json_true);
  cJSON_Delete(json_false);
  if (parsed_json1) {
    cJSON_Delete(parsed_json1);
  }
  if (parsed_json2) {
    cJSON_Delete(parsed_json2);
  }
  if (parsed_json3) {
    cJSON_Delete(parsed_json3);
  }
  cJSON_Delete(root_obj);
  cJSON_Delete(another_obj);
  cJSON_Delete(root_arr);
  cJSON_Delete(item_to_ref); // This item was added by reference, so it needs its own delete call.
  
  // Reset hooks to default to avoid affecting other fuzz targets
  cJSON_InitHooks(NULL);

  return 0;
}