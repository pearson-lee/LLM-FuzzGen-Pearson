#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    /*
     * ANALYSIS: The line coverage report for `cJSON_GetArrayItem` showed that the `while (i < item->valueint)` loop
     *           was never executed because `item->valueint` was always 0. Additionally, the `if (array == NULL)`
     *           check was not hit.
     * IMPLEMENTATION: The following code creates an array with two items and calls `cJSON_GetArrayItem` with index 1,
     *                 which forces the loop to execute. It also calls `cJSON_GetArrayItem` with a NULL array to hit the error path.
     */
    if (fdp.ConsumeBool()) {
        cJSON* array = cJSON_CreateArray();
        if (array) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(1));
            cJSON_AddItemToArray(array, cJSON_CreateNumber(2));
            cJSON_GetArrayItem(array, 1);
            cJSON_AddItemToObject(root, "get_array_item_test", array);
        }
        cJSON_GetArrayItem(NULL, 0);
    }

    /*
     * ANALYSIS: The line coverage report for `replace_item_in_object` showed that the `while (current)` loop's body
     *           was not fully executed because the item to be replaced was always the first item. The `if (!object)` check was also missed.
     * IMPLEMENTATION: This code creates an object with two items and replaces the second one, forcing the loop to
     *                 iterate. It also calls `cJSON_ReplaceItemInObject` with a NULL object to hit the error path.
     */
    if (fdp.ConsumeBool()) {
        cJSON* obj = cJSON_CreateObject();
        if (obj) {
            cJSON_AddItemToObject(obj, "first", cJSON_CreateString("one"));
            cJSON_AddItemToObject(obj, "second", cJSON_CreateString("two"));
            cJSON_ReplaceItemInObject(obj, "second", cJSON_CreateString("new_two"));
            cJSON_AddItemToObject(root, "replace_item_test", obj);
        }
        cJSON *null_item = cJSON_CreateNull();
        cJSON_ReplaceItemInObject(NULL, "key", null_item);
        if (null_item) {
            cJSON_Delete(null_item);
        }
    }

    /*
     * ANALYSIS: `cJSON_Duplicate` (and its internal recursive logic) had low coverage. Specifically, the recursive
     *           path for duplicating children, the path for duplicating an item with a `valuestring`, and the `if (!item)`
     *           check were not covered.
     * IMPLEMENTATION: This code creates an object with a child and calls `cJSON_Duplicate` with both `recurse=true` and `recurse=false`.
     *                 It also calls `cJSON_Duplicate` on a NULL item. To cover the `valuestring` path, it creates an item,
     *                 calls `cJSON_SetValuestring` on it, and then duplicates it.
     */
    if (fdp.ConsumeBool()) {
        cJSON* dup_test_obj = cJSON_CreateObject();
        if (dup_test_obj) {
            cJSON_AddItemToObject(dup_test_obj, "child", cJSON_CreateNumber(123));
            cJSON* dup_rec = cJSON_Duplicate(dup_test_obj, 1);
            if (dup_rec) cJSON_Delete(dup_rec);
            cJSON* dup_non_rec = cJSON_Duplicate(dup_test_obj, 0);
            if (dup_non_rec) cJSON_Delete(dup_non_rec);
            cJSON_AddItemToObject(root, "dup_test", dup_test_obj);
        }
        cJSON* dup_null = cJSON_Duplicate(NULL, fdp.ConsumeBool());
        if (dup_null) cJSON_Delete(dup_null);

        cJSON* vs_item = cJSON_CreateString("");
        if (vs_item) {
            cJSON_SetValuestring(vs_item, fdp.ConsumeRandomLengthString(20).c_str());
            cJSON* vs_item_dup = cJSON_Duplicate(vs_item, 1);
            if (vs_item_dup) cJSON_Delete(vs_item_dup);
            cJSON_Delete(vs_item);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that `cJSON_CreateStringReference`, `cJSON_CreateObjectReference`,
     *           and `cJSON_CreateArrayReference` were not being called at all.
     * IMPLEMENTATION: The following code calls these three functions to exercise their successful execution paths, improving
     *                 overall API coverage. The created reference items are immediately deleted to ensure memory safety.
     */
    if (fdp.ConsumeBool()) {
        const char *s = "string_for_ref";
        cJSON* string_ref = cJSON_CreateStringReference(s);
        if (string_ref) cJSON_Delete(string_ref);

        cJSON* obj_for_ref = cJSON_CreateObject();
        if (obj_for_ref) {
            cJSON* obj_ref = cJSON_CreateObjectReference(obj_for_ref);
            if (obj_ref) cJSON_Delete(obj_ref);
            cJSON_Delete(obj_for_ref);
        }

        cJSON* arr_for_ref = cJSON_CreateArray();
        if (arr_for_ref) {
            cJSON* arr_ref = cJSON_CreateArrayReference(arr_for_ref);
            if (arr_ref) cJSON_Delete(arr_ref);
            cJSON_Delete(arr_for_ref);
        }
    }

    // Clean up all memory associated with the root object and its children.
    cJSON_Delete(root);

    return 0;
}