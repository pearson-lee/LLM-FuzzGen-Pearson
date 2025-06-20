#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// A custom malloc that can be made to fail for testing purposes.
static int malloc_fail_countdown = -1;
static void* failing_malloc(size_t size) {
    if (malloc_fail_countdown == 0) {
        return NULL;
    }
    if (malloc_fail_countdown > 0) {
        malloc_fail_countdown--;
    }
    return malloc(size);
}

// Custom free function to match the custom malloc.
static void succeeding_free(void* pointer) {
    free(pointer);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Initialize cJSON with our custom memory allocators.
    // This allows us to test memory allocation failure scenarios.
    cJSON_Hooks hooks = {failing_malloc, succeeding_free};
    cJSON_InitHooks(&hooks);

    // Control when our custom malloc should start failing.
    // A negative value means it will never fail.
    malloc_fail_countdown = fdp.ConsumeIntegralInRange<int>(-1, 10);

    // Create a cJSON object to be used in various tests.
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    // Test cJSON_CreateStringArray
    std::vector<std::string> string_storage;
    int num_strings = fdp.ConsumeIntegralInRange<int>(0, 10);
    for (int i = 0; i < num_strings; i++) {
        string_storage.push_back(fdp.ConsumeRandomLengthString(100));
    }
    std::vector<const char*> string_array;
    for (const auto& s : string_storage) {
        string_array.push_back(s.c_str());
    }
    cJSON* cjson_string_array = cJSON_CreateStringArray(string_array.data(), string_array.size());
    if (cjson_string_array) {
        cJSON_AddItemToObject(root, "string_array", cjson_string_array);
    }

    // Test cJSON_CreateArrayReference
    cJSON *array_ref = cJSON_CreateArrayReference(cjson_string_array);
    if (array_ref) {
        cJSON_AddItemToObject(root, "array_ref", array_ref);
    }

    // Test cJSON_AddItemReferenceToArray
    cJSON *array = cJSON_CreateArray();
    if (array) {
        cJSON_AddItemReferenceToArray(array, root);
        cJSON_AddItemToObject(root, "another_array", array);
    }

    // Test cJSON_ReplaceItemInObject
    cJSON_AddItemToObject(root, "item_to_replace", cJSON_CreateString("will be replaced"));
    cJSON_ReplaceItemInObject(root, "item_to_replace", cJSON_CreateString("was replaced"));
    
    // Added to cover a branch in replace_item_in_object where the item to be replaced does not exist.
    cJSON_ReplaceItemInObject(root, "non_existent_item", cJSON_CreateString("should not be added"));

    // Test create_reference with a NULL item to hit a previously missed branch.
    cJSON* null_ref = cJSON_CreateObjectReference(NULL);
    if (null_ref) {
        cJSON_Delete(null_ref);
    }

    // Added to cover a branch in cJSON_ReplaceItemViaPointer where item and replacement are the same.
    cJSON *item_to_replace = cJSON_GetObjectItem(root, "item_to_replace");
    if (item_to_replace) {
        cJSON_ReplaceItemViaPointer(root, item_to_replace, item_to_replace);
    }

    // Added to cover a branch in cJSON_ReplaceItemViaPointer where parent is NULL.
    cJSON *new_item = cJSON_CreateString("new_item");
    if (item_to_replace && new_item) {
        cJSON_ReplaceItemViaPointer(NULL, item_to_replace, new_item);
    }
    if (new_item) {
        cJSON_Delete(new_item);
    }

    // Added to cover a branch in cJSON_CreateNull where malloc fails.
    malloc_fail_countdown = 0;
    cJSON* null_item = cJSON_CreateNull();
    if (null_item) {
        cJSON_Delete(null_item);
    }

    // Clean up all cJSON objects to prevent memory leaks.
    cJSON_Delete(root);

    return 0;
}