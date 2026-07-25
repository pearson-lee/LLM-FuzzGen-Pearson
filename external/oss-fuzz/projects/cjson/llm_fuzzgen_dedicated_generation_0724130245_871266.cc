/* BLOCKER_STRATEGY_CONTRACT
required_state: cJSON_strdup must return NULL, which occurs when memory allocation fails.
state_constructor: Use cJSON_InitHooks to install a custom malloc function (failing_malloc) that always returns NULL, simulating an out-of-memory condition.
trigger_api: cJSON_ReplaceItemInObject. This function calls the internal replace_item_in_object, which then calls cJSON_strdup to duplicate the object key. With the custom malloc hook, cJSON_strdup fails and returns NULL.
preserved_invariants: The custom memory allocation hooks must be active when cJSON_ReplaceItemInObject is called. The 'replacement' item should not be of type cJSON_String to avoid a use-after-free bug in the cJSON library's error handling for this specific failure.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/cjson/cJSON.h"

// A malloc that is designed to fail to test allocation-failure paths.
void* failing_malloc(size_t size)
{
    (void)size;
    return NULL;
}

// A free that can handle NULL pointers, to be paired with failing_malloc.
void safe_free(void* ptr)
{
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Start with default hooks to create objects successfully.
    cJSON_InitHooks(NULL);

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    // Use a non-string item for replacement to avoid potential heap corruption
    // in the cJSON library when replace_item_in_object fails after modifying
    // a string item. A number item's string property is NULL initially.
    cJSON* replacement = cJSON_CreateNumber(fdp.ConsumeIntegral<int>());
    if (!replacement) {
        cJSON_Delete(root);
        return 0;
    }

    std::string key = fdp.ConsumeRandomLengthString(100);
    
    // Add an item to the object so that the key exists. This makes the scenario
    // more realistic, although it is not strictly required to hit the blocker.
    cJSON_AddItemToObject(root, key.c_str(), cJSON_CreateString("original_value"));

    // Set up hooks to make malloc fail.
    cJSON_Hooks hooks;
    hooks.malloc_fn = failing_malloc;
    hooks.free_fn = safe_free;
    cJSON_InitHooks(&hooks);

    // This call will enter replace_item_in_object, where cJSON_strdup will
    // be called. Due to the failing malloc hook, cJSON_strdup will return NULL,
    // which will cause replacement->string to be NULL, hitting the blocker.
    cJSON_bool success = cJSON_ReplaceItemInObject(root, key.c_str(), replacement);

    // Restore hooks for cleanup regardless of success or failure.
    cJSON_InitHooks(NULL);

    if (!success) {
        // The call failed, so we are responsible for deleting the replacement item.
        cJSON_Delete(replacement);
    }

    cJSON_Delete(root);

    return 0;
}
