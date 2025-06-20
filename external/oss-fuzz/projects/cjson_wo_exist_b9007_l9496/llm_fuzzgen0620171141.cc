#include <stddef.h>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// Include the target library header using its project-relative path.
#include "/src/cjson/cJSON.h"

// Fuzzer-controlled allocation failure mechanism.
// These globals are used to simulate allocation failures in a controlled manner
// within the single-threaded fuzzer execution context.
static int malloc_fail_on = -1;
static int malloc_count = 0;

// A custom malloc function that can be instructed to fail at a specific call count.
// This is crucial for testing the error-handling paths in cJSON that deal with
// memory allocation failures.
static void* failing_malloc(size_t size) {
    if (malloc_fail_on != -1 && malloc_count >= malloc_fail_on) {
        // Return NULL to simulate an allocation failure.
        return NULL;
    }
    malloc_count++;
    return malloc(size);
}

// A custom free function that pairs with our custom malloc.
static void failing_free(void* ptr) {
    free(ptr);
}

// The entry point for the fuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Let the fuzzer decide if and when an allocation should fail during this run.
    // A value of -1 means allocations will not fail.
    malloc_fail_on = fdp.ConsumeIntegralInRange<int>(-1, 20);
    malloc_count = 0;

    // Initialize cJSON with our custom, potentially failing, memory hooks.
    // This strategy is key to reaching the low-coverage error handling branches
    // in internal functions like `ensure` and the various `print` functions.
    cJSON_Hooks hooks;
    hooks.malloc_fn = failing_malloc;
    hooks.free_fn = failing_free;
    cJSON_InitHooks(&hooks);

    // 1. Create a root JSON object. This is the starting point for our JSON structure.
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        // If creation fails (e.g., due to our hook), restore original hooks and exit.
        cJSON_InitHooks(NULL);
        return 0;
    }

    // Add a couple of items to the object to create a non-trivial JSON.
    // This exercises different `add` and `create` paths within the library.
    std::string key1 = fdp.ConsumeRandomLengthString(20);
    if (!key1.empty()) {
        // 2. Add a string value to the object.
        std::string value_str = fdp.ConsumeRandomLengthString(50);
        cJSON_AddStringToObject(root, key1.c_str(), value_str.c_str());
    }

    std::string key2 = fdp.ConsumeRandomLengthString(20);
    if (!key2.empty()) {
        // 3. Add a number value to the object.
        double value_num = fdp.ConsumeFloatingPoint<double>();
        cJSON_AddNumberToObject(root, key2.c_str(), value_num);
    }

    // Added call to cJSON_AddRawToObject to cover an untested branch in add_item_to_object.
    // This change directly addresses the coverage gap identified in the line coverage report.
    std::string key3 = fdp.ConsumeRandomLengthString(20);
    if (!key3.empty()) {
        cJSON_AddRawToObject(root, key3.c_str(), "{}");
    }

    // Added call to cJSON_CreateStringArray to improve coverage.
    const char* strings[] = {"a", "b", "c"};
    cJSON* string_array = cJSON_CreateStringArray(strings, 3);
    cJSON_AddItemToObject(root, "string_array", string_array);

    // Add an object to an object to hit a branch in add_item_to_object.
    cJSON* sub_object = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "sub_object", sub_object);

    // Add an array to an object to improve coverage of cJSON_AddArrayToObject.
    cJSON* sub_array = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "sub_array", sub_array);

    // Added call to cJSON_Duplicate to improve its coverage.
    cJSON* duplicated_root = cJSON_Duplicate(root, fdp.ConsumeBool());
    if (duplicated_root) {
        // Added call to cJSON_Compare to improve its coverage.
        cJSON_Compare(root, duplicated_root, fdp.ConsumeBool());
        cJSON_Delete(duplicated_root);
    }

    // Added calls to cJSON_AddObjectToObject and cJSON_AddArrayToObject with an existing key
    // to trigger the error handling logic and improve coverage.
    if (!key1.empty()) {
        cJSON_AddObjectToObject(root, key1.c_str());
        cJSON_AddArrayToObject(root, key1.c_str());
    }

    // Added call to cJSON_SetValuestring to improve its coverage.
    cJSON* valuestring_item = cJSON_CreateString("old_value");
    std::string new_value = fdp.ConsumeRandomLengthString(20);
    cJSON_SetValuestring(valuestring_item, new_value.c_str());
    cJSON_Delete(valuestring_item);

    // 4. Print the JSON object to a string. This is a critical step that will
    // heavily exercise the `print` and `ensure` functions, including the
    // allocation failure paths that we are specifically targeting for coverage.
    char *printed_json = cJSON_Print(root);

    // The `printed_json` string is allocated by cJSON's internal malloc (which we've hooked).
    // It is essential to free this memory using the corresponding free function from our hooks
    // to prevent memory leaks.
    if (printed_json) {
        hooks.free_fn(printed_json);
    }

    // 5. Clean up the entire cJSON object structure. This call recursively frees
    // all memory associated with the `root` object and its children, which is
    // crucial for preventing memory leaks.
    cJSON_Delete(root);

    // It's good practice to restore the original memory allocation hooks
    // to avoid side effects if the fuzzer were part of a larger program.
    cJSON_InitHooks(NULL);

    return 0;
}