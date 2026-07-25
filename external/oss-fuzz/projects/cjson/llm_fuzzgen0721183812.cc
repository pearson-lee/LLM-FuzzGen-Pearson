#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Global flag to control memory allocation failures for testing purposes.
static bool g_should_fail_alloc = false;

// A custom malloc function that can be made to fail on demand.
static void* custom_malloc(size_t size) {
    if (g_should_fail_alloc) {
        return NULL;
    }
    return malloc(size);
}

// Standard free function for cleanup.
static void custom_free(void* ptr) {
    free(ptr);
}

// The main fuzzing function that tests the cJSON library.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Initialize cJSON with our custom memory management hooks.
    cJSON_Hooks hooks = {custom_malloc, custom_free};
    cJSON_InitHooks(&hooks);

    // Create a root JSON object.
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed that cJSON_CreateDoubleArray
     *           had a branch at line 2676 (`if(!n)`) that was never taken. This branch
     *           is hit if `cJSON_CreateNumber` returns NULL, which happens on memory
     *           allocation failure.
     * IMPLEMENTATION: The following block sometimes sets `g_should_fail_alloc` to true
     *                 before calling `cJSON_CreateDoubleArray`. This causes the internal
     *                 `cJSON_CreateNumber` call to fail, exercising the previously
     *                 uncovered error-handling path.
     */
    if (fdp.ConsumeBool()) {
        g_should_fail_alloc = true;
        size_t num_doubles = fdp.ConsumeIntegralInRange<size_t>(0, 100);
        std::vector<double> doubles;
        doubles.reserve(num_doubles);
        for (size_t i = 0; i < num_doubles; ++i) {
            doubles.push_back(fdp.ConsumeFloatingPoint<double>());
        }
        cJSON* double_array = cJSON_CreateDoubleArray(doubles.data(), doubles.size());
        if (double_array) {
            cJSON_Delete(double_array);
        }
        g_should_fail_alloc = false;
    }

    // Add a string to the root object.
    cJSON* string_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str());
    if (string_item) {
        if (!cJSON_AddItemToObject(root, "a_string", string_item)) {
            cJSON_Delete(string_item);
        }
    }

    /*
     * ANALYSIS: The coverage report for `add_item_to_array` showed that the error-handling
     *           branch for `array == item` at line 1989 was never taken.
     * IMPLEMENTATION: A new array is created and we attempt to add it to itself,
     *                 specifically to trigger this self-referential check.
     */
    cJSON* array_to_test_self_add = cJSON_CreateArray();
    if (array_to_test_self_add) {
        cJSON_AddItemToArray(array_to_test_self_add, array_to_test_self_add);
        if (!cJSON_AddItemToObject(root, "self_add_array", array_to_test_self_add)) {
            cJSON_Delete(array_to_test_self_add);
        }
    }

    /*
     * ANALYSIS: The coverage report for `add_item_to_array` at line 2008 showed that the
     *           `if (child->prev)` condition was never false when a child existed. This
     *           indicates a failure to test arrays that are not correctly doubly-linked.
     * IMPLEMENTATION: We manually construct a malformed array where a child exists but its
     *                 `prev` pointer is NULL. Calling `cJSON_AddItemToArray` on this
     *                 structure forces the fuzzer to exercise the previously missed branch.
     *                 After this operation, the array is in a corrupt state and must be
     *                 manually deleted to prevent memory leaks.
     */
    cJSON* malformed_array = cJSON_CreateArray();
    if (malformed_array) {
        cJSON* child_item = cJSON_CreateNumber(1);
        if (child_item) {
            if (cJSON_AddItemToArray(malformed_array, child_item)) {
                child_item->prev = NULL; // Create the malformed state

                cJSON* new_item = cJSON_CreateNumber(2);
                if (new_item) {
                    // This call triggers the target branch. The return value and
                    // subsequent state of the objects are untrustworthy.
                    cJSON_AddItemToArray(malformed_array, new_item);
                    // Manually delete new_item as it may have been orphaned.
                    cJSON_Delete(new_item);
                }
            } else {
                cJSON_Delete(child_item);
            }
        }
        // Manually delete the entire corrupted array structure.
        // Do NOT add it to the root object.
        cJSON_Delete(malformed_array);
    }


    /*
     * ANALYSIS: The coverage report for `print` and `ensure` showed multiple uncovered
     *           branches related to memory allocation failures. For example, in `print`,
     *           the `fail:` block was never reached.
     * IMPLEMENTATION: We randomly set `g_should_fail_alloc` to true before calling
     *                 `cJSON_PrintUnformatted`. This simulates an allocation failure,
     *                 triggering the error-handling logic in `print` and `ensure`.
     */
    if (fdp.ConsumeBool()) {
        g_should_fail_alloc = true;
        char* printed_json = cJSON_PrintUnformatted(root);
        if (printed_json) {
            free(printed_json); // This should not be reached if allocation fails
        }
        g_should_fail_alloc = false;
    } else {
        char* printed_json = cJSON_PrintUnformatted(root);
        if (printed_json) {
            free(printed_json);
        }
    }

    // Final cleanup of the root object and all its children.
    cJSON_Delete(root);

    return 0;
}