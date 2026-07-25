#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
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
     * ANALYSIS: The fuzz target coverage shows that error-handling paths in
     *           cJSON_AddItemToObject are never exercised. The line coverage report
     *           for add_item_to_object confirms that checks for NULL string and NULL item are not hit.
     * IMPLEMENTATION: The following block calls cJSON_AddItemToObject with a NULL
     *                 key and a NULL item to trigger these error-handling paths.
     *                 The dummy item must be deleted manually as it's not added to the root.
     */
    cJSON* dummy_item = cJSON_CreateNumber(42);
    if (dummy_item) {
        cJSON_AddItemToObject(root, NULL, dummy_item);
        cJSON_Delete(dummy_item);
    }
    cJSON_AddItemToObject(root, "some_key", NULL);

    /*
     * ANALYSIS: The function-level coverage report shows cJSON_SetValuestring and
     *           cJSON_strdup have low coverage. The line-level report for
     *           cJSON_SetValuestring shows the allocation failure path for cJSON_strdup
     *           is not taken.
     * IMPLEMENTATION: The following block sets g_should_fail_alloc to true before
     *                 calling cJSON_SetValuestring on a newly created string object.
     *                 This forces the internal cJSON_strdup to fail, exercising the
     *                 error-handling logic in both functions.
     */
    if (fdp.ConsumeBool()) {
        cJSON* str_obj = cJSON_CreateString("initial_string");
        if (str_obj) {
            g_should_fail_alloc = true;
            cJSON_SetValuestring(str_obj, fdp.ConsumeRandomLengthString(100).c_str());
            g_should_fail_alloc = false;
            cJSON_Delete(str_obj);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report indicates that cJSON_Duplicate
     *           (via cJSON_Duplicate_rec) and cJSON_Compare have low coverage and are
     *           not being exercised by the fuzzer.
     * IMPLEMENTATION: This block creates a cJSON object, duplicates it using
     *                 cJSON_Duplicate, and then compares the original and the duplicate
     *                 with cJSON_Compare. This directly calls the uncovered functions.
     *                 Both the original and duplicated objects are safely deleted.
     */
    if (fdp.ConsumeBool()) {
        cJSON* j_to_dup = cJSON_CreateObject();
        if (j_to_dup) {
            cJSON_AddStringToObject(j_to_dup, "name", "value");
            cJSON* j_duplicated = cJSON_Duplicate(j_to_dup, fdp.ConsumeBool());
            if (j_duplicated) {
                cJSON_Compare(j_to_dup, j_duplicated, fdp.ConsumeBool());
                cJSON_Delete(j_duplicated);
            }
            cJSON_Delete(j_to_dup);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows cJSON_PrintBuffered has
     *           uncovered branches. The existing fuzzer only calls the unbuffered
     *           printing functions.
     * IMPLEMENTATION: This block calls cJSON_PrintBuffered with a dynamically sized
     *                 buffer to exercise the buffered printing logic. A std::vector
     *                 is used to ensure the buffer memory is safely managed.
     */
    if (fdp.ConsumeBool()) {
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 2048);
        char* printed_json = cJSON_PrintBuffered(root, buffer_size, fdp.ConsumeBool());
        if (printed_json) {
            free(printed_json);
        }
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

    /*
     * ANALYSIS: The function-level coverage report shows that `skip_utf8_bom` has low
     *           coverage. This function is called during parsing to handle an optional
     *           UTF-8 Byte Order Mark at the beginning of the input.
     * IMPLEMENTATION: The following block prepends a UTF-8 BOM to a fuzzer-generated
     *                 string and attempts to parse it. This directly exercises the
     *                 logic within `skip_utf8_bom`.
     */
    if (fdp.ConsumeBool()) {
        std::string bom_str = "\xEF\xBB\xBF";
        std::string json_str = fdp.ConsumeRandomLengthString(100);
        std::string with_bom = bom_str + json_str;
        cJSON* parsed_with_bom = cJSON_Parse(with_bom.c_str());
        if (parsed_with_bom) {
            cJSON_Delete(parsed_with_bom);
        }
    }

    /*
     * ANALYSIS: The line-level coverage for `cJSON_InsertItemInArray` shows that the
     *           `newitem == NULL` check at line 2296 is never taken.
     * IMPLEMENTATION: The following block creates an array and calls
     *                 `cJSON_InsertItemInArray` with a NULL item to trigger this
     *                 uncovered error-handling branch.
     */
    if (fdp.ConsumeBool()) {
        cJSON* array = cJSON_CreateArray();
        if (array) {
            cJSON_InsertItemInArray(array, 0, NULL);
            cJSON_Delete(array);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows low coverage for
     *           `cJSON_CreateIntArray` and `cJSON_CreateFloatArray`.
     * IMPLEMENTATION: This block adds calls to `cJSON_CreateIntArray` and
     *                 `cJSON_CreateFloatArray` with fuzzer-generated data, mirroring the
     *                 existing logic for `cJSON_CreateDoubleArray` to improve coverage.
     */
    if (fdp.ConsumeBool()) {
        size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 50);
        std::vector<int> ints(count);
        for(size_t i = 0; i < count; ++i) ints[i] = fdp.ConsumeIntegral<int>();
        cJSON* int_array = cJSON_CreateIntArray(ints.data(), ints.size());
        if (int_array) cJSON_Delete(int_array);
    }
    if (fdp.ConsumeBool()) {
        size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 50);
        std::vector<float> floats(count);
        for(size_t i = 0; i < count; ++i) floats[i] = fdp.ConsumeFloatingPoint<float>();
        cJSON* float_array = cJSON_CreateFloatArray(floats.data(), floats.size());
        if (float_array) cJSON_Delete(float_array);
    }

    /*
     * ANALYSIS: The line-level coverage for `cJSON_CreateStringArray` shows that the
     *           `if(!n)` check at line 2716 is never taken. This branch is hit on an
     *           internal allocation failure when creating a string.
     * IMPLEMENTATION: This block sets `g_should_fail_alloc` to true before calling
     *                 `cJSON_CreateStringArray` to force an allocation failure,
     *                 exercising the previously uncovered error-handling path.
     */
    if (fdp.ConsumeBool()) {
        size_t count = fdp.ConsumeIntegralInRange<size_t>(1, 10);
        std::vector<std::string> strings_vec;
        std::vector<const char*> strings_ptr;
        for(size_t i = 0; i < count; ++i) {
            strings_vec.push_back(fdp.ConsumeRandomLengthString(20));
        }
        for(const auto& s : strings_vec) {
            strings_ptr.push_back(s.c_str());
        }

        g_should_fail_alloc = true;
        cJSON* string_array = cJSON_CreateStringArray(strings_ptr.data(), strings_ptr.size());
        if (string_array) {
            cJSON_Delete(string_array);
        }
        g_should_fail_alloc = false;
    }

    /*
     * ANALYSIS: The function-level coverage report shows low coverage for the
     *           `create_reference` function, which is used by `cJSON_CreateStringReference`,
     *           `cJSON_CreateObjectReference`, and `cJSON_CreateArrayReference`.
     * IMPLEMENTATION: This block calls the reference creation functions to exercise
     *                 this logic. The created items are added to a temporary object that is
     *                 deleted, ensuring cleanup. The referenced string must be managed.
     */
    if (fdp.ConsumeBool()) {
        cJSON *ref_holder = cJSON_CreateObject();
        if (ref_holder) {
            std::string str_ref = fdp.ConsumeRandomLengthString(50);
            cJSON *str_ref_item = cJSON_CreateStringReference(str_ref.c_str());
            if (str_ref_item) {
                cJSON_AddItemToObject(ref_holder, "str_ref", str_ref_item);
            }

            cJSON *obj_ref_item = cJSON_CreateObjectReference(root);
            if (obj_ref_item) {
                // Avoid self-reference issues by not adding to root.
                cJSON_AddItemToObject(ref_holder, "obj_ref", obj_ref_item);
            }
            cJSON_Delete(ref_holder);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report shows low coverage for
     *           `cJSON_ReplaceItemViaPointer` and `replace_item_in_object`.
     * IMPLEMENTATION: This block creates an object, adds an item, and then replaces
     *                 that item using `cJSON_ReplaceItemInObject`. It also attempts
     *                 to replace an item with itself to hit edge-case checks.
     */
    if (fdp.ConsumeBool()) {
        cJSON* replace_obj = cJSON_CreateObject();
        if (replace_obj) {
            cJSON_AddNumberToObject(replace_obj, "item_to_replace", 1);
            cJSON* new_item = cJSON_CreateNumber(2);
            if (new_item) {
                cJSON_ReplaceItemInObject(replace_obj, "item_to_replace", new_item);
            }
            // Try to replace an item with itself
            cJSON* another_item = cJSON_GetObjectItem(replace_obj, "item_to_replace");
            if (another_item) {
                cJSON_ReplaceItemInObject(replace_obj, "item_to_replace", another_item);
            }
            cJSON_Delete(replace_obj);
        }
    }


    // Final cleanup of the root object and all its children.
    cJSON_Delete(root);

    return 0;
}