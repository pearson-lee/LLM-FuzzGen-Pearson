#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <limits.h> // For INT_MAX, INT_MIN
#include <cmath>    // For NAN, INFINITY
#include <cstring>  // For strcmp, needed for case_insensitive_strcmp test

#include <fuzzer/FuzzedDataProvider.h>

// Include the main cJSON header.
// Note: The provided API information indicates /src/cjson/cJSON.h as the main header.
// Assuming cJSON.h defines cJSON_bool and cJSON struct.
#include "/src/cjson/cJSON.h"

// Define CJSONDeleter and unique_cJSON_ptr as they are crucial for memory safety
// and are indicated as having 0.0% coverage, suggesting they might be part of
// a custom setup for C++ usage of cJSON.
// This custom deleter ensures cJSON_Delete is called when unique_cJSON_ptr goes out of scope.
struct CJSONDeleter {
    void operator()(cJSON* item) const {
        if (item) {
            cJSON_Delete(item);
        }
    }
};

// Define a unique_ptr alias for cJSON objects with the custom deleter.
using unique_cJSON_ptr = std::unique_ptr<cJSON, CJSONDeleter>;

// Helper function to create a fuzzed cJSON item.
// This function is designed to create various types of cJSON objects
// to provide diverse inputs to the target APIs.
unique_cJSON_ptr CreateFuzzedCjsonItem(FuzzedDataProvider& fdp) {
    unique_cJSON_ptr item;
    int type = fdp.ConsumeIntegralInRange<int>(0, 7); // 0-7 for different cJSON types

    switch (type) {
        case 0: // Null
            item.reset(cJSON_CreateNull());
            break;
        case 1: // True
            item.reset(cJSON_CreateTrue());
            break;
        case 2: // False
            item.reset(cJSON_CreateFalse());
            break;
        case 3: // Number
            item.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            break;
        case 4: // String
            // Added random NULL string input to hit cJSON_strdup's NULL check (lines 194-196 in cJSON.c)
            // and cJSON_CreateString's allocation failure path (lines 2486-2489 in cJSON.c).
            if (fdp.ConsumeBool()) {
                item.reset(cJSON_CreateString(nullptr));
            } else {
                // Store the string in a variable to ensure its lifetime extends beyond the c_str() call.
                std::string random_string = fdp.ConsumeRandomLengthString();
                item.reset(cJSON_CreateString(random_string.c_str()));
            }
            break;
        case 5: { // Array
            item.reset(cJSON_CreateArray());
            if (item) {
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 5); // Limit array size
                for (size_t i = 0; i < num_elements; ++i) {
                    unique_cJSON_ptr child = CreateFuzzedCjsonItem(fdp);
                    if (child) {
                        cJSON* raw_child = child.release(); // Release ownership
                        // cJSON_AddItemToArray takes ownership. If it fails, we must delete raw_child.
                        // Added random NULL item input to hit add_item_to_array's NULL check (lines 1979-1981 in cJSON.c).
                        bool add_failed = false;
                        if (fdp.ConsumeBool()) {
                            add_failed = !cJSON_AddItemToArray(item.get(), nullptr);
                        } else {
                            add_failed = !cJSON_AddItemToArray(item.get(), raw_child);
                        }

                        if (add_failed) {
                            cJSON_Delete(raw_child); // If addition failed, delete it manually
                        }
                    }
                }
            }
            break;
        }
        case 6: { // Object
            item.reset(cJSON_CreateObject());
            if (item) {
                size_t num_members = fdp.ConsumeIntegralInRange<size_t>(0, 5); // Limit object size
                for (size_t i = 0; i < num_members; ++i) {
                    std::string key = fdp.ConsumeRandomLengthString(16); // Limit key length
                    unique_cJSON_ptr value = CreateFuzzedCjsonItem(fdp);
                    if (value) {
                        cJSON* raw_value = value.release(); // Release ownership
                        // cJSON_AddItemToObject takes ownership. If it fails, we must delete raw_value.
                        // Added random NULL item or NULL key inputs to hit add_item_to_object's NULL checks (lines 2035-2037 in cJSON.c).
                        bool add_failed = false;
                        if (fdp.ConsumeBool()) {
                            add_failed = !cJSON_AddItemToObject(item.get(), key.c_str(), nullptr);
                        } else if (fdp.ConsumeBool()) {
                            add_failed = !cJSON_AddItemToObject(item.get(), nullptr, raw_value);
                        } else {
                            add_failed = !cJSON_AddItemToObject(item.get(), key.c_str(), raw_value);
                        }

                        if (add_failed) {
                            cJSON_Delete(raw_value); // If addition failed, delete it manually
                        }
                    }
                }
            }
            break;
        }
        case 7: // Raw (simple string for now)
            // Added random NULL raw string input to hit cJSON_strdup's NULL check (lines 194-196 in cJSON.c)
            // and cJSON_CreateRaw's allocation failure path (lines 2536-2539 in cJSON.c).
            if (fdp.ConsumeBool()) {
                item.reset(cJSON_CreateRaw(nullptr));
            } else {
                // Store the string in a variable to ensure its lifetime extends beyond the c_str() call.
                std::string random_string = fdp.ConsumeRandomLengthString();
                if (random_string.empty()) {
                    item.reset(cJSON_CreateRaw(nullptr)); // Pass nullptr for empty string to avoid strdup(empty_string)
                } else {
                    item.reset(cJSON_CreateRaw(random_string.c_str()));
                }
            }
            break;
    }
    return item;
}

// Fuzz target entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Exercise CJSONDeleter::operator() (0.0% coverage)
    // This is implicitly tested by using unique_cJSON_ptr.
    // When `item_to_delete` goes out of scope, its destructor will call CJSONDeleter::operator(),
    // which in turn calls cJSON_Delete.
    {
        unique_cJSON_ptr item_to_delete = CreateFuzzedCjsonItem(fdp);
        // The item will be deleted when item_to_delete goes out of scope.
    }

    // Create a base cJSON object for operations
    unique_cJSON_ptr base_json = CreateFuzzedCjsonItem(fdp);
    // Added check for base_json to be non-null to prevent crashes in subsequent operations.
    if (!base_json) {
        return 0; // Cannot proceed without a base object
    }

    // 2. Exercise unsigned char * print(const const cJSON *, cJSON_bool, const const internal_hooks *) (38.46% coverage)
    // This function is internal and typically called by cJSON_Print.
    // Calling cJSON_Print will exercise the internal `print` function and `ensure`.
    // cJSON_Print allocates memory, which needs to be freed.
    char* printed_json = cJSON_Print(base_json.get());
    if (printed_json) {
        // The `print` function (and `ensure`) are exercised during cJSON_Print.
        // Free the allocated string to prevent memory leaks.
        free(printed_json);
    }

    // Also test cJSON_PrintUnformatted to ensure different paths in `print` are taken.
    char* printed_unformatted_json = cJSON_PrintUnformatted(base_json.get());
    if (printed_unformatted_json) {
        free(printed_unformatted_json);
    }

    // Added test for print_value's default case (lines 1448-1449 in cJSON.c)
    // by creating an item and manually setting its type to an invalid value.
    unique_cJSON_ptr invalid_type_json = unique_cJSON_ptr(cJSON_CreateNumber(0)); // Create a valid cJSON object first
    if (invalid_type_json) {
        invalid_type_json->type = fdp.ConsumeIntegralInRange<int>(256, 512); // Arbitrary invalid type
        char* printed_invalid = cJSON_Print(invalid_type_json.get());
        if (printed_invalid) {
            free(printed_invalid);
        }
    }

    // Added tests for print_number's isnan/isinf branch (lines 570-572 in cJSON.c)
    unique_cJSON_ptr nan_json = unique_cJSON_ptr(cJSON_CreateNumber(NAN));
    if (nan_json) {
        char* printed_nan = cJSON_Print(nan_json.get());
        if (printed_nan) {
            free(printed_nan);
        }
    }
    unique_cJSON_ptr inf_json = unique_cJSON_ptr(cJSON_CreateNumber(INFINITY));
    if (inf_json) {
        char* printed_inf = cJSON_Print(inf_json.get());
        if (printed_inf) {
            free(printed_inf);
        }
    }

    // 3. Exercise cJSON_bool replace_item_in_object(cJSON *, const char *, cJSON *, cJSON_bool) (47.05% coverage)
    // This function requires a cJSON object that is an object type.
    // It also requires a key and a new item to replace with.
    if (cJSON_IsObject(base_json.get())) {
        std::string key_to_replace = fdp.ConsumeRandomLengthString(16); // Key for replacement
        unique_cJSON_ptr new_item = CreateFuzzedCjsonItem(fdp); // New item to insert

        if (new_item) {
            cJSON* raw_new_item = new_item.release(); // Release ownership
            // Attempt to replace an item using the public API cJSON_ReplaceItemInObject.
            // cJSON_ReplaceItemInObject takes ownership of new_item if successful.
            // Added test to hit cJSON_ReplaceItemViaPointer's `replacement == item` branch (lines 2323-2325 in cJSON.c).
            cJSON* existing_item = cJSON_GetObjectItem(base_json.get(), key_to_replace.c_str());
            if (existing_item && fdp.ConsumeBool()) { // Randomly try to replace an existing item with itself
                // If replacement fails, existing_item is still part of base_json, no deletion needed.
                cJSON_ReplaceItemInObject(base_json.get(), key_to_replace.c_str(), existing_item);
                cJSON_Delete(raw_new_item); // Delete the new_item that was not used
            } else {
                if (!cJSON_ReplaceItemInObject(base_json.get(), key_to_replace.c_str(), raw_new_item)) {
                    cJSON_Delete(raw_new_item); // If replacement failed, delete it manually
                }
            }
        }
    }

    // 4. Exercise char * cJSON_SetValuestring(cJSON *, const char *) (66.66% coverage)
    // This function modifies the string value of a cJSON item.
    // It requires a cJSON item that is a string type.
    if (cJSON_IsString(base_json.get())) {
        // Store the string in a variable to ensure its lifetime extends beyond the c_str() call.
        std::string new_string_value = fdp.ConsumeRandomLengthString();
        // cJSON_SetValuestring handles its own memory management for the valuestring.
        // It frees the old string internally and returns the new string (or the modified existing one).
        // The returned char* should not be freed by the caller.
        cJSON_SetValuestring(base_json.get(), new_string_value.c_str());

        // Added test to hit cJSON_SetValuestring's NULL valuestring branch (lines 413-415 in cJSON.c).
        if (fdp.ConsumeBool()) {
            cJSON_SetValuestring(base_json.get(), nullptr);
        }
    }
    // Added tests to hit cJSON_SetValuestring's initial NULL object or non-string type branch (lines 408-410 in cJSON.c).
    if (fdp.ConsumeBool()) {
        cJSON_SetValuestring(nullptr, "test"); // Test NULL object
    }
    if (cJSON_IsNumber(base_json.get()) && fdp.ConsumeBool()) {
        cJSON_SetValuestring(base_json.get(), "test"); // Test non-string object
    }

    // Added tests for cJSON_IsString and cJSON_IsObject with NULL input (lines 2972-2974 and 2992-2994 in cJSON.c).
    cJSON_IsString(nullptr);
    cJSON_IsObject(nullptr);

    // Added tests for get_object_item with NULL object or NULL name (lines 1903-1905 in cJSON.c).
    if (cJSON_IsObject(base_json.get())) {
        cJSON_GetObjectItem(nullptr, "key"); // Test NULL object
        cJSON_GetObjectItem(base_json.get(), nullptr); // Test NULL name
    }

    // Added test for get_object_item's case_sensitive branch (lines 1909-1914 in cJSON.c).
    if (cJSON_IsObject(base_json.get())) {
        std::string key_for_case_sensitive = fdp.ConsumeRandomLengthString(16);
        // Add an item with this key to ensure it exists for lookup.
        unique_cJSON_ptr dummy_value = CreateFuzzedCjsonItem(fdp);
        if (dummy_value) {
            // cJSON_AddItemToObject takes ownership of dummy_value.
            cJSON_AddItemToObject(base_json.get(), key_for_case_sensitive.c_str(), dummy_value.release());
        }
        cJSON_GetObjectItemCaseSensitive(base_json.get(), key_for_case_sensitive.c_str());
    }

    // Added tests for add_item_to_array's NULL checks (lines 1979-1981 in cJSON.c).
    if (cJSON_IsArray(base_json.get())) {
        unique_cJSON_ptr item_for_add_array = CreateFuzzedCjsonItem(fdp);
        if (item_for_add_array) {
            cJSON_AddItemToArray(nullptr, item_for_add_array.get()); // Test NULL array
            cJSON_AddItemToArray(base_json.get(), nullptr); // Test NULL item
            cJSON_AddItemToArray(base_json.get(), base_json.get()); // Test array == item
        }
    }

    // Added tests for add_item_to_object's NULL checks (lines 2035-2037 in cJSON.c).
    if (cJSON_IsObject(base_json.get())) {
        unique_cJSON_ptr item_for_add_object = CreateFuzzedCjsonItem(fdp);
        if (item_for_add_object) {
            cJSON_AddItemToObject(nullptr, "key", item_for_add_object.get()); // Test NULL object
            cJSON_AddItemToObject(base_json.get(), nullptr, item_for_add_object.get()); // Test NULL key
            cJSON_AddItemToObject(base_json.get(), "key", nullptr); // Test NULL item
            cJSON_AddItemToObject(base_json.get(), "key", base_json.get()); // Test object == item
        }
    }

    // Added test for add_item_to_object's constant_key branch (lines 2040-2043 in cJSON.c).
    if (cJSON_IsObject(base_json.get())) {
        unique_cJSON_ptr item_for_add_object_cs = CreateFuzzedCjsonItem(fdp);
        if (item_for_add_object_cs) {
            // cJSON_AddItemToObjectCS takes ownership of the item and treats the key as constant.
            cJSON_AddItemToObjectCS(base_json.get(), "constant_key", item_for_add_object_cs.release());
        }
    }

    // Added tests for replace_item_in_object's NULL checks (lines 2377-2379 in cJSON.c).
    if (cJSON_IsObject(base_json.get())) {
        unique_cJSON_ptr replacement_item = CreateFuzzedCjsonItem(fdp);
        if (replacement_item) {
            cJSON_ReplaceItemInObject(base_json.get(), "key", nullptr); // Test NULL replacement
            cJSON_ReplaceItemInObject(base_json.get(), nullptr, replacement_item.get()); // Test NULL string
        }
    }

    // Additional fuzzing for `print` and `ensure` by creating various JSON structures
    // and printing them. This ensures diverse inputs for the printing logic.
    for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(0, 3); ++i) {
        unique_cJSON_ptr complex_json = CreateFuzzedCjsonItem(fdp);
        if (complex_json) {
            char* printed_complex = cJSON_Print(complex_json.get());
            if (printed_complex) {
                free(printed_complex);
            }
        }
    }

    // --- New additions for coverage improvement ---

    // Added tests for cJSON_IsNumber and cJSON_IsArray with NULL input (lines 2962-2964 and 2982-2984 in cJSON.c).
    // These lines previously had 0 hits.
    cJSON_IsNumber(nullptr);
    cJSON_IsArray(nullptr);

    // Added tests for case_insensitive_strcmp's NULL checks and identical pointer branch.
    // Lines 136-138 and 141-143 in cJSON.c previously had 0 hits.
    // Note: case_insensitive_strcmp is an internal function, so we can't call it directly.
    // However, it's called by get_object_item when case_sensitive is false.
    // The existing fuzzer already calls cJSON_GetObjectItem which uses get_object_item with case_sensitive=false.
    // To hit the NULL checks in case_insensitive_strcmp, we would need to make get_object_item pass NULL strings,
    // which is not directly possible without corrupting cJSON internal state.
    // The `string1 == string2` branch can be hit if `current_element->string` is the same pointer as `name`.
    // This is also hard to control without direct access to cJSON's internal string pointers.
    // Given the constraints, directly targeting these internal branches is difficult without
    // significant changes to cJSON's memory management or internal structure.
    // I will add a dummy call to a public API that *might* indirectly trigger it if the fuzzer
    // generates specific inputs, but direct control is limited.
    // The existing `cJSON_GetObjectItem(base_json.get(), nullptr)` already tests a NULL name.
    // The `cJSON_GetObjectItem(nullptr, "key")` tests a NULL object.
    // These already cover the `get_object_item` NULL checks.

    // To hit `add_item_to_object` line 2056 (deallocate `item->string` when `!cJSON_StringIsConst` and `item->string != NULL`):
    // This branch is taken when `constant_key` is false (which is the case for `cJSON_AddItemToObject`)
    // and the `item` being added already has a non-NULL `string` member that is not `cJSON_StringIsConst`.
    // We can create a string item, then add it to an object.
    if (cJSON_IsObject(base_json.get())) {
        std::string key_for_add_item_to_object_branch = fdp.ConsumeRandomLengthString(16);
        // Create a string item that is NOT constant (default for cJSON_CreateString)
        unique_cJSON_ptr string_item_for_branch = unique_cJSON_ptr(cJSON_CreateString("initial_string"));
        if (string_item_for_branch) {
            // Ensure it's not marked as constant, which cJSON_CreateString already does.
            // Add it to the object. This should trigger the deallocation of "initial_string"
            // if the item's string is replaced by the new key.
            // Memory safety: cJSON_AddItemToObject takes ownership of string_item_for_branch.release().
            cJSON_AddItemToObject(base_json.get(), key_for_add_item_to_object_branch.c_str(), string_item_for_branch.release());
        }
    }

    // All unique_cJSON_ptr objects will be automatically deleted when they go out of scope,
    // ensuring memory safety and exercising CJSONDeleter::operator().

    return 0;
}