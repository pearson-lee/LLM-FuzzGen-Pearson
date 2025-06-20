#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr

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
            item.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str()));
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
                        if (!cJSON_AddItemToArray(item.get(), raw_child)) {
                            cJSON_Delete(raw_child);
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
                        if (!cJSON_AddItemToObject(item.get(), key.c_str(), raw_value)) {
                            cJSON_Delete(raw_value);
                        }
                    }
                }
            }
            break;
        }
        case 7: // Raw (simple string for now)
            item.reset(cJSON_CreateRaw(fdp.ConsumeRandomLengthString().c_str()));
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
            if (!cJSON_ReplaceItemInObject(base_json.get(), key_to_replace.c_str(), raw_new_item)) {
                cJSON_Delete(raw_new_item); // If replacement failed, delete it manually
            }
        }
    }

    // 4. Exercise char * cJSON_SetValuestring(cJSON *, const char *) (66.66% coverage)
    // This function modifies the string value of a cJSON item.
    // It requires a cJSON item that is a string type.
    if (cJSON_IsString(base_json.get())) {
        std::string new_string_value = fdp.ConsumeRandomLengthString();
        // cJSON_SetValuestring handles its own memory management for the valuestring.
        // It frees the old string internally and returns the new string (or the modified existing one).
        // The returned char* should not be freed by the caller.
        cJSON_SetValuestring(base_json.get(), new_string_value.c_str());
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

    // All unique_cJSON_ptr objects will be automatically deleted when they go out of scope,
    // ensuring memory safety and exercising CJSONDeleter::operator().

    return 0;
}