#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min

// Include the cJSON header with its full project-relative path.
#include "/src/cjson/cJSON.h"

// Define a helper function to safely delete cJSON objects.
// This is crucial for memory safety. cJSON_Delete handles freeing the entire
// cJSON tree, including all its children and associated memory, preventing leaks.
void SafeCJSONDelete(cJSON* item) {
    if (item != nullptr) {
        cJSON_Delete(item);
    }
}

// Custom deleter for char* returned by cJSON_Print, using cJSON_free.
// This ensures that memory allocated by cJSON_Print is deallocated using the
// library's own free function, preventing potential memory mismatches.
struct CJSONCharFree {
    void operator()(char* ptr) const {
        if (ptr != nullptr) {
            cJSON_free(ptr);
        }
    }
};

// LLVMFuzzerTestOneInput is the entry point for the fuzzer.
// It takes raw fuzzer input data and its size.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize FuzzedDataProvider to consume the input data.
    FuzzedDataProvider fdp(Data, Size);

    // Create a root cJSON object (an empty object) to serve as the base for fuzzing operations.
    // This object will manage the lifetime of all its children.
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        // If root object creation fails (e.g., out of memory), there's nothing to fuzz.
        return 0;
    }

    // Use std::unique_ptr with a custom deleter (SafeCJSONDelete) for automatic memory management.
    // This RAII (Resource Acquisition Is Initialization) approach ensures that cJSON_Delete is
    // called on the root object when root_ptr goes out of scope, preventing memory leaks
    // even if the fuzzer exits prematurely due to an error or an early return.
    std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> root_ptr(root, &SafeCJSONDelete);

    // Continue performing fuzzing operations as long as there's data remaining in the fuzzer input.
    while (fdp.remaining_bytes() > 0) {
        // Consume an integral to decide which cJSON API operation to perform.
        // Increased range to include new operations (cases 5, 6, 7).
        uint8_t operation = fdp.ConsumeIntegralInRange<uint8_t>(0, 7);

        // Generate a key string for object operations.
        // Limiting the length to prevent excessive memory consumption for keys,
        // and ensuring we don't consume all remaining bytes for just the key.
        std::string key = fdp.ConsumeRandomLengthString(std::min((size_t)256, fdp.remaining_bytes()));
        if (key.empty()) {
            key = "fuzz_key"; // Provide a default key if the fuzzer input results in an empty string.
        }

        // Execute the chosen cJSON API based on the 'operation' value.
        switch (operation) {
            case 0: { // Exercise cJSON_AddObjectToObject(cJSON * const object, const char * const name)
                // Adds a new cJSON object as a child of the root object with the given key.
                // The newly created object is owned by 'root' upon successful addition,
                // so no explicit deletion is needed for the returned cJSON* here.
                cJSON_AddObjectToObject(root, key.c_str());
                break;
            }
            case 1: { // Exercise cJSON_AddArrayToObject(cJSON * const object, const char * const name)
                // Adds a new cJSON array as a child of the root object with the given key.
                // Similar to AddObjectToObject, the newly created array is owned by 'root'.
                cJSON_AddArrayToObject(root, key.c_str());
                break;
            }
            case 2: { // Exercise cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string, cJSON *newitem)
                // This operation tests replacing an existing item within the object.
                // First, create a new cJSON item (using cJSON_CreateRaw for diverse input types).
                std::string raw_value = fdp.ConsumeRandomLengthString(std::min((size_t)1024, fdp.remaining_bytes()));
                cJSON *new_item = cJSON_CreateRaw(raw_value.c_str());

                // Use a unique_ptr for 'new_item' to ensure it's deleted if:
                // 1. Its creation fails (new_item is nullptr).
                // 2. The replacement operation fails (new_item is not added to 'root').
                // 3. The fuzzer loop terminates before 'new_item' is managed by 'root'.
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> new_item_ptr(new_item, &SafeCJSONDelete);

                if (new_item != nullptr) {
                    // Attempt to replace an item in 'root' with 'new_item'.
                    cJSON_bool success = cJSON_ReplaceItemInObjectCaseSensitive(root, key.c_str(), new_item);
                    if (success) {
                        // If replacement was successful, 'root' now owns 'new_item'.
                        // Release ownership from new_item_ptr to prevent double-free when new_item_ptr goes out of scope.
                        new_item_ptr.release();
                    }
                }
                break;
            }
            case 3: { // Exercise cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)
                // Deletes an item from the root object based on the provided key.
                // This tests deletion logic and ensures proper memory deallocation of the deleted item.
                cJSON_DeleteItemFromObjectCaseSensitive(root, key.c_str());
                break;
            }
            case 4: { // Exercise cJSON_CreateRaw(const char *raw)
                // This operation focuses on the creation of a raw cJSON item.
                // It's important to test the creation process itself, even if the item isn't added to the main tree.
                std::string raw_data = fdp.ConsumeRandomLengthString(std::min((size_t)1024, fdp.remaining_bytes()));
                cJSON *raw_item = cJSON_CreateRaw(raw_data.c_str());
                // Since this raw_item is not added to 'root' (and thus not managed by root_ptr),
                // it must be explicitly deleted here to prevent a memory leak.
                SafeCJSONDelete(raw_item);
                break;
            }
            case 5: { // New operation: cJSON_Print, cJSON_Parse, cJSON_Minify
                // Document: Added to cover cJSON_Print, cJSON_Parse, and cJSON_Minify functions.
                // Print the current root object to a JSON string.
                char* printed_json_str = cJSON_Print(root);
                // Document: Using std::unique_ptr with custom deleter CJSONCharFree to manage memory returned by cJSON_Print.
                std::unique_ptr<char, CJSONCharFree> printed_json_ptr(printed_json_str);

                if (printed_json_str != nullptr) {
                    // Document: Calling cJSON_Parse to cover parsing logic.
                    cJSON* parsed_json = cJSON_Parse(printed_json_str);
                    // Document: Using std::unique_ptr with SafeCJSONDelete to manage memory returned by cJSON_Parse.
                    std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> parsed_json_ptr(parsed_json, &SafeCJSONDelete);

                    // Document: Calling cJSON_Minify to cover minification logic.
                    // Create a mutable copy for cJSON_Minify as it modifies in place.
                    std::string mutable_json_str = printed_json_str;
                    cJSON_Minify(const_cast<char*>(mutable_json_str.c_str()));
                }

                // Also test cJSON_Parse with a fuzzed string directly to cover more parsing paths.
                std::string fuzzed_json_str = fdp.ConsumeRandomLengthString(std::min((size_t)2048, fdp.remaining_bytes()));
                if (!fuzzed_json_str.empty()) {
                    cJSON* fuzzed_parsed_json = cJSON_Parse(fuzzed_json_str.c_str());
                    std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> fuzzed_parsed_json_ptr(fuzzed_parsed_json, &SafeCJSONDelete);

                    // Document: Calling cJSON_Minify on a fuzzed string.
                    std::string mutable_fuzzed_json_str = fuzzed_json_str;
                    cJSON_Minify(const_cast<char*>(mutable_fuzzed_json_str.c_str()));
                }
                break;
            }
            case 6: { // New operation: cJSON_Is* and cJSON_Get*Value functions
                // Document: Added to cover various cJSON_Is* functions and cJSON_Get*Value to improve coverage of type checking and value retrieval.
                // Test on root object (its type might vary based on previous operations)
                cJSON_IsInvalid(root);
                cJSON_IsFalse(root);
                cJSON_IsTrue(root);
                cJSON_IsBool(root);
                cJSON_IsNull(root);
                cJSON_IsNumber(root);
                cJSON_IsString(root);
                cJSON_IsArray(root);
                cJSON_IsObject(root);
                cJSON_IsRaw(root);
                cJSON_GetStringValue(root);
                cJSON_GetNumberValue(root);

                // Create and test different types of cJSON items to ensure comprehensive coverage.
                cJSON* null_item = cJSON_CreateNull();
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> null_item_ptr(null_item, &SafeCJSONDelete);
                if (null_item) { cJSON_IsNull(null_item); cJSON_IsBool(null_item); } // Test cJSON_IsBool on null

                cJSON* true_item = cJSON_CreateTrue();
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> true_item_ptr(true_item, &SafeCJSONDelete);
                if (true_item) { cJSON_IsTrue(true_item); cJSON_IsBool(true_item); }

                cJSON* false_item = cJSON_CreateFalse();
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> false_item_ptr(false_item, &SafeCJSONDelete);
                if (false_item) { cJSON_IsFalse(false_item); cJSON_IsBool(false_item); }

                double num_val = fdp.ConsumeFloatingPoint<double>();
                cJSON* num_item = cJSON_CreateNumber(num_val);
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> num_item_ptr(num_item, &SafeCJSONDelete);
                if (num_item) { cJSON_IsNumber(num_item); cJSON_GetNumberValue(num_item); }

                std::string str_val = fdp.ConsumeRandomLengthString(std::min((size_t)128, fdp.remaining_bytes()));
                cJSON* str_item = cJSON_CreateString(str_val.c_str());
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> str_item_ptr(str_item, &SafeCJSONDelete);
                if (str_item) { cJSON_IsString(str_item); cJSON_GetStringValue(str_item); }

                cJSON* array_item = cJSON_CreateArray();
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> array_item_ptr(array_item, &SafeCJSONDelete);
                if (array_item) { cJSON_IsArray(array_item); }

                cJSON* object_item = cJSON_CreateObject();
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> object_item_ptr(object_item, &SafeCJSONDelete);
                if (object_item) { cJSON_IsObject(object_item); }

                break;
            }
            case 7: { // New operation: cJSON_Create* variants for basic types
                // Document: Added to cover various cJSON_Create* functions for basic types (Null, True, False, Bool, Number, String).
                cJSON* created_item = nullptr;
                uint8_t create_op = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);
                switch (create_op) {
                    case 0: created_item = cJSON_CreateNull(); break;
                    case 1: created_item = cJSON_CreateTrue(); break;
                    case 2: created_item = cJSON_CreateFalse(); break;
                    case 3: created_item = cJSON_CreateBool(fdp.ConsumeBool()); break;
                    case 4: created_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
                    case 5: {
                        std::string s = fdp.ConsumeRandomLengthString(std::min((size_t)128, fdp.remaining_bytes()));
                        created_item = cJSON_CreateString(s.c_str());
                        break;
                    }
                }
                // Document: Ensuring proper memory management for newly created cJSON items that are not added to the root.
                SafeCJSONDelete(created_item); // Delete immediately as they are not added to the root.
                break;
            }
        }
    }

    // The destructor of 'root_ptr' will automatically call SafeCJSONDelete(root),
    // ensuring all cJSON objects created and managed by 'root' are properly freed.
    // This completes the memory-safe fuzz target.

    return 0;
}