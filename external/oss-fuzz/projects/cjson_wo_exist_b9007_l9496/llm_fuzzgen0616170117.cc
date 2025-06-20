#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min
#include <cstring> // For strdup (though not used in final version, kept for potential future use if minify was included)
#include <cmath> // For isnan, isinf (indirectly used by cJSON_PrintNumber/ParseNumber)

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
        // Modified: Increased range to cover new operations (0-7 for 8 operations).
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
            case 5: { // Added: Exercise cJSON_Parse(const char *value)
                // Added call to cJSON_Parse based on coverage report (0% coverage).
                // This aims to cover the JSON parsing logic and its internal functions (e.g., parse_value, parse_string, parse_number).
                std::string json_string = fdp.ConsumeRandomLengthString(std::min((size_t)4096, fdp.remaining_bytes()));
                // Use unique_ptr to manage the memory returned by cJSON_Parse, ensuring it's freed.
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> parsed_item(cJSON_Parse(json_string.c_str()), &SafeCJSONDelete);
                break;
            }
            case 6: { // Added: Exercise cJSON_Print(const cJSON *item)
                // Added call to cJSON_Print based on coverage report (0% coverage).
                // This aims to cover the JSON printing logic and its internal functions (e.g., print_value, print_string, print_number).
                char* printed_json = cJSON_Print(root);
                // Memory allocated by cJSON_Print must be freed using cJSON_free.
                if (printed_json) {
                    cJSON_free(printed_json); // Memory-safe: uses cJSON's deallocation function.
                }
                break;
            }
            case 7: { // Added: Exercise cJSON_CreateIntArray(const int *numbers, int count)
                // Added call to cJSON_CreateIntArray based on coverage report (0% coverage).
                // This aims to cover the creation of integer arrays and related internal logic.
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 10); // Limit array size to prevent excessive memory usage
                std::vector<int> int_array;
                for (size_t i = 0; i < num_elements; ++i) {
                    int_array.push_back(fdp.ConsumeIntegral<int>());
                }
                // Use unique_ptr to manage the memory of the created array, ensuring it's freed.
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> int_json_array(
                    cJSON_CreateIntArray(int_array.data(), int_array.size()), &SafeCJSONDelete);
                break;
            }
        }
    }

    // The destructor of 'root_ptr' will automatically call SafeCJSONDelete(root),
    // ensuring all cJSON objects created and managed by 'root' are properly freed.
    // This completes the memory-safe fuzz target.

    return 0;
}