#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min
#include <cstring> // For strlen, memcpy
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
        // Modified: Increased range to cover new operations (0-29 for 30 operations).
        uint8_t operation = fdp.ConsumeIntegralInRange<uint8_t>(0, 29);

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
            case 8: { // Added: Exercise cJSON_GetErrorPtr()
                // Added call to cJSON_GetErrorPtr() based on coverage report (0% coverage).
                cJSON_GetErrorPtr();
                break;
            }
            case 9: { // Added: Exercise cJSON_Version()
                // Added call to cJSON_Version() based on coverage report (0% coverage).
                cJSON_Version();
                break;
            }
            case 10: { // Added: Exercise cJSON_CreateNull()
                // Added call to cJSON_CreateNull() based on coverage report (0% coverage).
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> null_item(cJSON_CreateNull(), &SafeCJSONDelete);
                break;
            }
            case 11: { // Added: Exercise cJSON_CreateTrue()
                // Added call to cJSON_CreateTrue() based on coverage report (0% coverage).
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> true_item(cJSON_CreateTrue(), &SafeCJSONDelete);
                break;
            }
            case 12: { // Added: Exercise cJSON_CreateFalse()
                // Added call to cJSON_CreateFalse() based on coverage report (0% coverage).
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> false_item(cJSON_CreateFalse(), &SafeCJSONDelete);
                break;
            }
            case 13: { // Added: Exercise cJSON_CreateBool()
                // Added call to cJSON_CreateBool() based on coverage report (0% coverage).
                cJSON_bool boolean_val = fdp.ConsumeBool();
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> bool_item(cJSON_CreateBool(boolean_val), &SafeCJSONDelete);
                break;
            }
            case 14: { // Added: Exercise cJSON_CreateString()
                // Added call to cJSON_CreateString() based on coverage report (0% coverage).
                std::string str_val = fdp.ConsumeRandomLengthString(std::min((size_t)1024, fdp.remaining_bytes()));
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> string_item(cJSON_CreateString(str_val.c_str()), &SafeCJSONDelete);
                break;
            }
            case 15: { // Added: Exercise cJSON_CreateFloatArray()
                // Added call to cJSON_CreateFloatArray() based on coverage report (0% coverage).
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 10);
                std::vector<float> float_array;
                for (size_t i = 0; i < num_elements; ++i) {
                    float_array.push_back(fdp.ConsumeFloatingPoint<float>());
                }
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> float_json_array(
                    cJSON_CreateFloatArray(float_array.data(), float_array.size()), &SafeCJSONDelete);
                break;
            }
            case 16: { // Added: Exercise cJSON_CreateDoubleArray()
                // Added call to cJSON_CreateDoubleArray() based on coverage report (0% coverage).
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 10);
                std::vector<double> double_array;
                for (size_t i = 0; i < num_elements; ++i) {
                    double_array.push_back(fdp.ConsumeFloatingPoint<double>());
                }
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> double_json_array(
                    cJSON_CreateDoubleArray(double_array.data(), double_array.size()), &SafeCJSONDelete);
                break;
            }
            case 17: { // Added: Exercise cJSON_CreateStringArray()
                // Added call to cJSON_CreateStringArray() based on coverage report (0% coverage).
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 10);
                std::vector<std::string> string_vec;
                // Reserve capacity to prevent reallocations that would invalidate c_str() pointers.
                string_vec.reserve(num_elements);
                std::vector<const char*> string_ptrs;
                string_ptrs.reserve(num_elements);
                for (size_t i = 0; i < num_elements; ++i) {
                    string_vec.push_back(fdp.ConsumeRandomLengthString(std::min((size_t)256, fdp.remaining_bytes())));
                    string_ptrs.push_back(string_vec.back().c_str());
                }
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> string_json_array(
                    cJSON_CreateStringArray(string_ptrs.data(), string_ptrs.size()), &SafeCJSONDelete);
                break;
            }
            case 18: { // Added: Exercise cJSON_Minify()
                // Added call to cJSON_Minify() based on coverage report (0% coverage).
                // This requires a mutable string, so we print the root and then create a mutable copy.
                char* printed_json = cJSON_Print(root);
                if (printed_json) {
                    size_t len = strlen(printed_json);
                    // Allocate memory using cJSON_malloc for the mutable copy
                    char* mutable_copy = (char*)cJSON_malloc(len + 1); // +1 for null terminator
                    if (mutable_copy) {
                        memcpy(mutable_copy, printed_json, len + 1); // Copy including null terminator
                        // Use unique_ptr to manage the mutable_copy, ensuring it's freed with cJSON_free
                        std::unique_ptr<char, decltype(&cJSON_free)> mutable_json_ptr(mutable_copy, &cJSON_free);
                        cJSON_Minify(mutable_json_ptr.get());
                    }
                    cJSON_free(printed_json); // Free the original printed string
                }
                break;
            }
            case 19: { // Added: Exercise cJSON_Compare()
                // Added call to cJSON_Compare() based on coverage report (0% coverage).
                // Compare root with a duplicate of itself and with a newly parsed item to cover different comparison paths.
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> duplicated_root(cJSON_Duplicate(root, fdp.ConsumeBool()), &SafeCJSONDelete);
                if (duplicated_root) {
                    cJSON_Compare(root, duplicated_root.get(), fdp.ConsumeBool());
                }

                std::string json_string_for_compare = fdp.ConsumeRandomLengthString(std::min((size_t)4096, fdp.remaining_bytes()));
                std::unique_ptr<cJSON, decltype(&SafeCJSONDelete)> parsed_item_for_compare(cJSON_Parse(json_string_for_compare.c_str()), &SafeCJSONDelete);
                if (parsed_item_for_compare) {
                    cJSON_Compare(root, parsed_item_for_compare.get(), fdp.ConsumeBool());
                }
                break;
            }
            case 20: { // Added: Exercise cJSON_IsInvalid()
                // Added call to cJSON_IsInvalid() based on coverage report (0% coverage).
                cJSON_IsInvalid(root);
                break;
            }
            case 21: { // Added: Exercise cJSON_IsFalse()
                // Added call to cJSON_IsFalse() based on coverage report (0% coverage).
                cJSON_IsFalse(root);
                break;
            }
            case 22: { // Added: Exercise cJSON_IsTrue()
                // Added call to cJSON_IsTrue() based on coverage report (0% coverage).
                cJSON_IsTrue(root);
                break;
            }
            case 23: { // Added: Exercise cJSON_IsBool()
                // Added call to cJSON_IsBool() based on coverage report (0% coverage).
                cJSON_IsBool(root);
                break;
            }
            case 24: { // Added: Exercise cJSON_IsNull()
                // Added call to cJSON_IsNull() based on coverage report (0% coverage).
                cJSON_IsNull(root);
                break;
            }
            case 25: { // Added: Exercise cJSON_IsNumber()
                // Added call to cJSON_IsNumber() based on coverage report (0% coverage).
                cJSON_IsNumber(root);
                break;
            }
            case 26: { // Added: Exercise cJSON_IsString()
                // Added call to cJSON_IsString() based on coverage report (0% coverage).
                cJSON_IsString(root);
                break;
            }
            case 27: { // Added: Exercise cJSON_IsArray()
                // Added call to cJSON_IsArray() based on coverage report (0% coverage).
                cJSON_IsArray(root);
                break;
            }
            case 28: { // Added: Exercise cJSON_IsObject()
                // Added call to cJSON_IsObject() based on coverage report (0% coverage).
                cJSON_IsObject(root);
                break;
            }
            case 29: { // Added: Exercise cJSON_IsRaw()
                // Added call to cJSON_IsRaw() based on coverage report (0% coverage).
                cJSON_IsRaw(root);
                break;
            }
        }
    }

    // The destructor of 'root_ptr' will automatically call SafeCJSONDelete(root),
    // ensuring all cJSON objects created and managed by 'root' are properly freed.
    // This completes the memory-safe fuzz target.

    return 0;
}