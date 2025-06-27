#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // Required for std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h" // All headers are provided with full project-relative path

// Custom deleter for cJSON* to enable RAII with std::unique_ptr.
// This ensures that cJSON objects are always properly freed using cJSON_Delete,
// preventing memory leaks.
struct CJSONDeleter {
    void operator()(cJSON* obj) const {
        if (obj) {
            cJSON_Delete(obj);
        }
    }
};

// Dummy malloc and free functions for cJSON_InitHooks
static void* fuzzer_malloc(size_t size) {
    return malloc(size);
}

static void fuzzer_free(void* ptr) {
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Fuzzing `cJSON_ParseWithLengthOpts`
    // This function is chosen as it's the core parsing logic, and `cJSON_Parse`
    // and `cJSON_ParseWithOpts` are wrappers around it. It offers more parameters
    // for comprehensive fuzzing, targeting its low branch coverage.
    {
        // Generate a random length JSON string from the fuzzer data.
        std::string json_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 4096));
        const char* value = json_str.c_str();
        size_t buffer_length = json_str.length();
        
        // Determine if `return_parse_end` should be used (non-NULL) or not.
        const char* return_parse_end_ptr = nullptr;
        bool use_return_parse_end = fdp.ConsumeBool();
        const char** return_parse_end = use_return_parse_end ? &return_parse_end_ptr : nullptr;

        // Determine if the JSON should be required to be null-terminated.
        cJSON_bool require_null_terminated = fdp.ConsumeBool();

        // Case 1: Standard parsing with generated inputs.
        // The parsed item is managed by unique_ptr for automatic deletion.
        std::unique_ptr<cJSON, CJSONDeleter> parsed_item(
            cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated)
        );

        // Case 2: Test with NULL `value` argument.
        // This specifically targets the `if (value == NULL || ...)` branch (line 1113:9)
        // in `cJSON_ParseWithLengthOpts` which was previously uncovered.
        std::unique_ptr<cJSON, CJSONDeleter> parsed_item_null_value(
            cJSON_ParseWithLengthOpts(NULL, buffer_length, return_parse_end, require_null_terminated)
        );

        // Case 3: Test with 0 `buffer_length`.
        // This targets the `if (... || 0 == buffer_length)` branch (line 1113:26)
        // in `cJSON_ParseWithLengthOpts` which was also uncovered.
        std::unique_ptr<cJSON, CJSONDeleter> parsed_item_zero_len(
            cJSON_ParseWithLengthOpts(value, 0, return_parse_end, require_null_terminated)
        );

        // Case 4: Test with non-NULL `return_parse_end` and a parsing failure.
        // This aims to hit the `if (return_parse_end != NULL)` branch within the error
        // handling block (line 1172:13) in `cJSON_ParseWithLengthOpts`.
        const char* fail_end_ptr = nullptr;
        // Generate a small, likely invalid JSON string to trigger a parse failure.
        std::string invalid_json = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 100));
        std::unique_ptr<cJSON, CJSONDeleter> parsed_invalid(
            cJSON_ParseWithLengthOpts(invalid_json.c_str(), invalid_json.length(), &fail_end_ptr, require_null_terminated)
        );
    }

    // 2. Fuzzing `cJSON_PrintPreallocated`
    // This function had 0% coverage and allows testing the library's ability to print
    // JSON into a user-provided, fixed-size buffer, which is critical for memory safety.
    {
        // Create a cJSON object to print. Using `cJSON_Parse` here provides diverse content.
        std::string json_to_print_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512));
        std::unique_ptr<cJSON, CJSONDeleter> item_to_print(cJSON_Parse(json_to_print_str.c_str()));

        if (item_to_print) {
            // Generate a buffer size and allocate a vector to serve as the preallocated buffer.
            size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, 2048);
            std::vector<char> print_buffer(buffer_size); // Memory managed by std::vector.
            cJSON_bool format = fdp.ConsumeBool(); // Determine if output should be formatted.

            // Case 1: Valid buffer and length.
            cJSON_PrintPreallocated(item_to_print.get(), print_buffer.data(), static_cast<int>(buffer_size), format);

            // Case 2: NULL `buffer`.
            // This targets the `if (... || (buffer == NULL))` branch (line 1309:25)
            // in `cJSON_PrintPreallocated` which was previously uncovered.
            cJSON_PrintPreallocated(item_to_print.get(), NULL, static_cast<int>(buffer_size), format);

            // Case 3: Negative `length`.
            // This targets the `if ((length < 0) || ...)` branch (line 1309:9)
            // in `cJSON_PrintPreallocated` which was also previously uncovered.
            cJSON_PrintPreallocated(item_to_print.get(), print_buffer.data(), -1, format);
        }
    }

    // 3. Fuzzing `cJSON_AddNumberToObject`
    // This function modifies a cJSON object by adding a number property. It had 0% coverage.
    {
        // Create an empty cJSON object to add properties to.
        std::unique_ptr<cJSON, CJSONDeleter> root_object(cJSON_CreateObject());
        if (root_object) {
            // Generate a random key string and a double value.
            std::string key = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
            double number_val = fdp.ConsumeFloatingPoint<double>();

            // Add the first number to the object.
            cJSON_AddNumberToObject(root_object.get(), key.c_str(), number_val);

            // Add multiple numbers with different keys to test potential reallocations
            // within the object's internal structure and key collision handling.
            size_t num_additions = fdp.ConsumeIntegralInRange<size_t>(0, 10);
            for (size_t i = 0; i < num_additions; ++i) {
                std::string another_key = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
                double another_number = fdp.ConsumeFloatingPoint<double>();
                cJSON_AddNumberToObject(root_object.get(), another_key.c_str(), another_number);
            }
        }
        // Added call to cJSON_AddNumberToObject with NULL object to cover the `if (object == NULL)` branch.
        cJSON_AddNumberToObject(NULL, "dummy_key", 123.45);
    }

    // 4. Fuzzing `cJSON_Compare`
    // This function had 0% coverage and a significant number of missed branches (76),
    // making it a high-priority target for comprehensive testing of JSON comparison logic.
    {
        // Generate two random JSON strings to create cJSON objects for comparison.
        std::string json_str1 = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512));
        std::string json_str2 = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512));
        cJSON_bool case_sensitive = fdp.ConsumeBool(); // Test both case-sensitive and insensitive comparisons.

        // Parse the strings into cJSON objects. These might be NULL if parsing fails.
        std::unique_ptr<cJSON, CJSONDeleter> item1(cJSON_Parse(json_str1.c_str()));
        std::unique_ptr<cJSON, CJSONDeleter> item2(cJSON_Parse(json_str2.c_str()));

        // Test various combinations of valid and NULL items to cover edge cases in comparison.
        if (item1 && item2) {
            cJSON_Compare(item1.get(), item2.get(), case_sensitive);
        } else if (item1) {
            cJSON_Compare(item1.get(), NULL, case_sensitive); // Compare valid item against NULL.
        } else if (item2) {
            cJSON_Compare(NULL, item2.get(), case_sensitive); // Compare NULL against valid item.
        } else {
            cJSON_Compare(NULL, NULL, case_sensitive); // Compare two NULL items.
        }
    }

    // 5. Fuzzing `cJSON_CreateStringArray`
    // This function creates a JSON array from an array of C-style strings and had 0% coverage.
    {
        // Determine the number of strings for the array.
        size_t num_strings = fdp.ConsumeIntegralInRange<size_t>(0, 20);
        std::vector<std::string> string_vec; // Holds std::string objects (memory managed).
        // Reserve capacity to prevent reallocations that would invalidate c_str() pointers.
        string_vec.reserve(num_strings); 
        std::vector<const char*> c_strings;  // Holds C-style string pointers.
        c_strings.reserve(num_strings); // Reserve for c_strings for efficiency.

        // Populate `string_vec` with random strings and `c_strings` with pointers to them.
        for (size_t i = 0; i < num_strings; ++i) {
            string_vec.push_back(fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 100)));
            // The c_str() pointer is valid as long as the string_vec element doesn't move.
            // With reserve, it won't move.
            c_strings.push_back(string_vec.back().c_str());
        }

        // Case 1: Valid strings array and count.
        std::unique_ptr<cJSON, CJSONDeleter> string_array(
            cJSON_CreateStringArray(c_strings.data(), static_cast<int>(c_strings.size()))
        );

        // Case 2: NULL `strings` array with a non-zero count.
        // This aims to hit an error path or assertion if the library handles this case.
        if (num_strings > 0) {
            std::unique_ptr<cJSON, CJSONDeleter> null_strings_array(
                cJSON_CreateStringArray(NULL, static_cast<int>(num_strings))
            );
        }

        // Case 3: Valid `strings` array but zero count.
        // Tests the creation of an empty string array.
        std::unique_ptr<cJSON, CJSONDeleter> zero_count_array(
            cJSON_CreateStringArray(c_strings.data(), 0)
        );
    }

    // 6. Fuzzing simple utility functions (0% coverage)
    {
        // Added to cover cJSON_GetErrorPtr, which had 0% coverage.
        cJSON_GetErrorPtr();

        // Added to cover cJSON_Version, which had 0% coverage.
        cJSON_Version();

        // Added to cover cJSON_ParseWithLength, which had 0% coverage.
        std::string json_str_len = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 4096));
        std::unique_ptr<cJSON, CJSONDeleter> parsed_len(
            cJSON_ParseWithLength(json_str_len.c_str(), json_str_len.length())
        );
        // Added call with NULL value to cover the `if (value == NULL)` branch in cJSON_ParseWithLengthOpts (called by cJSON_ParseWithLength).
        std::unique_ptr<cJSON, CJSONDeleter> parsed_len_null(
            cJSON_ParseWithLength(NULL, 0)
        );
    }

    // 7. Fuzzing cJSON_InitHooks (0% coverage)
    {
        // Case 1: Call with NULL to reset hooks. Added to cover the NULL branch in cJSON_InitHooks.
        cJSON_InitHooks(NULL); 

        // Case 2: Call with custom hooks. Added to cover the non-NULL branch in cJSON_InitHooks.
        cJSON_Hooks custom_hooks;
        custom_hooks.malloc_fn = fuzzer_malloc;
        custom_hooks.free_fn = fuzzer_free;
        cJSON_InitHooks(&custom_hooks); 

        // Reset hooks to default after testing custom ones to avoid affecting other fuzzing.
        cJSON_InitHooks(NULL);
    }

    // 8. Fuzzing array item accessors (0% coverage)
    {
        std::unique_ptr<cJSON, CJSONDeleter> array_item(cJSON_CreateArray());
        if (array_item) {
            // Add some items to the array
            size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 10);
            for (size_t i = 0; i < num_elements; ++i) {
                cJSON_AddItemToArray(array_item.get(), cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            }

            // Test cJSON_GetArraySize. Added to cover cJSON_GetArraySize with a valid array.
            cJSON_GetArraySize(array_item.get()); 
            // Added to cover cJSON_GetArraySize with NULL array.
            cJSON_GetArraySize(NULL); 

            // Test cJSON_GetArrayItem. Added to cover cJSON_GetArrayItem with valid/invalid indices.
            int index = fdp.ConsumeIntegralInRange<int>(-5, static_cast<int>(num_elements + 5));
            // FIX: cJSON_GetArrayItem returns a non-owning pointer. Do not wrap in unique_ptr.
            cJSON* retrieved_item = cJSON_GetArrayItem(array_item.get(), index); 
            // FIX: cJSON_GetArrayItem returns a non-owning pointer. Do not wrap in unique_ptr.
            cJSON* retrieved_item_null_array = cJSON_GetArrayItem(NULL, index); 
        } else {
            // If array_item creation failed, still test with NULL.
            cJSON_GetArraySize(NULL);
            cJSON_GetArrayItem(NULL, fdp.ConsumeIntegral<int>());
        }
    }

    // 9. Fuzzing object item existence check (0% coverage)
    {
        std::unique_ptr<cJSON, CJSONDeleter> object_item(cJSON_CreateObject());
        std::string key = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
        std::string non_existent_key = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));

        if (object_item) {
            cJSON_AddStringToObject(object_item.get(), key.c_str(), "value");
            // Added to cover cJSON_HasObjectItem with existing key.
            cJSON_HasObjectItem(object_item.get(), key.c_str()); 
            // Added to cover cJSON_HasObjectItem with non-existing key.
            cJSON_HasObjectItem(object_item.get(), non_existent_key.c_str()); 
        }
        // Added to cover cJSON_HasObjectItem with NULL object.
        cJSON_HasObjectItem(NULL, key.c_str()); 
    }

    // 10. Fuzzing cJSON_Add*ToObject (0% coverage for many)
    {
        std::unique_ptr<cJSON, CJSONDeleter> root_object(cJSON_CreateObject());
        std::string key_bool = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
        std::string key_string = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
        std::string key_raw = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
        std::string key_object = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
        std::string key_array = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
        
        cJSON_bool bool_val = fdp.ConsumeBool();
        std::string string_val = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 100));
        std::string raw_val = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 100));

        // Test with valid object
        if (root_object) {
            // Added to cover cJSON_AddTrueToObject.
            cJSON_AddTrueToObject(root_object.get(), key_bool.c_str()); 
            // Added to cover cJSON_AddFalseToObject.
            cJSON_AddFalseToObject(root_object.get(), key_bool.c_str()); 
            // Added to cover cJSON_AddBoolToObject.
            cJSON_AddBoolToObject(root_object.get(), key_bool.c_str(), bool_val); 
            // Added to cover cJSON_AddStringToObject.
            cJSON_AddStringToObject(root_object.get(), key_string.c_str(), string_val.c_str()); 
            // Added to cover cJSON_AddRawToObject.
            cJSON_AddRawToObject(root_object.get(), key_raw.c_str(), raw_val.c_str()); 
            // Added to cover cJSON_AddObjectToObject.
            cJSON_AddObjectToObject(root_object.get(), key_object.c_str()); 
            // Added to cover cJSON_AddArrayToObject.
            cJSON_AddArrayToObject(root_object.get(), key_array.c_str()); 
        }

        // Test with NULL object to hit error paths. Added to cover NULL object path for respective functions.
        cJSON_AddTrueToObject(NULL, key_bool.c_str()); 
        cJSON_AddFalseToObject(NULL, key_bool.c_str()); 
        cJSON_AddBoolToObject(NULL, key_bool.c_str(), bool_val); 
        cJSON_AddStringToObject(NULL, key_string.c_str(), string_val.c_str()); 
        cJSON_AddRawToObject(NULL, key_raw.c_str(), raw_val.c_str()); 
        cJSON_AddObjectToObject(NULL, key_object.c_str()); 
        cJSON_AddArrayToObject(NULL, key_array.c_str()); 
    }

    // 11. Fuzzing cJSON_CreateBool (0% coverage)
    {
        // Added to cover cJSON_CreateBool(true).
        std::unique_ptr<cJSON, CJSONDeleter> true_item(cJSON_CreateBool(cJSON_True)); 
        // Added to cover cJSON_CreateBool(false).
        std::unique_ptr<cJSON, CJSONDeleter> false_item(cJSON_CreateBool(cJSON_False)); 
    }

    // 12. Fuzzing cJSON_Is* functions (0% coverage for many)
    {
        // Create various types of cJSON objects
        std::unique_ptr<cJSON, CJSONDeleter> null_item(cJSON_CreateNull());
        std::unique_ptr<cJSON, CJSONDeleter> true_item(cJSON_CreateTrue());
        std::unique_ptr<cJSON, CJSONDeleter> false_item(cJSON_CreateFalse());
        std::unique_ptr<cJSON, CJSONDeleter> number_item(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str()));
        std::unique_ptr<cJSON, CJSONDeleter> array_item(cJSON_CreateArray());
        std::unique_ptr<cJSON, CJSONDeleter> object_item(cJSON_CreateObject());
        std::unique_ptr<cJSON, CJSONDeleter> raw_item(cJSON_CreateRaw(fdp.ConsumeRandomLengthString(100).c_str()));
        
        // Test cJSON_IsInvalid. Added to cover cJSON_IsInvalid with various types and NULL.
        cJSON_IsInvalid(null_item.get()); 
        cJSON_IsInvalid(true_item.get());
        cJSON_IsInvalid(false_item.get());
        cJSON_IsInvalid(number_item.get());
        cJSON_IsInvalid(string_item.get());
        cJSON_IsInvalid(array_item.get());
        cJSON_IsInvalid(object_item.get());
        cJSON_IsInvalid(raw_item.get());
        cJSON_IsInvalid(NULL); 

        // Test cJSON_IsFalse. Added to cover cJSON_IsFalse with various types and NULL.
        cJSON_IsFalse(null_item.get()); 
        cJSON_IsFalse(true_item.get());
        cJSON_IsFalse(false_item.get());
        cJSON_IsFalse(NULL); 

        // Test cJSON_IsTrue. Added to cover cJSON_IsTrue with various types and NULL.
        cJSON_IsTrue(null_item.get()); 
        cJSON_IsTrue(true_item.get());
        cJSON_IsTrue(false_item.get());
        cJSON_IsTrue(NULL); 

        // Test cJSON_IsBool. Added to cover cJSON_IsBool with various types and NULL.
        cJSON_IsBool(null_item.get()); 
        cJSON_IsBool(true_item.get());
        cJSON_IsBool(false_item.get());
        cJSON_IsBool(NULL); 

        // Test cJSON_IsNull. Added to cover cJSON_IsNull with various types and NULL.
        cJSON_IsNull(null_item.get()); 
        cJSON_IsNull(true_item.get());
        cJSON_IsNull(false_item.get());
        cJSON_IsNull(NULL); 

        // Test cJSON_IsRaw. Added to cover cJSON_IsRaw with various types and NULL.
        cJSON_IsRaw(null_item.get()); 
        cJSON_IsRaw(true_item.get());
        cJSON_IsRaw(false_item.get());
        cJSON_IsRaw(raw_item.get());
        cJSON_IsRaw(NULL); 
    }

    // 13. Fuzzing cJSON_GetStringValue and cJSON_GetNumberValue (0% coverage)
    {
        std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str()));
        std::unique_ptr<cJSON, CJSONDeleter> number_item(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        std::unique_ptr<cJSON, CJSONDeleter> object_item(cJSON_CreateObject()); // Non-string/number type

        // Added to cover cJSON_GetStringValue with a string, non-string, and NULL.
        cJSON_GetStringValue(string_item.get()); 
        cJSON_GetStringValue(number_item.get()); 
        cJSON_GetStringValue(NULL); 

        // Added to cover cJSON_GetNumberValue with a number, non-number, and NULL.
        cJSON_GetNumberValue(number_item.get()); 
        cJSON_GetNumberValue(string_item.get()); 
        cJSON_GetNumberValue(NULL); 
    }

    // 14. Fuzzing cJSON_AddItemReferenceToArray and cJSON_AddItemReferenceToObject (0% coverage)
    {
        std::unique_ptr<cJSON, CJSONDeleter> array_root(cJSON_CreateArray());
        std::unique_ptr<cJSON, CJSONDeleter> object_root(cJSON_CreateObject());
        
        // Create an item to reference for the array test.
        std::unique_ptr<cJSON, CJSONDeleter> item_to_reference_array(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        
        if (array_root && item_to_reference_array) {
            // cJSON_AddItemReferenceToArray does NOT take ownership.
            // So, item_to_reference_array unique_ptr should retain ownership and delete it.
            cJSON_AddItemReferenceToArray(array_root.get(), item_to_reference_array.get());
        }
        // Test with NULL array_root
        cJSON_AddItemReferenceToArray(NULL, item_to_reference_array.get());
        // Test with NULL item_to_reference
        cJSON_AddItemReferenceToArray(array_root.get(), NULL);

        // Create a separate item to reference for the object test.
        std::unique_ptr<cJSON, CJSONDeleter> item_to_reference_object(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        std::string key = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));

        if (object_root && item_to_reference_object) {
            // cJSON_AddItemReferenceToObject does NOT take ownership.
            // So, item_to_reference_object unique_ptr should retain ownership and delete it.
            cJSON_AddItemReferenceToObject(object_root.get(), key.c_str(), item_to_reference_object.get());
        }
        // Test with NULL object_root
        cJSON_AddItemReferenceToObject(NULL, "dummy_key", item_to_reference_object.get());
        // Test with NULL item_to_reference
        cJSON_AddItemReferenceToObject(object_root.get(), "dummy_key", NULL);
        // Test with NULL key
        cJSON_AddItemReferenceToObject(object_root.get(), NULL, item_to_reference_object.get());
    }

    return 0;
}