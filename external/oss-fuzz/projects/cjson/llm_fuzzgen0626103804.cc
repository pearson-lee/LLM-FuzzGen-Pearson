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

    return 0;
}