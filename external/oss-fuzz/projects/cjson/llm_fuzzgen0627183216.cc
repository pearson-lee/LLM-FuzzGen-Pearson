#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min

#include <fuzzer/FuzzedDataProvider.h>

// All Headers: /src/cjson/cJSON.h
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON objects to ensure proper memory deallocation.
// This is crucial for memory safety and preventing leaks.
struct CJSONDeleter {
    void operator()(cJSON* obj) const {
        if (obj) {
            cJSON_Delete(obj);
        }
    }
};

// Custom deleter for char* allocated by cJSON_PrintBuffered,
// which uses cJSON_free for deallocation.
struct CJSONFreeDeleter {
    void operator()(char* ptr) const {
        if (ptr) {
            cJSON_free(ptr);
        }
    }
};

/**
 * @brief Helper function to create a random cJSON item for fuzzing.
 * This function recursively generates diverse JSON structures (null, boolean, number, string, array, object).
 * It uses FuzzedDataProvider to determine the type and content of the JSON elements.
 *
 * @param fdp FuzzedDataProvider instance for generating fuzzed input.
 * @param depth Current recursion depth to prevent excessive nesting and stack overflow.
 * @return A unique_ptr managing the created cJSON object, ensuring it's automatically deleted.
 */
std::unique_ptr<cJSON, CJSONDeleter> create_random_item(FuzzedDataProvider& fdp, int depth) {
    // Base case for recursion: stop creating nested items if depth limit is reached.
    if (depth <= 0) {
        return nullptr;
    }

    // Use FuzzedDataProvider to randomly select the type of cJSON item to create.
    switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
        case 0: // Create a cJSON_Null item
            return std::unique_ptr<cJSON, CJSONDeleter>(cJSON_CreateNull());
        case 1: // Create a cJSON_True item
            return std::unique_ptr<cJSON, CJSONDeleter>(cJSON_CreateTrue());
        case 2: // Create a cJSON_False item
            return std::unique_ptr<cJSON, CJSONDeleter>(cJSON_CreateFalse());
        case 3: // Create a cJSON_Number item
            return std::unique_ptr<cJSON, CJSONDeleter>(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        case 4: { // Create a cJSON_String item
            // Consume a random length string for the value.
            std::string random_string = fdp.ConsumeRandomLengthString(100);
            return std::unique_ptr<cJSON, CJSONDeleter>(cJSON_CreateString(random_string.c_str()));
        }
        case 5: { // Create a cJSON_Array or cJSON_Object (recursive case)
            if (fdp.ConsumeBool()) { // Randomly choose between Array and Object
                // Create a cJSON_Array
                std::unique_ptr<cJSON, CJSONDeleter> array(cJSON_CreateArray());
                if (array) {
                    // Add a random number of child elements to the array
                    int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                    for (int i = 0; i < num_elements; ++i) {
                        // Recursively create child items with reduced depth
                        std::unique_ptr<cJSON, CJSONDeleter> child = create_random_item(fdp, depth - 1);
                        if (child) {
                            // Add the child to the array and release ownership from unique_ptr
                            // as cJSON_AddItemToArray takes ownership.
                            cJSON_AddItemToArray(array.get(), child.release());
                        }
                    }
                }
                return array;
            } else {
                // Create a cJSON_Object
                std::unique_ptr<cJSON, CJSONDeleter> object(cJSON_CreateObject());
                if (object) {
                    // Add a random number of key-value pairs to the object
                    int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
                    for (int i = 0; i < num_elements; ++i) {
                        // Consume a random string for the key
                        std::string key = fdp.ConsumeRandomLengthString(20);
                        // Recursively create child items with reduced depth
                        std::unique_ptr<cJSON, CJSONDeleter> child = create_random_item(fdp, depth - 1);
                        if (child) {
                            // Add the child to the object and release ownership from unique_ptr
                            // as cJSON_AddItemToObject takes ownership.
                            cJSON_AddItemToObject(object.get(), key.c_str(), child.release());
                        }
                    }
                }
                return object;
            }
        }
        default:
            return nullptr; // Should not be reached
    }
}

// Entry point for the fuzzer. This function is called repeatedly with new fuzzed input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Fuzz cJSON_Minify
    // This function modifies the input string in-place.
    {
        // Consume a random length string from the fuzzer data.
        std::string json_str = fdp.ConsumeRandomLengthString(1024);
        // Create a mutable buffer (std::vector<char>) from the string for in-place modification.
        std::vector<char> json_buffer(json_str.begin(), json_str.end());
        json_buffer.push_back('\0'); // Ensure null-termination for C-style string functions.

        // Call cJSON_Minify with the fuzzed string.
        cJSON_Minify(json_buffer.data());

        // To cover the 'json == NULL' branch in cJSON_Minify,
        // we explicitly call it with a nullptr based on fuzzed boolean.
        if (fdp.ConsumeBool()) {
            cJSON_Minify(nullptr);
        }
    }

    // 2. Fuzz cJSON_CreateTrue and cJSON_CreateFalse
    // These functions are fundamental for creating boolean JSON values.
    {
        // Create a cJSON_True item. The unique_ptr ensures automatic deletion.
        std::unique_ptr<cJSON, CJSONDeleter> true_item(cJSON_CreateTrue());
        // Create a cJSON_False item. The unique_ptr ensures automatic deletion.
        std::unique_ptr<cJSON, CJSONDeleter> false_item(cJSON_CreateFalse());
    }

    // 3. Fuzz cJSON_PrintBuffered
    // This function prints a cJSON object into a dynamically allocated buffer.
    {
        // Create a random cJSON object using the helper function.
        // The depth is fuzzed to create varying levels of nesting.
        std::unique_ptr<cJSON, CJSONDeleter> root_item = create_random_item(fdp, fdp.ConsumeIntegralInRange<int>(1, 5));
        if (root_item) {
            // Consume a random buffer size for cJSON_PrintBuffered.
            size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096);
            // Consume a boolean to determine if the output should be formatted.
            cJSON_bool format = fdp.ConsumeBool() ? cJSON_True : cJSON_False;
            
            // Call cJSON_PrintBuffered. It returns a newly allocated char*
            // which is managed by std::unique_ptr with CJSONFreeDeleter for memory safety.
            std::unique_ptr<char, CJSONFreeDeleter> printed_json(cJSON_PrintBuffered(root_item.get(), buffer_size, format));
        }
    }

    // 4. Fuzz cJSON_ParseWithLengthOpts
    // This function parses a JSON string with additional options.
    {
        // Consume the remaining fuzzer data as a string to be parsed as JSON.
        std::string json_input = fdp.ConsumeRemainingBytesAsString();
        if (!json_input.empty()) {
            const char *json_start = json_input.c_str();
            const char *return_parse_end = nullptr; // Output parameter for parse end pointer.
            // Consume a boolean to determine if the input string must be null-terminated.
            cJSON_bool require_null_terminated = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

            // Call cJSON_ParseWithLengthOpts. It returns a cJSON* object
            // which is managed by std::unique_ptr with CJSONDeleter for memory safety.
            std::unique_ptr<cJSON, CJSONDeleter> parsed_item(
                cJSON_ParseWithLengthOpts(json_start, json_input.length(), &return_parse_end, require_null_terminated));
        }
    }

    return 0; // Fuzzer always returns 0 on successful execution.
}