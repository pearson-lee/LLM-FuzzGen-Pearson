#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON objects using std::unique_ptr to ensure cJSON_Delete is called.
struct CJSONDeleter {
    void operator()(cJSON* item) const {
        if (item) {
            cJSON_Delete(item);
        }
    }
};

// Custom deleter for memory allocated by cJSON_malloc or cJSON_Print* using std::unique_ptr
// to ensure cJSON_free is called.
struct CJSONMallocDeleter {
    void operator()(void* ptr) const {
        if (ptr) {
            cJSON_free(ptr);
        }
    }
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a switch based on fuzzer input to select which API to test in this iteration.
    // This approach ensures that over the course of a fuzzing campaign, all selected
    // APIs receive input and their code paths are explored.
    const uint8_t api_selector = fdp.ConsumeIntegral<uint8_t>();

    switch (api_selector % 5) { // Select one of the 5 target APIs
        case 0: {
            // 1. Test cJSON_malloc and cJSON_free
            // This specifically targets the cJSON_malloc function which had 0% coverage
            // in the provided report, ensuring its execution path is tested.
            size_t alloc_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024 * 1024); // Fuzz allocation size up to 1MB
            // Allocate memory using cJSON_malloc. std::unique_ptr with CJSONMallocDeleter
            // automatically calls cJSON_free when the unique_ptr goes out of scope,
            // ensuring memory safety.
            std::unique_ptr<void, CJSONMallocDeleter> allocated_mem(cJSON_malloc(alloc_size));
            // Memory is automatically freed when allocated_mem is destroyed.
            break;
        }
        case 1: {
            // 2. Test cJSON_PrintBuffered
            // This function had lower coverage (66.67% line) and interacts with internal
            // buffer management logic (like 'ensure'), which also had low coverage.
            // Fuzzing buffer size helps trigger reallocation paths within 'ensure'.
            // Create a cJSON object to print. Parsing fuzzer input provides diverse JSON structures.
            std::string json_string = fdp.ConsumeRandomLengthString(1024);
            // Use std::unique_ptr with CJSONDeleter for automatic memory management of the parsed item.
            std::unique_ptr<cJSON, CJSONDeleter> json_item(cJSON_Parse(json_string.c_str()));

            if (json_item) {
                // cJSON_PrintBuffered takes a minimum buffer size (int prebuffer) and returns a new string.
                // It does NOT write into a provided buffer.
                int prebuffer_size = fdp.ConsumeIntegralInRange<int>(0, 4096); // Fuzz minimum buffer size
                // Use 1 for true, 0 for false for cJSON_bool based on header definitions
                cJSON_bool format = fdp.ConsumeBool() ? 1 : 0; // Fuzz format option (formatted/unformatted)

                // Call cJSON_PrintBuffered. It returns a newly allocated string.
                // Use std::unique_ptr with CJSONMallocDeleter to free the returned string.
                std::unique_ptr<char, CJSONMallocDeleter> printed_string(
                    cJSON_PrintBuffered(json_item.get(), prebuffer_size, format)
                );
                // printed_string is automatically freed by unique_ptr.
            }
            // json_item is automatically freed by unique_ptr.
            break;
        }
        case 2: {
            // 3. Test cJSON_Duplicate
            // This function tests the object copying logic (78.57% line coverage),
            // which can be complex for nested arrays and objects.
            // Create a cJSON object to duplicate. Parsing fuzzer input provides diverse structures.
            std::string json_string = fdp.ConsumeRandomLengthString(1024);
            // Use std::unique_ptr for the original item.
            std::unique_ptr<cJSON, CJSONDeleter> original_item(cJSON_Parse(json_string.c_str()));

            if (original_item) {
                // Use 1 for true, 0 for false for cJSON_bool based on header definitions
                cJSON_bool recurse = fdp.ConsumeBool() ? 1 : 0; // Fuzz recurse option (deep vs shallow copy)
                // Duplicate the item. std::unique_ptr ensures the duplicated item is freed.
                std::unique_ptr<cJSON, CJSONDeleter> duplicated_item(cJSON_Duplicate(original_item.get(), recurse));
                // original_item is automatically freed by unique_ptr.
            }
            break;
        }
        case 3: {
            // 4. Test cJSON_CreateIntArray
            // This function creates a JSON array from a C integer array (87.88% line coverage),
            // testing array creation paths and handling different integer values.
            size_t array_size = fdp.ConsumeIntegralInRange<size_t>(0, 100); // Fuzz array size
            std::vector<int> int_array;
            int_array.reserve(array_size);
            for (size_t i = 0; i < array_size; ++i) {
                int_array.push_back(fdp.ConsumeIntegral<int>()); // Fuzz array elements
            }

            // Call cJSON_CreateIntArray. std::unique_ptr ensures the created array is freed.
            std::unique_ptr<cJSON, CJSONDeleter> json_array(cJSON_CreateIntArray(int_array.data(), int_array.size()));
            // json_array is automatically freed by unique_ptr. int_array is freed by std::vector.
            break;
        }
        case 4: {
            // 5. Test cJSON_ParseWithLengthOpts
            // This is a critical parsing function (95.08% line coverage) that allows
            // testing specific options like length and null termination requirement.
            std::string json_string = fdp.ConsumeRandomLengthString(1024);
            size_t json_length = json_string.length(); // Use actual length

            // Fuzz options for parsing
            // Use 1 for true, 0 for false for cJSON_bool based on header definitions
            cJSON_bool require_null_terminated = fdp.ConsumeBool() ? 1 : 0;
            // The cJSON_ParseWithLengthOpts function in this version does not support skipping comments.
            // Removed the skip_comments variable and argument.

            const char* parse_end = NULL; // Pointer to store parse end location

            // Call cJSON_ParseWithLengthOpts. std::unique_ptr ensures the parsed item is freed if successful.
            // Corrected argument order and removed the non-existent skip_comments argument.
            std::unique_ptr<cJSON, CJSONDeleter> parsed_item(
                cJSON_ParseWithLengthOpts(
                    json_string.c_str(),
                    json_length,
                    &parse_end, // 3rd argument: return_parse_end
                    require_null_terminated // 4th argument: require_null_terminated
                )
            );
            // parsed_item is automatically freed by unique_ptr (if not NULL).
            // parse_end is a pointer into the input string, no memory to free.
            break;
        }
    }

    return 0;
}