#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON items
struct CJSONDeleter {
    void operator()(cJSON* item) const {
        cJSON_Delete(item);
    }
};

// Custom deleter for strings allocated by cJSON_Print*
struct CJSONFreeDeleter {
    void operator()(char* str) const {
        cJSON_free(str);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a switch to call different APIs based on fuzzer data to ensure diversity.
    const int api_choice = fdp.ConsumeIntegralInRange<int>(0, 4);

    // Create a base JSON item to be used by some functions.
    // Use unique_ptr for automatic memory management.
    std::unique_ptr<cJSON, CJSONDeleter> base_item = nullptr;

    // Vectors to hold string data for keys and array elements to ensure their lifetime
    // extends beyond the loop iteration where they are created.
    std::vector<std::string> object_keys;
    std::vector<std::string> array_strings;


    // Create a base item with varied structure and types if needed by the chosen API.
    if (api_choice == 0 || api_choice == 1 || api_choice == 2 || api_choice == 4) {
         const int base_item_type = fdp.ConsumeIntegralInRange<int>(0, 7);
         switch (base_item_type) {
             case 0: base_item.reset(cJSON_CreateNull()); break;
             case 1: base_item.reset(cJSON_CreateTrue()); break;
             case 2: base_item.reset(cJSON_CreateFalse()); break;
             case 3: base_item.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>())); break;
             case 4: {
                 std::string s = fdp.ConsumeRandomLengthString();
                 base_item.reset(cJSON_CreateString(s.c_str()));
                 break;
             }
             case 5: base_item.reset(cJSON_CreateArray()); break;
             case 6: base_item.reset(cJSON_CreateObject()); break;
             case 7: {
                 std::string r = fdp.ConsumeRandomLengthString();
                 base_item.reset(cJSON_CreateRaw(r.c_str()));
                 break;
             }
         }

         // Populate arrays/objects if created to increase complexity.
         if (base_item && (base_item->type & 0xFF) == cJSON_Array) {
             int num_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
             array_strings.reserve(num_elements); // Reserve space to avoid reallocations
             for (int i = 0; i < num_elements; ++i) {
                 const int element_type = fdp.ConsumeIntegralInRange<int>(0, 3);
                 cJSON* element = nullptr;
                 switch (element_type) {
                     case 0: element = cJSON_CreateNull(); break;
                     case 1: element = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
                     case 2: {
                         array_strings.push_back(fdp.ConsumeRandomLengthString(20));
                         element = cJSON_CreateString(array_strings.back().c_str());
                         break;
                     }
                     case 3: element = cJSON_CreateBool(fdp.ConsumeBool()); break;
                 }
                 if (element) {
                     // cJSON_AddItemToArray takes ownership of the element
                     cJSON_AddItemToArray(base_item.get(), element);
                 }
             }
         } else if (base_item && (base_item->type & 0xFF) == cJSON_Object) {
              int num_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
              object_keys.reserve(num_elements); // Reserve space to avoid reallocations
              array_strings.reserve(num_elements); // Reserve space for string values in objects
              for (int i = 0; i < num_elements; ++i) {
                 object_keys.push_back(fdp.ConsumeRandomLengthString(20));
                 const int element_type = fdp.ConsumeIntegralInRange<int>(0, 3);
                 cJSON* element = nullptr;
                 switch (element_type) {
                     case 0: element = cJSON_CreateNull(); break;
                     case 1: element = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); break;
                     case 2: {
                         array_strings.push_back(fdp.ConsumeRandomLengthString(20));
                         element = cJSON_CreateString(array_strings.back().c_str());
                         break;
                     }
                     case 3: element = cJSON_CreateBool(fdp.ConsumeBool()); break;
                 }
                 if (element) {
                     // Use AddItemToObjectCS to cover case-sensitive version too.
                     // cJSON_AddItemToObjectCS takes ownership of the element.
                     // Pass c_str() from the string stored in object_keys.
                     cJSON_AddItemToObjectCS(base_item.get(), object_keys.back().c_str(), element);
                 }
             }
         }
    }


    switch (api_choice) {
        case 0: {
            // Fuzz cJSON_ParseWithLengthOpts
            std::string json_string = fdp.ConsumeRemainingBytesAsString();
            // Ensure json_string is null-terminated as expected by cJSON functions
            json_string += '\0';
            const char* return_parse_end = nullptr;
            cJSON_bool require_null_terminated = fdp.ConsumeBool();
            // Pass actual length or a smaller length to test partial parsing
            size_t parse_length = fdp.ConsumeBool() ? json_string.length() : fdp.ConsumeIntegralInRange<size_t>(0, json_string.length());

            // Parse the string. The returned item is managed by unique_ptr.
            std::unique_ptr<cJSON, CJSONDeleter> parsed_item(
                cJSON_ParseWithLengthOpts(json_string.c_str(), parse_length, &return_parse_end, require_null_terminated)
            );

            // No explicit deletion needed for parsed_item due to unique_ptr.
            // return_parse_end points into the input string, no memory to free.
            break;
        }
        case 1: {
            // Fuzz cJSON_PrintBuffered
            if (base_item) {
                // Test with negative, zero, small, and larger buffer sizes to trigger different paths in ensure.
                int prebuffer_size = fdp.ConsumeIntegralInRange<int>(-10, 4096);
                cJSON_bool format = fdp.ConsumeBool();
                // The returned string is managed by unique_ptr with CJSONFreeDeleter.
                std::unique_ptr<char, CJSONFreeDeleter> printed_string(
                    cJSON_PrintBuffered(base_item.get(), prebuffer_size, format)
                );
                // printed_string will be automatically freed when it goes out of scope.
            }
            break;
        }
        case 2: {
            // Fuzz cJSON_Duplicate
            if (base_item) {
                cJSON_bool recurse = fdp.ConsumeBool();
                // The duplicated item is managed by unique_ptr.
                std::unique_ptr<cJSON, CJSONDeleter> duplicated_item(
                    cJSON_Duplicate(base_item.get(), recurse)
                );
                // duplicated_item will be automatically freed.
            }
            break;
        }
        case 3: {
            // Fuzz cJSON_CreateStringArray
            int count = fdp.ConsumeIntegralInRange<int>(0, 20);
            std::vector<std::string> strings_vec; // Manages string data
            strings_vec.reserve(count); // Reserve space to avoid reallocations

            // Option to include NULL strings in the array
            bool include_null = fdp.ConsumeBool();

            // Populate the vector of strings.
            for (int i = 0; i < count; ++i) {
                if (include_null && fdp.ConsumeBool()) {
                    strings_vec.push_back(""); // Placeholder for potential nullptr
                } else {
                    strings_vec.push_back(fdp.ConsumeRandomLengthString(50));
                }
            }

            // Create the vector of const char* pointers from the stable strings_vec.
            std::vector<const char*> strings_c_ptr;
            strings_c_ptr.reserve(count);
            for (int i = 0; i < count; ++i) {
                 // If include_null is true, the string is empty (our placeholder),
                 // and fuzzer data says so, use nullptr. Otherwise, use the c_str().
                 // Note: The fdp.ConsumeBool() here is to add randomness to whether a null is included
                 // even if include_null is true.
                 if (include_null && strings_vec[i].empty() && fdp.ConsumeBool()) {
                     strings_c_ptr.push_back(nullptr);
                 } else {
                     strings_c_ptr.push_back(strings_vec[i].c_str());
                 }
            }

            // Create the string array. The returned item is managed by unique_ptr.
            std::unique_ptr<cJSON, CJSONDeleter> string_array_item(
                cJSON_CreateStringArray(strings_c_ptr.data(), count)
            );
            // string_array_item will be automatically freed.
            // strings_vec ensures the underlying string data remains valid during the call to cJSON_CreateStringArray.
            break;
        }
        case 4: {
            // Fuzz cJSON_SetValuestring
            // Need a cJSON item that can have a string value. Create a string item.
            std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString("initial"));
            if (string_item) {
                std::string new_value_string = fdp.ConsumeRandomLengthString();
                // Test setting with a new string or with NULL
                const char* value_to_set = fdp.ConsumeBool() ? nullptr : new_value_string.c_str();
                cJSON_SetValuestring(string_item.get(), value_to_set);
            }
            // string_item will be automatically freed.
            break;
        }
    }

    // All allocated cJSON items and printed strings are managed by unique_ptr
    // and will be freed automatically when they go out of scope at the end of the function.
    // object_keys and array_strings vectors also go out of scope here,
    // deallocating the string data they hold.

    return 0;
}