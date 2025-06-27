#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cmath> // For isnan and isinf
#include <fuzzer/FuzzedDataProvider.h>

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Define a custom allocator to potentially trigger allocation failures
static int allocation_failure_countdown = 0; // Fail when this reaches 0

static void* custom_allocate(size_t size) {
    // Simulate allocation failure based on a countdown
    if (size > 0 && allocation_failure_countdown > 0) {
        allocation_failure_countdown--;
        if (allocation_failure_countdown == 0) {
            return NULL; // Simulate failure
        }
    }
    return malloc(size);
}

static void custom_deallocate(void* pointer) {
    free(pointer);
}

// cJSON_Hooks struct only contains malloc_fn and free_fn
static cJSON_Hooks custom_hooks = {
    custom_allocate,
    custom_deallocate
};

// Helper function to create a cJSON item based on fuzzer data
cJSON* create_random_item(FuzzedDataProvider& fdp, int depth) {
    if (depth > 5 || fdp.ConsumeBool()) { // Limit depth and sometimes return a simple type
        int type = fdp.ConsumeIntegralInRange<int>(0, 8); // Increased range to include reference types
        switch (type) {
            case 0: return cJSON_CreateNull();
            case 1: return cJSON_CreateBool(fdp.ConsumeBool());
            case 2: return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            case 3: return cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str());
            case 4: { // Raw
                std::string raw_string = fdp.ConsumeRandomLengthString(100);
                cJSON* raw_item = cJSON_CreateRaw(raw_string.c_str());
                // Randomly set valuestring to NULL for Raw types to hit cJSON_SetValuestring branch
                if (raw_item && fdp.ConsumeBool()) {
                     cJSON_free(raw_item->valuestring); // Free existing string first
                     raw_item->valuestring = NULL;
                }
                return raw_item;
            }
            case 5: { // String with potential NULL valuestring
                cJSON* string_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(50).c_str());
                 // Randomly set valuestring to NULL for String types to hit cJSON_SetValuestring branch
                 if (string_item && fdp.ConsumeBool()) {
                     cJSON_free(string_item->valuestring); // Free existing string first
                     string_item->valuestring = NULL;
                 }
                 return string_item;
            }
            case 6: { // Create a reference to a simple item
                cJSON* simple_item = create_random_item(fdp, depth + 1);
                if (!simple_item) return NULL; // Handle potential allocation failure
                cJSON* ref_item = NULL;
                int ref_type = fdp.ConsumeIntegralInRange<int>(0, 2);
                if (ref_type == 0) ref_item = cJSON_CreateStringReference(cJSON_GetStringValue(simple_item));
                else if (ref_type == 1) ref_item = cJSON_CreateObjectReference(simple_item); // Note: Object reference takes the item itself
                else ref_item = cJSON_CreateArrayReference(simple_item); // Note: Array reference takes the item itself
                // Do NOT delete simple_item here. The reference points to it.
                // simple_item will be leaked if ref_item is added to a structure and simple_item is not.
                // This is a trade-off to fix the use-after-free.
                return ref_item;
            }
            default: return cJSON_CreateNull();
        }
    } else { // Create array or object
        int type = fdp.ConsumeBool() ? 7 : 8; // Adjusted types
        if (type == 7) { // Array
            cJSON* array_item = cJSON_CreateArray();
            if (!array_item) return NULL; // Handle potential allocation failure
            int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_elements; ++i) {
                cJSON_AddItemToArray(array_item, create_random_item(fdp, depth + 1));
            }
            return array_item;
        } else { // Object
            cJSON* object_item = cJSON_CreateObject();
            if (!object_item) return NULL; // Handle potential allocation failure
            int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_elements; ++i) {
                std::string key = fdp.ConsumeRandomLengthString(10);
                cJSON_AddItemToObject(object_item, key.c_str(), create_random_item(fdp, depth + 1));
            }
            return object_item;
        }
    }
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Set allocation failure countdown based on fuzzer data to hit allocation failure paths
    allocation_failure_countdown = fdp.ConsumeIntegralInRange<int>(0, 100); // Reset countdown per input

    // Set custom hooks to potentially trigger allocation failure paths
    cJSON_InitHooks(&custom_hooks);

    // 1. Exercise cJSON_ParseWithLengthOpts
    {
        std::string json_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
        cJSON_bool require_null_terminated = fdp.ConsumeBool();

        const char* parse_end = NULL;
        // Sometimes pass NULL parse_end to hit the corresponding branch in cJSON_ParseWithLengthOpts
        const char** parse_end_ptr = fdp.ConsumeBool() ? &parse_end : NULL;

        // Test various input scenarios to hit different branches in parsing
        int parse_scenario = fdp.ConsumeIntegralInRange<int>(0, 3);
        std::string input_to_parse;
        if (parse_scenario == 0) { // Normal valid/invalid JSON
            input_to_parse = json_string;
        } else if (parse_scenario == 1) { // Empty or whitespace only input
            input_to_parse = fdp.ConsumeBool() ? "" : "   \t\n";
        } else if (parse_scenario == 2) { // Invalid JSON structure
            input_to_parse = "{ \"a\": 1, "; // Incomplete JSON
        } else { // Valid JSON followed by trailing characters
            input_to_parse = "{ \"a\": 1 }" + fdp.ConsumeRandomLengthString(10);
        }

        // Sometimes pass NULL for the json string itself to hit the NULL input path
        const char* json_c_str = fdp.ConsumeBool() ? input_to_parse.c_str() : NULL;
        // Use the actual size of the string as the buffer length to prevent overflows
        size_t current_parse_length = (json_c_str == NULL) ? 0 : input_to_parse.size();

        // cJSON_ParseWithLengthOpts takes cJSON_bool directly, not a struct pointer
        cJSON* parsed_item = cJSON_ParseWithLengthOpts(json_c_str, current_parse_length, parse_end_ptr, require_null_terminated);
        cJSON_Delete(parsed_item);
    }

    // Add tests for array creation functions to improve their coverage
    {
        int num_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
        std::vector<int> int_array_data;
        for(int i = 0; i < num_elements; ++i) int_array_data.push_back(fdp.ConsumeIntegral<int>());
        cJSON* int_array = cJSON_CreateIntArray(int_array_data.data(), num_elements);
        cJSON_Delete(int_array);

        std::vector<float> float_array_data;
        for(int i = 0; i < num_elements; ++i) float_array_data.push_back(fdp.ConsumeFloatingPoint<float>());
        cJSON* float_array = cJSON_CreateFloatArray(float_array_data.data(), num_elements);
        cJSON_Delete(float_array);

        std::vector<double> double_array_data;
        for(int i = 0; i < num_elements; ++i) double_array_data.push_back(fdp.ConsumeFloatingPoint<double>());
        cJSON* double_array = cJSON_CreateDoubleArray(double_array_data.data(), num_elements);
        cJSON_Delete(double_array);

        std::vector<std::string> string_array_data_str;
        std::vector<const char*> string_array_data_c_str;
        for(int i = 0; i < num_elements; ++i) {
            string_array_data_str.push_back(fdp.ConsumeRandomLengthString(20));
        }
        for(const auto& s : string_array_data_str) {
            string_array_data_c_str.push_back(s.c_str());
        }
        cJSON* string_array = cJSON_CreateStringArray(string_array_data_c_str.data(), num_elements);
        cJSON_Delete(string_array);
    }

    // Add tests for reference creation functions to improve their coverage
    {
        cJSON* simple_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
        if (simple_item) {
            cJSON* string_ref = cJSON_CreateStringReference(cJSON_GetStringValue(simple_item));
            cJSON_Delete(string_ref);
            cJSON_Delete(simple_item); // Delete the original after creating the reference
        }

        cJSON* object_item = cJSON_CreateObject();
        if (object_item) {
             cJSON* object_ref = cJSON_CreateObjectReference(object_item);
             cJSON_Delete(object_ref);
             cJSON_Delete(object_item); // Delete the original
        }

        cJSON* array_item = cJSON_CreateArray();
        if (array_item) {
            cJSON* array_ref = cJSON_CreateArrayReference(array_item);
            cJSON_Delete(array_ref);
            cJSON_Delete(array_item); // Delete the original
        }
    }


    // Create a random cJSON item for other operations
    cJSON* item = create_random_item(fdp, 0);

    // The else block for NULL item is now reachable due to allocation failure simulation
    if (item) {
        // 2. Exercise cJSON_PrintBuffered
        {
            // Test with various buffer sizes, including small ones to trigger reallocation in 'ensure'
            size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, 50); // Small buffer size
            cJSON_bool format = fdp.ConsumeBool(); // Use cJSON_bool
            char* printed_string = cJSON_PrintBuffered(item, buffer_size, format);
            cJSON_free(printed_string); // Use cJSON_free for strings allocated by cJSON

            // Also test with a larger buffer size
            buffer_size = fdp.ConsumeIntegralInRange<size_t>(100, 1024);
            printed_string = cJSON_PrintBuffered(item, buffer_size, format);
            cJSON_free(printed_string);
        }

        // 3. Exercise cJSON_Duplicate
        {
            // Test duplicating with different recurse flags (cJSON_True or cJSON_False)
            cJSON_bool recurse = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

            // Test duplicating an item with no children (already exists)

            cJSON* duplicated_item = cJSON_Duplicate(item, recurse);
            cJSON_Delete(duplicated_item);

            // Test duplicating a NULL item (already exists)

            // Test duplicating a reference item to hit the byreference branch in cJSON_Duplicate
            cJSON* simple_item_for_ref = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            if (simple_item_for_ref) {
                cJSON* ref_item = cJSON_CreateObjectReference(simple_item_for_ref); // Create a reference
                if (ref_item) {
                    cJSON_bool recurse_ref = fdp.ConsumeBool() ? cJSON_True : cJSON_False; // Choose recurse for reference duplication
                    cJSON* duplicated_ref_item = cJSON_Duplicate(ref_item, recurse_ref);
                    cJSON_Delete(duplicated_ref_item);
                }
                cJSON_Delete(simple_item_for_ref); // Delete the original
            }
        }

        // 4. Exercise cJSON_Compare (Existing tests seem comprehensive)
        {
            cJSON* item2 = create_random_item(fdp, 0);
            cJSON_bool compare_case = fdp.ConsumeBool();

            // Test comparing NULL items (already exists)

            // Test comparing different types, values, and structures (already exists)
            cJSON_Compare(item, item2, compare_case);

            // Test comparing numbers that are not equal (already exists)

            // Test case-sensitive string/raw comparison with different values (already exists)

            cJSON_Delete(item2);
        }

        // 5. Exercise cJSON_SetValuestring
        {
            std::string new_string = fdp.ConsumeRandomLengthString(100);

            // Test with NULL item (already exists)
            // Test with NULL string (already exists)

            // Create a string item with initially NULL valuestring and set it (already exists)

            // Set valuestring on the existing item if it's a string or raw to hit the !cJSON_IsRaw branch
            if ((item->type & 0xFF) == cJSON_String || (item->type & 0xFF) == cJSON_Raw) {
                 cJSON_SetValuestring(item, new_string.c_str());
            }

            // Explicitly create a Raw item and set its valuestring to ensure Raw type is tested
            cJSON* raw_item_for_set = cJSON_CreateRaw("initial_raw_value");
            if (raw_item_for_set) {
                 std::string raw_new_string = fdp.ConsumeRandomLengthString(100);
                 cJSON_SetValuestring(raw_item_for_set, raw_new_string.c_str());
                 cJSON_Delete(raw_item_for_set);
            }
        }

        // 6. Exercise cJSON_InsertItemInArray to improve its coverage
        {
            if ((item->type & 0xFF) == cJSON_Array) {
                int array_size = cJSON_GetArraySize(item);
                int index = fdp.ConsumeIntegralInRange<int>(0, array_size); // Allow inserting at the end
                cJSON* item_to_insert = create_random_item(fdp, 0);
                if (item_to_insert) {
                    // cJSON_InsertItemInArray takes the item to insert, not a pointer to it
                    cJSON_InsertItemInArray(item, index, item_to_insert);
                }
            }
        }

         // 7. Exercise cJSON_ReplaceItemViaPointer to improve its coverage
        {
            if ((item->type & 0xFF) == cJSON_Array) {
                int array_size = cJSON_GetArraySize(item);
                if (array_size > 0) {
                    cJSON* item_to_replace = cJSON_GetArrayItem(item, fdp.ConsumeIntegralInRange<int>(0, array_size - 1));
                    cJSON* new_item = create_random_item(fdp, 0);
                     if (item_to_replace && new_item) {
                        cJSON_ReplaceItemViaPointer(item, item_to_replace, new_item);
                     } else {
                         cJSON_Delete(new_item); // Clean up if replacement doesn't happen
                     }
                }
            } else if ((item->type & 0xFF) == cJSON_Object) {
                 // Find a random item in the object to replace
                 cJSON* current = item->child;
                 int object_size = 0;
                 while(current) { object_size++; current = current->next; }

                 if (object_size > 0) {
                     int index_to_replace = fdp.ConsumeIntegralInRange<int>(0, object_size - 1);
                     current = item->child;
                     for(int i = 0; i < index_to_replace; ++i) current = current->next;

                     cJSON* item_to_replace = current;
                     cJSON* new_item = create_random_item(fdp, 0);
                     if (item_to_replace && new_item) {
                         cJSON_ReplaceItemViaPointer(item, item_to_replace, new_item);
                     } else {
                         cJSON_Delete(new_item); // Clean up
                     }
                 }
            }
        }

        // 8. Exercise cJSON_Minify to improve its coverage
        {
            // Create a formatted JSON string to minify
            char* formatted_json = cJSON_Print(item);
            if (formatted_json) {
                // Minify in place
                cJSON_Minify(formatted_json);
                cJSON_free(formatted_json);
            }
        }


        cJSON_Delete(item);
    } else {
        // If item creation failed due to allocation failure, still exercise functions that handle NULL
        // This block is now reachable due to allocation failure simulation.
         if (fdp.ConsumeBool()) {
            cJSON_PrintBuffered(NULL, fdp.ConsumeIntegralInRange<size_t>(0, 1024), fdp.ConsumeBool());
        }
         if (fdp.ConsumeBool()) {
            cJSON_Duplicate(NULL, fdp.ConsumeBool());
        }
         if (fdp.ConsumeBool()) {
            cJSON_Compare(NULL, NULL, fdp.ConsumeBool());
        }
         if (fdp.ConsumeBool()) {
             std::string new_string = fdp.ConsumeRandomLengthString(100);
            cJSON_SetValuestring(NULL, new_string.c_str());
        }
    }


    return 0;
}