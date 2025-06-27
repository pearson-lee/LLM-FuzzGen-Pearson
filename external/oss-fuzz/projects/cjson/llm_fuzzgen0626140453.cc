#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cmath> // For isnan and isinf
#include <fuzzer/FuzzedDataProvider.h>

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Define a custom allocator to potentially trigger allocation failures
static void* custom_allocate(size_t size) {
    // Simple allocation, could add logic here to sometimes return NULL
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
        int type = fdp.ConsumeIntegralInRange<int>(0, 6);
        switch (type) {
            case 0: return cJSON_CreateNull();
            case 1: return cJSON_CreateBool(fdp.ConsumeBool());
            case 2: return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            case 3: return cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str());
            case 4: { // Raw
                std::string raw_string = fdp.ConsumeRandomLengthString(100);
                // Intentionally sometimes create raw with NULL valuestring to hit uncovered branch
                cJSON* raw_item = cJSON_CreateRaw(raw_string.c_str());
                // Note: Directly setting valuestring to NULL is a low-level manipulation
                // and requires careful handling to avoid leaks if the original string was allocated.
                // cJSON_CreateRaw allocates the string, so freeing it here is necessary before setting NULL.
                if (raw_item && fdp.ConsumeBool()) { // Randomly set valuestring to NULL
                     cJSON_free(raw_item->valuestring);
                     raw_item->valuestring = NULL;
                }
                return raw_item;
            }
            case 5: { // Create a string item and potentially set its valuestring to NULL initially
                cJSON* string_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(50).c_str());
                 // Note: Directly setting valuestring to NULL is a low-level manipulation
                 // and requires careful handling to avoid leaks if the original string was allocated.
                 // cJSON_CreateString allocates the string, so freeing it here is necessary before setting NULL.
                 if (string_item && fdp.ConsumeBool()) { // Randomly set valuestring to NULL
                     cJSON_free(string_item->valuestring);
                     string_item->valuestring = NULL;
                 }
                 return string_item;
            }
            default: return cJSON_CreateNull();
        }
    } else { // Create array or object
        int type = fdp.ConsumeBool() ? 6 : 7;
        if (type == 6) { // Array
            cJSON* array_item = cJSON_CreateArray();
            int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_elements; ++i) {
                cJSON_AddItemToArray(array_item, create_random_item(fdp, depth + 1));
            }
            return array_item;
        } else { // Object
            cJSON* object_item = cJSON_CreateObject();
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

    // Set custom hooks to potentially trigger allocation failure paths
    cJSON_InitHooks(&custom_hooks);

    // 1. Exercise cJSON_ParseWithLengthOpts
    {
        std::string json_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
        // Limit parse_length to the actual size of the string to prevent overflow
        size_t parse_length = fdp.ConsumeIntegralInRange<size_t>(0, json_string.size());
        cJSON_bool require_null_terminated = fdp.ConsumeBool();

        const char* parse_end = NULL;

        // Test valid/invalid inputs within the bounds of the string
        cJSON* parsed_item = cJSON_ParseWithLengthOpts(json_string.c_str(), parse_length, &parse_end, require_null_terminated);
        cJSON_Delete(parsed_item);

        // Optionally, add a test with NULL input and length 0, which should be safe
        if (fdp.ConsumeBool()) {
             cJSON_ParseWithLengthOpts(NULL, 0, &parse_end, require_null_terminated);
        }
    }

    // Create a random cJSON item for other operations
    cJSON* item = create_random_item(fdp, 0);

    if (item) {
        // 2. Exercise cJSON_PrintBuffered
        {
            size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
            cJSON_bool format = fdp.ConsumeBool(); // Use cJSON_bool
            char* printed_string = cJSON_PrintBuffered(item, buffer_size, format);
            cJSON_free(printed_string); // Use cJSON_free for strings allocated by cJSON
        }

        // 3. Exercise cJSON_Duplicate
        {
            cJSON_bool copy_mode = fdp.ConsumeBool(); // Use cJSON_bool
            // Test duplicating an item with no children
            if (fdp.ConsumeBool()) {
                cJSON* simple_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
                cJSON* duplicated_simple = cJSON_Duplicate(simple_item, copy_mode);
                cJSON_Delete(simple_item);
                cJSON_Delete(duplicated_simple);
            }

            cJSON* duplicated_item = cJSON_Duplicate(item, copy_mode);
            cJSON_Delete(duplicated_item);

            // Test duplicating a NULL item
            if (fdp.ConsumeBool()) {
                cJSON_Duplicate(NULL, copy_mode);
            }
        }

        // 4. Exercise cJSON_Compare
        {
            cJSON* item2 = create_random_item(fdp, 0);
            cJSON_bool compare_case = fdp.ConsumeBool(); // Use cJSON_bool

            // Test comparing NULL items
            if (fdp.ConsumeBool()) {
                cJSON_Compare(NULL, item2, compare_case);
            }
             if (fdp.ConsumeBool()) {
                cJSON_Compare(item, NULL, compare_case);
            }
             if (fdp.ConsumeBool()) {
                cJSON_Compare(NULL, NULL, compare_case);
            }

            // Test comparing different types, values, and structures
            cJSON_Compare(item, item2, compare_case);

            // Test comparing numbers that are not equal
            if (item && item2 && item->type == cJSON_Number && item2->type == cJSON_Number) {
                 if (fdp.ConsumeBool()) {
                     // Create a new number item with a different value and compare
                     cJSON* unequal_num = cJSON_CreateNumber(item2->valuedouble + 1.0);
                     if (unequal_num) {
                         cJSON_Compare(item, unequal_num, compare_case);
                         cJSON_Delete(unequal_num);
                     }
                 }
            }

            // Test case-sensitive string/raw comparison with different values
            if (item && item2) {
                if ((item->type & 0xFF) == cJSON_String && (item2->type & 0xFF) == cJSON_String) {
                    if (fdp.ConsumeBool()) {
                        // Create a new string item with a different value and compare
                        cJSON* different_string_item = cJSON_CreateString("different_string");
                        if (different_string_item) {
                             cJSON_Compare(item, different_string_item, true); // Case-sensitive
                            cJSON_Delete(different_string_item);
                        }
                    }
                }
                 if ((item->type & 0xFF) == cJSON_Raw && (item2->type & 0xFF) == cJSON_Raw) {
                    if (fdp.ConsumeBool()) {
                        // Create a new raw item with a different value and compare
                        cJSON* different_raw_item = cJSON_CreateRaw("different_raw");
                         if (different_raw_item) {
                            cJSON_Compare(item, different_raw_item, true); // Case-sensitive
                            cJSON_Delete(different_raw_item);
                         }
                    }
                }
            }


            cJSON_Delete(item2);
        }

        // 5. Exercise cJSON_SetValuestring
        {
            std::string new_string = fdp.ConsumeRandomLengthString(100);

            // Test with NULL item
            if (fdp.ConsumeBool()) {
                cJSON_SetValuestring(NULL, new_string.c_str());
            }
            // Test with NULL string
            if (fdp.ConsumeBool()) {
                 cJSON_SetValuestring(item, NULL);
            }

            // Create a string item with initially NULL valuestring and set it
            if (fdp.ConsumeBool()) {
                cJSON* null_string_item = cJSON_CreateString(NULL);
                cJSON_SetValuestring(null_string_item, new_string.c_str());
                cJSON_Delete(null_string_item);
            }

            // Set valuestring on the existing item if it's a string
            if ((item->type & 0xFF) == cJSON_String) {
                 cJSON_SetValuestring(item, new_string.c_str());
            }
        }


        cJSON_Delete(item);
    } else {
        // If item creation failed, still exercise functions that handle NULL
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