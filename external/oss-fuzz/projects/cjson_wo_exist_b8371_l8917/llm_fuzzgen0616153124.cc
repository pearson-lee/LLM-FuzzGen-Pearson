#include "/src/cjson/cJSON.h" // Required header for cJSON library functions.
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <vector>  // For creating arrays of data for cJSON array creation functions
#include <cstring> // For strcpy, strlen
#include <cstdlib> // For malloc, free (used for cJSON_Minify example)
#include <new>     // For std::nothrow

// Helper function to safely delete cJSON objects.
// It calls cJSON_Delete and then sets the pointer to nullptr to prevent double frees.
void SafeCJSONDelete(cJSON*& item) {
    if (item) {
        cJSON_Delete(item);
        item = nullptr;
    }
}

// Helper function to safely free memory allocated by cJSON (e.g., by cJSON_PrintBuffered).
// It calls cJSON_free (which uses the library's configured deallocator, defaulting to free)
// and then sets the pointer to nullptr.
void SafeCJSONFree(void*& ptr) {
    if (ptr) {
        cJSON_free(ptr);
        ptr = nullptr;
    }
}

// Entry point for the fuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Initialize cJSON objects that will be used in the fuzz target.
    cJSON *root_json = nullptr;       // For the initially parsed JSON object.
    cJSON *item_to_add = nullptr;     // For a newly created JSON item.
    cJSON *duplicated_json = nullptr; // For a duplicated JSON object.
    char *printed_buffer = nullptr;   // For the string output of printing functions.
    std::string added_item_key;       // To store the key if an item is added to an object.

    // --- New variables from original enhanced target ---
    cJSON *parsed_json_simple = nullptr;      // For cJSON_Parse
    char *printed_unformatted_str = nullptr;  // For cJSON_PrintUnformatted
    char *printed_formatted_str = nullptr;    // For cJSON_Print
    cJSON *number_json_item = nullptr;        // For cJSON_CreateNumber
    cJSON *array_json = nullptr;              // For cJSON_CreateArray and related functions
    char *minifiable_json_string = nullptr;   // For cJSON_Minify
    cJSON *string_to_modify_valuestring = nullptr; // For cJSON_SetValuestring
    cJSON *replacement_obj_item = nullptr;    // For cJSON_ReplaceItemInObject

    // --- New variables for this enhancement iteration ---
    cJSON *parsed_json_len = nullptr;         // For cJSON_ParseWithLength


    // --- API: cJSON_Version (Original New) ---
    /* const char* version_str = */ cJSON_Version(); 

    // --- API 1: cJSON_ParseWithOpts ---
    std::string json_to_parse = fdp.ConsumeRandomLengthString(1024);
    const char *parse_end_ptr = nullptr; 
    cJSON_bool require_null_terminated_parse = fdp.ConsumeBool();
    root_json = cJSON_ParseWithOpts(json_to_parse.c_str(), &parse_end_ptr, require_null_terminated_parse);

    // --- API: cJSON_Parse (Original New) ---
    std::string json_to_parse_simple_str = fdp.ConsumeRandomLengthString(256);
    parsed_json_simple = cJSON_Parse(json_to_parse_simple_str.c_str());

    // --- API: cJSON_ParseWithLength (New Enhancement) ---
    // Description: Parses a JSON string with a specified length.
    // Input Strategy: Consume a string and a length. Also test with NULL string.
    // Memory Management: Allocates a cJSON object, freed by SafeCJSONDelete.
    // Coverage Rationale: Targets uncovered cJSON_ParseWithLength and its internal error checks (e.g. null value).
    std::string json_to_parse_len_str = fdp.ConsumeRandomLengthString(256);
    size_t len_for_parse = fdp.ConsumeIntegralInRange<size_t>(0, json_to_parse_len_str.length());
    if (fdp.ConsumeBool()) { // Normal case
        if (!json_to_parse_len_str.empty() || len_for_parse == 0) { // Ensure c_str() is valid if len > 0 or if string is empty and len is 0.
             parsed_json_len = cJSON_ParseWithLength(json_to_parse_len_str.c_str(), len_for_parse);
        }
    } else { // Test with NULL value string to cover null check branch in underlying parse function
        parsed_json_len = cJSON_ParseWithLength(nullptr, len_for_parse);
    }


    // --- API 2: cJSON_CreateString ---
    std::string string_value_for_item = fdp.ConsumeRandomLengthString(128);
    item_to_add = cJSON_CreateString(string_value_for_item.c_str());

    // --- API: cJSON_CreateNumber (Original New) ---
    double num_value_for_item = fdp.ConsumeFloatingPoint<double>();
    number_json_item = cJSON_CreateNumber(num_value_for_item);

    // --- API 3: cJSON_AddItemToObject ---
    if (root_json && cJSON_IsObject(root_json) && item_to_add) {
        added_item_key = fdp.ConsumeRandomLengthString(32); 
        if (cJSON_AddItemToObject(root_json, added_item_key.c_str(), item_to_add)) {
            item_to_add = nullptr; 
        }
    }

    // --- API: cJSON_AddNumberToObject (Original New) ---
    if (root_json && cJSON_IsObject(root_json)) {
        std::string number_item_key_for_obj = fdp.ConsumeRandomLengthString(32);
        double number_to_add_to_obj_val = fdp.ConsumeFloatingPoint<double>();
        /* cJSON* added_num_ptr = */ cJSON_AddNumberToObject(root_json, number_item_key_for_obj.c_str(), number_to_add_to_obj_val);
    }
    
    // --- API: cJSON_AddStringToObject (New Enhancement) ---
    // Description: Creates a string item and adds it to a cJSON object.
    // Input Strategy: If root_json is an object, add a string with fuzzed key and value.
    //                 Also test with NULL object or NULL name to cover internal branches.
    // Memory Management: The new string item is owned by root_json if successfully added.
    //                  cJSON_AddStringToObject handles its own item creation and deletion on failure.
    // Coverage Rationale: Targets uncovered cJSON_AddStringToObject and its internal error checks (e.g. null object, null name).
    std::string string_item_key_for_obj_new = fdp.ConsumeRandomLengthString(32);
    std::string string_val_to_add_to_obj_new = fdp.ConsumeRandomLengthString(64);
    const char* string_val_ptr_for_add = fdp.ConsumeBool() ? string_val_to_add_to_obj_new.c_str() : nullptr; // Test with NULL string value (cJSON_CreateString handles this)

    if (root_json && cJSON_IsObject(root_json) && fdp.ConsumeBool()) { // Normal case
        /* cJSON* added_str_ptr = */ cJSON_AddStringToObject(root_json, string_item_key_for_obj_new.c_str(), string_val_ptr_for_add);
    } else if (fdp.ConsumeBool()) { // Test with NULL object to cover branch in add_item_to_object
        cJSON_AddStringToObject(nullptr, string_item_key_for_obj_new.c_str(), string_val_ptr_for_add);
    } else { // Test with NULL name to cover branch in add_item_to_object
        if (root_json && cJSON_IsObject(root_json)) { // Ensure object is valid for this specific test
            cJSON_AddStringToObject(root_json, nullptr, string_val_ptr_for_add);
        }
    }
    
    // --- APIs: cJSON_CreateArray, cJSON_AddItemToArray, cJSON_GetArraySize, cJSON_GetArrayItem (Original New) ---
    array_json = cJSON_CreateArray();
    if (array_json) {
        if (number_json_item) { 
            if (cJSON_AddItemToArray(array_json, number_json_item)) {
                number_json_item = nullptr; 
            }
        }
        std::string str_for_array_val_content = fdp.ConsumeRandomLengthString(64);
        cJSON* string_item_for_array_creation = cJSON_CreateString(str_for_array_val_content.c_str());
        if (string_item_for_array_creation) {
            if (cJSON_AddItemToArray(array_json, string_item_for_array_creation)) {
                // string_item_for_array_creation is now owned by array_json
            } else {
                SafeCJSONDelete(string_item_for_array_creation); 
            }
        }
        int current_array_size = cJSON_GetArraySize(array_json);
        if (current_array_size > 0) {
            int random_idx = fdp.ConsumeIntegralInRange<int>(0, current_array_size - 1);
            /* cJSON* fetched_item = */ cJSON_GetArrayItem(array_json, random_idx);
        }
    }

    // --- API: cJSON_DeleteItemFromArray (New Enhancement) ---
    // Description: Deletes an item from a cJSON array by index.
    // Input Strategy: If array_json exists and is not empty, delete an item at a fuzzed index.
    //                 Also test with NULL array or invalid index.
    // Memory Management: The API handles freeing the memory of the deleted cJSON item.
    // Coverage Rationale: Targets uncovered cJSON_DeleteItemFromArray and its internal checks (e.g. null array, invalid index).
    if (array_json && cJSON_GetArraySize(array_json) > 0 && fdp.ConsumeBool()) { // Normal case
        int current_size_before_delete = cJSON_GetArraySize(array_json); // Get size before potential modification
        if (current_size_before_delete > 0) { 
            int idx_to_delete = fdp.ConsumeIntegralInRange<int>(0, current_size_before_delete - 1);
            cJSON_DeleteItemFromArray(array_json, idx_to_delete);
        }
    } else if (fdp.ConsumeBool()) { // Test with NULL array to cover null check in DetachItemFromArray
        cJSON_DeleteItemFromArray(nullptr, fdp.ConsumeIntegral<int>());
    } else { // Test with invalid index on a valid array (if array_json exists)
        if (array_json) {
            cJSON_DeleteItemFromArray(array_json, -1); // Test negative index to cover 'which < 0'
            if (cJSON_GetArraySize(array_json) > 0) { // Test out-of-bounds positive index
                 cJSON_DeleteItemFromArray(array_json, cJSON_GetArraySize(array_json) + 5);
            } else { // Test on empty array (which might be 0 or some other value)
                 cJSON_DeleteItemFromArray(array_json, 0);
            }
        }
    }

    // --- API 4: cJSON_Duplicate ---
    if (root_json) {
        cJSON_bool recurse_duplicate = fdp.ConsumeBool();
        duplicated_json = cJSON_Duplicate(root_json, recurse_duplicate);
    }

    // --- API 5: cJSON_PrintBuffered ---
    cJSON* json_to_print_buffered_ptr = (fdp.ConsumeBool() && duplicated_json) ? duplicated_json : root_json;
    if (json_to_print_buffered_ptr) {
        int prebuffer_size = fdp.ConsumeIntegralInRange<int>(0, 2048); 
        cJSON_bool format_print = fdp.ConsumeBool();
        printed_buffer = cJSON_PrintBuffered(json_to_print_buffered_ptr, prebuffer_size, format_print);
    }

    // --- API: cJSON_PrintPreallocated (New Enhancement) ---
    // Description: Prints a cJSON item to a preallocated buffer.
    // Input Strategy: Use an existing JSON object. Create a buffer of fuzzed size using std::vector. Test error conditions.
    // Memory Management: std::vector manages the buffer memory.
    // Coverage Rationale: Targets uncovered cJSON_PrintPreallocated, including (length < 0) and (buffer == NULL) branches.
    cJSON* json_to_print_prealloc = root_json ? root_json : (parsed_json_simple ? parsed_json_simple : (duplicated_json ? duplicated_json : item_to_add));
    if (json_to_print_prealloc) {
        int buffer_size_prealloc = fdp.ConsumeIntegralInRange<int>(1, 2048); // Ensure buffer_size > 0
        std::vector<char> prealloc_vec_buffer(buffer_size_prealloc);
        cJSON_bool format_prealloc = fdp.ConsumeBool();
        
        if (fdp.ConsumeBool()) { // Test with valid buffer and size
            /* cJSON_bool success = */ cJSON_PrintPreallocated(json_to_print_prealloc, prealloc_vec_buffer.data(), buffer_size_prealloc, format_prealloc);
        }
        if (fdp.ConsumeBool()) { // Test with invalid length to cover (length < 0) branch
             cJSON_PrintPreallocated(json_to_print_prealloc, prealloc_vec_buffer.data(), -1, format_prealloc);
        }
        if (fdp.ConsumeBool()) { // Test with NULL buffer to cover (buffer == NULL) branch
             cJSON_PrintPreallocated(json_to_print_prealloc, nullptr, buffer_size_prealloc, format_prealloc);
        }
    } else { // Test with NULL item to cover item == NULL branch in print_value
        std::vector<char> temp_buffer_for_null_item(100); // Buffer must be valid for this test
        if (!temp_buffer_for_null_item.empty()) {
             cJSON_PrintPreallocated(nullptr, temp_buffer_for_null_item.data(), static_cast<int>(temp_buffer_for_null_item.size()), fdp.ConsumeBool());
        }
    }


    // --- API: cJSON_PrintUnformatted (Original New) ---
    cJSON* json_for_unformatted_print = root_json ? root_json : (duplicated_json ? duplicated_json : parsed_json_simple);
    if (json_for_unformatted_print) {
        printed_unformatted_str = cJSON_PrintUnformatted(json_for_unformatted_print);
    }
    
    // --- API: cJSON_Print (Original New) ---
    cJSON* json_for_formatted_print_ptr = duplicated_json ? duplicated_json : (root_json ? root_json : parsed_json_simple);
    if (json_for_formatted_print_ptr) {
        printed_formatted_str = cJSON_Print(json_for_formatted_print_ptr);
    }

    // --- API: cJSON_Minify (Original New) ---
    if (printed_unformatted_str) { 
        size_t len = strlen(printed_unformatted_str);
        minifiable_json_string = (char*)malloc(len + 1); 
        if (minifiable_json_string) {
            strcpy(minifiable_json_string, printed_unformatted_str);
            cJSON_Minify(minifiable_json_string);
            free(minifiable_json_string); 
            minifiable_json_string = nullptr; 
        }
    } else if (printed_buffer) { 
        size_t len = strlen(printed_buffer);
        minifiable_json_string = (char*)malloc(len + 1);
        if (minifiable_json_string) {
            strcpy(minifiable_json_string, printed_buffer);
            cJSON_Minify(minifiable_json_string);
            free(minifiable_json_string);
            minifiable_json_string = nullptr;
        }
    }
    
    // --- API: cJSON_SetValuestring (Original New) ---
    std::string initial_val_for_setvaluestring = fdp.ConsumeRandomLengthString(32);
    string_to_modify_valuestring = cJSON_CreateString(initial_val_for_setvaluestring.c_str());
    if (string_to_modify_valuestring) {
        std::string new_string_val_for_setvaluestring = fdp.ConsumeRandomLengthString(fdp.ConsumeBool() ? 64 : 16); 
        cJSON_SetValuestring(string_to_modify_valuestring, new_string_val_for_setvaluestring.c_str());
    }
    
    // --- Bonus API: cJSON_DeleteItemFromObject ---
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_to_delete;
        if (!added_item_key.empty() && fdp.ConsumeBool()) { 
            key_to_delete = added_item_key;
        } else {
            key_to_delete = fdp.ConsumeRandomLengthString(32); 
        }
        cJSON_DeleteItemFromObject(root_json, key_to_delete.c_str());
    }

    // --- API: cJSON_ReplaceItemInObject (Original New) ---
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_for_replacement = fdp.ConsumeRandomLengthString(32);
        replacement_obj_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); 
        if (replacement_obj_item) {
            if (cJSON_ReplaceItemInObject(root_json, key_for_replacement.c_str(), replacement_obj_item)) {
                replacement_obj_item = nullptr; 
            }
        }
    }

    // --- API: cJSON_HasObjectItem (New Enhancement) ---
    // Description: Checks if an object has an item with the given key.
    // Input Strategy: If root_json is an object, use a fuzzed key. Also test with NULL object/key.
    // Memory Management: No new allocations.
    // Coverage Rationale: Targets uncovered cJSON_HasObjectItem and its call to cJSON_GetObjectItem (which handles NULL object/key).
    std::string key_for_has_item_check = fdp.ConsumeRandomLengthString(32);
    if (root_json && cJSON_IsObject(root_json) && fdp.ConsumeBool()) { // Normal case
        /* cJSON_bool has_item = */ cJSON_HasObjectItem(root_json, key_for_has_item_check.c_str());
    } else if (fdp.ConsumeBool()) { // Test with NULL object
        /* cJSON_bool has_item_null_obj = */ cJSON_HasObjectItem(nullptr, key_for_has_item_check.c_str());
    } else { // Test with NULL key
         if (root_json && cJSON_IsObject(root_json)) { // Object must be valid for this test
            /* cJSON_bool has_item_null_key = */ cJSON_HasObjectItem(root_json, nullptr);
         } else { // If root_json is not a valid object, test with nullptr for object as well
            /* cJSON_bool has_item_all_null = */ cJSON_HasObjectItem(nullptr, nullptr);
         }
    }


    // --- Bonus API: cJSON_Compare ---
    if (root_json && duplicated_json) {
        cJSON_bool case_sensitive_compare = fdp.ConsumeBool();
        cJSON_Compare(root_json, duplicated_json, case_sensitive_compare);
    }

    // --- Cleanup Phase ---
    SafeCJSONDelete(root_json);
    SafeCJSONDelete(item_to_add); 
    SafeCJSONDelete(duplicated_json);
    SafeCJSONFree(reinterpret_cast<void*&>(printed_buffer));

    // Cleanup for original new items
    SafeCJSONDelete(parsed_json_simple);
    SafeCJSONFree(reinterpret_cast<void*&>(printed_unformatted_str));
    SafeCJSONFree(reinterpret_cast<void*&>(printed_formatted_str));
    SafeCJSONDelete(number_json_item); 
    SafeCJSONDelete(array_json);
    SafeCJSONDelete(string_to_modify_valuestring);
    SafeCJSONDelete(replacement_obj_item); 

    // Cleanup for this enhancement iteration's items
    SafeCJSONDelete(parsed_json_len); // Added for cJSON_ParseWithLength

    return 0; 
}