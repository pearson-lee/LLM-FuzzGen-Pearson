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

    // --- New variables for previous enhancement iteration ---
    cJSON *parsed_json_len = nullptr;         // For cJSON_ParseWithLength

    // --- New variables for this enhancement iteration ---
    cJSON *created_null_item = nullptr;       // For cJSON_CreateNull
    cJSON *created_true_item = nullptr;       // For cJSON_CreateTrue
    cJSON *created_false_item = nullptr;      // For cJSON_CreateFalse
    cJSON *created_bool_item = nullptr;       // For cJSON_CreateBool
    cJSON *created_object_item = nullptr;     // For cJSON_CreateObject


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

    // --- API: cJSON_ParseWithLength (Previous Enhancement) ---
    std::string json_to_parse_len_str = fdp.ConsumeRandomLengthString(256);
    size_t len_for_parse = fdp.ConsumeIntegralInRange<size_t>(0, json_to_parse_len_str.length());
    if (fdp.ConsumeBool()) { 
        if (!json_to_parse_len_str.empty() || len_for_parse == 0) { 
             parsed_json_len = cJSON_ParseWithLength(json_to_parse_len_str.c_str(), len_for_parse);
        }
    } else { 
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
    
    // --- API: cJSON_AddStringToObject (Previous Enhancement) ---
    std::string string_item_key_for_obj_new = fdp.ConsumeRandomLengthString(32);
    std::string string_val_to_add_to_obj_new = fdp.ConsumeRandomLengthString(64);
    const char* string_val_ptr_for_add = fdp.ConsumeBool() ? string_val_to_add_to_obj_new.c_str() : nullptr; 

    if (root_json && cJSON_IsObject(root_json) && fdp.ConsumeBool()) { 
        /* cJSON* added_str_ptr = */ cJSON_AddStringToObject(root_json, string_item_key_for_obj_new.c_str(), string_val_ptr_for_add);
    } else if (fdp.ConsumeBool()) { 
        cJSON_AddStringToObject(nullptr, string_item_key_for_obj_new.c_str(), string_val_ptr_for_add);
    } else { 
        if (root_json && cJSON_IsObject(root_json)) { 
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

    // --- API: cJSON_DeleteItemFromArray (Previous Enhancement) ---
    if (array_json && cJSON_GetArraySize(array_json) > 0 && fdp.ConsumeBool()) { 
        int current_size_before_delete = cJSON_GetArraySize(array_json); 
        if (current_size_before_delete > 0) { 
            int idx_to_delete = fdp.ConsumeIntegralInRange<int>(0, current_size_before_delete - 1);
            cJSON_DeleteItemFromArray(array_json, idx_to_delete);
        }
    } else if (fdp.ConsumeBool()) { 
        cJSON_DeleteItemFromArray(nullptr, fdp.ConsumeIntegral<int>());
    } else { 
        if (array_json) {
            cJSON_DeleteItemFromArray(array_json, -1); 
            if (cJSON_GetArraySize(array_json) > 0) { 
                 cJSON_DeleteItemFromArray(array_json, cJSON_GetArraySize(array_json) + 5);
            } else { 
                 cJSON_DeleteItemFromArray(array_json, 0);
            }
        }
    }

    // --- API: cJSON_CreateObject (New Enhancement) ---
    // Description: Creates an empty cJSON object.
    // Memory Management: Allocates a cJSON object, stored in created_object_item and freed by SafeCJSONDelete in cleanup.
    //                    If added to array_json, ownership is transferred and created_object_item is set to nullptr.
    // Coverage Rationale: Targets uncovered cJSON_CreateObject and its internal new item allocation.
    created_object_item = cJSON_CreateObject();
    if (array_json && created_object_item && fdp.ConsumeBool()) { // Attempt to use the created object
        if (cJSON_AddItemToArray(array_json, created_object_item)) {
            created_object_item = nullptr; // Ownership transferred to array_json
        }
    }

    // --- APIs: cJSON_CreateNull, cJSON_CreateTrue, cJSON_CreateFalse, cJSON_CreateBool (New Enhancement) ---
    // Description: Creates cJSON items of specific literal types (null, true, false, bool).
    // Memory Management: Allocate cJSON objects, stored in created_..._item variables and freed by SafeCJSONDelete in cleanup.
    //                    If added to array_json, ownership is transferred and the respective pointer is set to nullptr.
    // Coverage Rationale: Targets uncovered cJSON_CreateNull, cJSON_CreateTrue, cJSON_CreateFalse, cJSON_CreateBool
    //                     and their internal new item allocations and type setting. cJSON_CreateBool also tests boolean conditional.
    created_null_item = cJSON_CreateNull();
    created_true_item = cJSON_CreateTrue();
    created_false_item = cJSON_CreateFalse();
    created_bool_item = cJSON_CreateBool(fdp.ConsumeBool()); // Test both true/false for cJSON_CreateBool

    // Attempt to add these created literal items to array_json to ensure they are used and to test array functionality further.
    if (array_json) {
        if (created_null_item && fdp.ConsumeBool()) {
            if (cJSON_AddItemToArray(array_json, created_null_item)) created_null_item = nullptr;
        }
        if (created_true_item && fdp.ConsumeBool()) {
            if (cJSON_AddItemToArray(array_json, created_true_item)) created_true_item = nullptr;
        }
        if (created_false_item && fdp.ConsumeBool()) {
            if (cJSON_AddItemToArray(array_json, created_false_item)) created_false_item = nullptr;
        }
        if (created_bool_item && fdp.ConsumeBool()) {
            if (cJSON_AddItemToArray(array_json, created_bool_item)) created_bool_item = nullptr;
        }
    }
    
    // --- APIs: cJSON_AddNullToObject, cJSON_AddTrueToObject, cJSON_AddFalseToObject, cJSON_AddBoolToObject (New Enhancement) ---
    // Description: Adds literal typed items (null, true, false, bool) to a cJSON object.
    // Input Strategy: Target root_json if it's an object, or a newly created object_item, or nullptr. Use fuzzed keys (or nullptr key).
    // Memory Management: New items are owned by the target object if successfully added. These APIs handle their own internal item creation
    //                    and deletion on failure (e.g. if target object is NULL or key is NULL and causes failure).
    // Coverage Rationale: Targets uncovered cJSON_Add<Type>ToObject functions. This covers their internal calls to cJSON_Create<Type>
    //                     and add_item_to_object, including error handling for NULL object/key or allocation failures.
    cJSON* target_object_for_add_literal = nullptr;
    if (fdp.ConsumeBool() && root_json && cJSON_IsObject(root_json)) {
        target_object_for_add_literal = root_json;
    } else if (fdp.ConsumeBool() && created_object_item && cJSON_IsObject(created_object_item)) {
        // Use the object created earlier if it wasn't added to array_json
        target_object_for_add_literal = created_object_item;
    }
    // If target_object_for_add_literal is still nullptr, it tests adding to a NULL object.

    std::string key_for_add_literal_str = fdp.ConsumeRandomLengthString(32);
    const char* key_ptr_for_add_literal = key_for_add_literal_str.c_str();
    if (fdp.ConsumeBool()) { // 50% chance to test with NULL key
        key_ptr_for_add_literal = nullptr;
    }

    // Randomly call one of these Add<Type>ToObject functions
    uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0,3);
    if (choice == 0) {
        /* cJSON* added_item = */ cJSON_AddNullToObject(target_object_for_add_literal, key_ptr_for_add_literal);
    } else if (choice == 1) {
        /* cJSON* added_item = */ cJSON_AddTrueToObject(target_object_for_add_literal, key_ptr_for_add_literal);
    } else if (choice == 2) {
        /* cJSON* added_item = */ cJSON_AddFalseToObject(target_object_for_add_literal, key_ptr_for_add_literal);
    } else {
        /* cJSON* added_item = */ cJSON_AddBoolToObject(target_object_for_add_literal, key_ptr_for_add_literal, fdp.ConsumeBool());
    }

    // --- APIs: cJSON_IsInvalid, cJSON_IsRaw, cJSON_IsNull, cJSON_IsTrue, cJSON_IsFalse, cJSON_IsBool (New Enhancement) ---
    // Description: Checks the type of a cJSON item.
    // Input Strategy: Call on a selection of existing/newly created items and nullptr to cover various states.
    // Memory Management: No new allocations. These are read-only operations.
    // Coverage Rationale: Targets several uncovered cJSON_Is<Type> functions. Calling with both valid items and nullptr
    //                     ensures coverage of the (item == NULL) branches within these type checking functions.
    cJSON* item_for_type_check_a = root_json ? root_json : (created_object_item ? created_object_item : (created_null_item ? created_null_item : (array_json ? array_json : nullptr)));
    cJSON* item_for_type_check_b = created_bool_item ? created_bool_item : (created_true_item ? created_true_item : (created_false_item ? created_false_item : (number_json_item ? number_json_item : nullptr)));

    // Test on potentially valid items if they exist
    if (item_for_type_check_a) {
        /*volatile cJSON_bool r = */ cJSON_IsInvalid(item_for_type_check_a); cJSON_IsRaw(item_for_type_check_a); cJSON_IsNull(item_for_type_check_a);
        cJSON_IsTrue(item_for_type_check_a); cJSON_IsFalse(item_for_type_check_a); cJSON_IsBool(item_for_type_check_a);
    }
    if (item_for_type_check_b) {
        /*volatile cJSON_bool r = */ cJSON_IsInvalid(item_for_type_check_b); cJSON_IsRaw(item_for_type_check_b); cJSON_IsNull(item_for_type_check_b);
        cJSON_IsTrue(item_for_type_check_b); cJSON_IsFalse(item_for_type_check_b); cJSON_IsBool(item_for_type_check_b);
    }
    // Test with NULL to cover `item == NULL` branches in type check functions
    /*volatile cJSON_bool r_null = */ cJSON_IsInvalid(nullptr); cJSON_IsRaw(nullptr); cJSON_IsNull(nullptr);
    cJSON_IsTrue(nullptr); cJSON_IsFalse(nullptr); cJSON_IsBool(nullptr);


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

    // --- API: cJSON_PrintPreallocated (Previous Enhancement) ---
    cJSON* json_to_print_prealloc = root_json ? root_json : (parsed_json_simple ? parsed_json_simple : (duplicated_json ? duplicated_json : item_to_add));
    if (json_to_print_prealloc) {
        int buffer_size_prealloc = fdp.ConsumeIntegralInRange<int>(1, 2048); 
        std::vector<char> prealloc_vec_buffer(buffer_size_prealloc);
        cJSON_bool format_prealloc = fdp.ConsumeBool();
        
        if (fdp.ConsumeBool()) { 
            /* cJSON_bool success = */ cJSON_PrintPreallocated(json_to_print_prealloc, prealloc_vec_buffer.data(), buffer_size_prealloc, format_prealloc);
        }
        if (fdp.ConsumeBool()) { 
             cJSON_PrintPreallocated(json_to_print_prealloc, prealloc_vec_buffer.data(), -1, format_prealloc);
        }
        if (fdp.ConsumeBool()) { 
             cJSON_PrintPreallocated(json_to_print_prealloc, nullptr, buffer_size_prealloc, format_prealloc);
        }
    } else { 
        std::vector<char> temp_buffer_for_null_item(100); 
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

    // --- API: cJSON_HasObjectItem (Previous Enhancement) ---
    std::string key_for_has_item_check = fdp.ConsumeRandomLengthString(32);
    if (root_json && cJSON_IsObject(root_json) && fdp.ConsumeBool()) { 
        /* cJSON_bool has_item = */ cJSON_HasObjectItem(root_json, key_for_has_item_check.c_str());
    } else if (fdp.ConsumeBool()) { 
        /* cJSON_bool has_item_null_obj = */ cJSON_HasObjectItem(nullptr, key_for_has_item_check.c_str());
    } else { 
         if (root_json && cJSON_IsObject(root_json)) { 
            /* cJSON_bool has_item_null_key = */ cJSON_HasObjectItem(root_json, nullptr);
         } else { 
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

    // Cleanup for previous enhancement iteration's items
    SafeCJSONDelete(parsed_json_len); 

    // Cleanup for this enhancement iteration's items
    SafeCJSONDelete(created_null_item);
    SafeCJSONDelete(created_true_item);
    SafeCJSONDelete(created_false_item);
    SafeCJSONDelete(created_bool_item);
    SafeCJSONDelete(created_object_item);


    return 0; 
}