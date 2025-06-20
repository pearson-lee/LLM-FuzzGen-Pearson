#include "/src/cjson/cJSON.h" // Required header for cJSON library functions.
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <vector>  // For creating arrays of data for cJSON array creation functions
#include <cstring> // For strcpy, strlen
#include <cstdlib> // For malloc, free (used for cJSON_Minify example)
#include <cmath>   // For NAN

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

    // --- New variables for enhanced coverage ---
    cJSON *parsed_json_simple = nullptr;      // For cJSON_Parse
    char *printed_unformatted_str = nullptr;  // For cJSON_PrintUnformatted
    char *printed_formatted_str = nullptr;    // For cJSON_Print
    cJSON *number_json_item = nullptr;        // For cJSON_CreateNumber
    cJSON *array_json = nullptr;              // For cJSON_CreateArray and related functions
    char *minifiable_json_string = nullptr;   // For cJSON_Minify
    cJSON *string_to_modify_valuestring = nullptr; // For cJSON_SetValuestring
    cJSON *replacement_obj_item = nullptr;    // For cJSON_ReplaceItemInObject

    // Variables for newly added coverage targets
    cJSON *null_item = nullptr;
    cJSON *true_item = nullptr;
    cJSON *false_item = nullptr;
    cJSON *bool_item = nullptr;
    cJSON *object_item_created = nullptr;
    cJSON *raw_item_created = nullptr;
    cJSON *string_item_for_get_value = nullptr;
    cJSON *number_item_for_get_value = nullptr;
    cJSON *int_array_item = nullptr;
    cJSON *float_array_item = nullptr;
    cJSON *double_array_item = nullptr;
    cJSON *string_array_item = nullptr;
    cJSON *string_ref_item = nullptr;
    cJSON *object_ref_item = nullptr;
    cJSON *array_ref_item = nullptr;
    char *preallocated_buffer = nullptr;


    // --- API: cJSON_Version (New) ---
    // Description: Gets the cJSON library version string.
    // Input Strategy: No input needed.
    // Memory Management: Returns a pointer to a static string, no free needed by caller.
    // Coverage Rationale: Targets the uncovered cJSON_Version function.
    /* const char* version_str = */ cJSON_Version(); // Call for coverage

    // --- API 1: cJSON_ParseWithOpts ---
    // Description: Parses a JSON string with specified options. This tests the core parsing logic.
    // Input Strategy: Consume a string from the fuzzer data to be parsed as JSON.
    //                 Consume a boolean to decide if the input must be null-terminated.
    // Memory Management: cJSON_ParseWithOpts allocates a new cJSON object if successful,
    //                    which must be freed later using cJSON_Delete.
    std::string json_to_parse = fdp.ConsumeRandomLengthString(1024);
    const char *parse_end_ptr = nullptr; // Optional: to see where parsing stopped.
    cJSON_bool require_null_terminated_parse = fdp.ConsumeBool();
    root_json = cJSON_ParseWithOpts(json_to_parse.c_str(), &parse_end_ptr, require_null_terminated_parse);

    // --- API: cJSON_Parse (New) ---
    // Description: Parses a JSON string using default options.
    // Input Strategy: Consume a string from fuzzer data.
    // Memory Management: cJSON_Parse allocates a cJSON object, which needs to be freed by SafeCJSONDelete.
    // Coverage Rationale: Targets the uncovered cJSON_Parse function.
    std::string json_to_parse_simple_str = fdp.ConsumeRandomLengthString(256);
    parsed_json_simple = cJSON_Parse(json_to_parse_simple_str.c_str());


    // --- API 2: cJSON_CreateString ---
    // Description: Creates a new cJSON string item. This tests item creation.
    // Input Strategy: Consume a string from the fuzzer data for the value of the JSON string.
    // Memory Management: cJSON_CreateString allocates a new cJSON object,
    //                    which must be freed using cJSON_Delete if not added to another JSON structure.
    std::string string_value_for_item = fdp.ConsumeRandomLengthString(128);
    item_to_add = cJSON_CreateString(string_value_for_item.c_str());

    // --- API: cJSON_CreateNumber (New) ---
    // Description: Creates a cJSON number item.
    // Input Strategy: Consume a double value from fuzzer data.
    // Memory Management: cJSON_CreateNumber allocates a cJSON object.
    //                  It will be added to an array or deleted directly if not added.
    // Coverage Rationale: Targets the uncovered cJSON_CreateNumber function.
    double num_value_for_item = fdp.ConsumeFloatingPoint<double>();
    number_json_item = cJSON_CreateNumber(num_value_for_item);

    // --- API 3: cJSON_AddItemToObject ---
    // Description: Adds an item to a cJSON object. This tests object modification.
    // Input Strategy: If root_json is a valid object and item_to_add was created,
    //                 Consume a string for the key and attempt to add item_to_add.
    // Memory Management: If cJSON_AddItemToObject is successful, root_json takes ownership of item_to_add.
    //                    The item_to_add pointer should then be considered transferred (nulled out here).
    //                    If it fails, item_to_add remains owned by this scope and must be deleted manually.
    if (root_json && cJSON_IsObject(root_json) && item_to_add) {
        added_item_key = fdp.ConsumeRandomLengthString(32); // Generate a key for the item.
        if (cJSON_AddItemToObject(root_json, added_item_key.c_str(), item_to_add)) {
            // Item successfully added. root_json now owns item_to_add.
            item_to_add = nullptr; // Mark as transferred.
        }
        // If adding failed, item_to_add is still valid and needs cleanup later.
    }

    // --- API: cJSON_AddNumberToObject (New) ---
    // Description: Creates a number item and adds it to a cJSON object.
    // Input Strategy: If root_json is an object, add a number with a fuzzed key and value.
    // Memory Management: The new number item is owned by root_json if successfully added.
    //                    cJSON_AddNumberToObject handles its own item creation.
    // Coverage Rationale: Targets the uncovered cJSON_AddNumberToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string number_item_key_for_obj = fdp.ConsumeRandomLengthString(32);
        double number_to_add_to_obj_val = fdp.ConsumeFloatingPoint<double>();
        /* cJSON* added_num_ptr = */ cJSON_AddNumberToObject(root_json, number_item_key_for_obj.c_str(), number_to_add_to_obj_val);
        // The returned pointer is to an item within root_json, no separate delete needed for it.
    }
    
    // --- APIs: cJSON_CreateArray, cJSON_AddItemToArray, cJSON_GetArraySize, cJSON_GetArrayItem (New) ---
    // Description: Tests array creation, item addition, size retrieval, and item retrieval.
    // Input Strategy: Create an array. Add the 'number_json_item' (if created) and a new string item. Get its size and an item.
    // Memory Management: array_json is allocated and needs SafeCJSONDelete.
    //                    Items added via cJSON_AddItemToArray are owned by array_json.
    //                    If number_json_item is added, its ownership transfers.
    // Coverage Rationale: Targets uncovered array manipulation functions.
    array_json = cJSON_CreateArray();
    if (array_json) {
        if (number_json_item) { // Try to add the previously created number item
            if (cJSON_AddItemToArray(array_json, number_json_item)) {
                number_json_item = nullptr; // Ownership transferred to array_json
            }
            // If adding failed, number_json_item remains and will be cleaned up later by SafeCJSONDelete.
        }

        std::string str_for_array_val_content = fdp.ConsumeRandomLengthString(64);
        cJSON* string_item_for_array_creation = cJSON_CreateString(str_for_array_val_content.c_str());
        if (string_item_for_array_creation) {
            if (cJSON_AddItemToArray(array_json, string_item_for_array_creation)) {
                // string_item_for_array_creation is now owned by array_json
            } else {
                SafeCJSONDelete(string_item_for_array_creation); // Failed to add, clean it up
            }
        }
        
        int current_array_size = cJSON_GetArraySize(array_json);
        if (current_array_size > 0) {
            int random_idx = fdp.ConsumeIntegralInRange<int>(0, current_array_size - 1);
            /* cJSON* fetched_item = */ cJSON_GetArrayItem(array_json, random_idx);
            // fetched_item is a pointer to an item within array_json, no separate delete needed for it.
        }
    }


    // --- API 4: cJSON_Duplicate ---
    // Description: Creates a deep copy of a cJSON item. This tests cloning/duplication logic.
    // Input Strategy: If root_json exists, duplicate it. Consume a boolean for recursive duplication.
    // Memory Management: cJSON_Duplicate allocates a new cJSON object for the copy,
    //                    which must be freed using cJSON_Delete.
    if (root_json) {
        cJSON_bool recurse_duplicate = fdp.ConsumeBool();
        duplicated_json = cJSON_Duplicate(root_json, recurse_duplicate);
    }

    // --- API 5: cJSON_PrintBuffered ---
    // Description: Prints a cJSON item to a dynamically sized buffer. Tests serialization.
    // Input Strategy: Choose randomly between root_json or duplicated_json (if available) to print.
    //                 Consume an integer for the initial buffer size and a boolean for formatting.
    // Memory Management: cJSON_PrintBuffered allocates a character buffer,
    //                    which must be freed using cJSON_free.
    cJSON* json_to_print_buffered_ptr = (fdp.ConsumeBool() && duplicated_json) ? duplicated_json : root_json;
    if (json_to_print_buffered_ptr) {
        int prebuffer_size = fdp.ConsumeIntegralInRange<int>(0, 2048); // Test with various buffer sizes.
        cJSON_bool format_print = fdp.ConsumeBool();
        printed_buffer = cJSON_PrintBuffered(json_to_print_buffered_ptr, prebuffer_size, format_print);
    }

    // --- API: cJSON_PrintUnformatted (New) ---
    // Description: Prints a cJSON item to a string without formatting.
    // Input Strategy: Use root_json, duplicated_json, or parsed_json_simple if available.
    // Memory Management: Allocates a char buffer, which needs to be freed by SafeCJSONFree.
    // Coverage Rationale: Targets the uncovered cJSON_PrintUnformatted function.
    cJSON* json_for_unformatted_print = root_json ? root_json : (duplicated_json ? duplicated_json : parsed_json_simple);
    if (json_for_unformatted_print) {
        printed_unformatted_str = cJSON_PrintUnformatted(json_for_unformatted_print);
    }
    
    // --- API: cJSON_Print (New) ---
    // Description: Prints a cJSON item to a string with formatting.
    // Input Strategy: Use root_json, duplicated_json, or parsed_json_simple if available.
    // Memory Management: Allocates a char buffer, freed by SafeCJSONFree.
    // Coverage Rationale: Targets uncovered cJSON_Print.
    cJSON* json_for_formatted_print_ptr = duplicated_json ? duplicated_json : (root_json ? root_json : parsed_json_simple);
    if (json_for_formatted_print_ptr) {
        printed_formatted_str = cJSON_Print(json_for_formatted_print_ptr);
        // This string will be cleaned up in the main cleanup phase.
    }

    // --- API: cJSON_Minify (New) ---
    // Description: Minifies a JSON string in-place.
    // Input Strategy: Use the output of cJSON_PrintUnformatted if available.
    // Memory Management: Requires a mutable copy of the JSON string. The copy is allocated with malloc and freed with free.
    // Coverage Rationale: Targets uncovered cJSON_Minify.
    if (printed_unformatted_str) { // Use the string from cJSON_PrintUnformatted
        size_t len = strlen(printed_unformatted_str);
        minifiable_json_string = (char*)malloc(len + 1); 
        if (minifiable_json_string) {
            strcpy(minifiable_json_string, printed_unformatted_str);
            cJSON_Minify(minifiable_json_string);
            free(minifiable_json_string); // Free the mutable copy
            minifiable_json_string = nullptr; 
        }
    } else if (printed_buffer) { // Fallback to printed_buffer if unformatted wasn't generated
        size_t len = strlen(printed_buffer);
        minifiable_json_string = (char*)malloc(len + 1);
        if (minifiable_json_string) {
            strcpy(minifiable_json_string, printed_buffer);
            cJSON_Minify(minifiable_json_string);
            free(minifiable_json_string);
            minifiable_json_string = nullptr;
        }
    }
    
    // --- API: cJSON_SetValuestring (New) ---
    // Description: Sets the value of a cJSON string item.
    // Input Strategy: Create a string item and then set its value with varying lengths.
    // Memory Management: The cJSON item manages its internal string. The item itself is created and deleted in this block.
    // Coverage Rationale: Targets uncovered cJSON_SetValuestring.
    std::string initial_val_for_setvaluestring = fdp.ConsumeRandomLengthString(32);
    string_to_modify_valuestring = cJSON_CreateString(initial_val_for_setvaluestring.c_str());
    if (string_to_modify_valuestring) {
        std::string new_string_val_for_setvaluestring = fdp.ConsumeRandomLengthString(fdp.ConsumeBool() ? 64 : 16); // Test with potentially longer or shorter strings
        cJSON_SetValuestring(string_to_modify_valuestring, new_string_val_for_setvaluestring.c_str());
        // The string_to_modify_valuestring will be cleaned up in the main cleanup phase.
    }
    
    // --- Bonus API: cJSON_DeleteItemFromObject ---
    // Description: Deletes an item from a cJSON object by key. Tests further object modification.
    // Input Strategy: If root_json is an object, attempt to delete an item.
    //                 Randomly choose between deleting the item added earlier (if any) or a random key.
    // Memory Management: cJSON_DeleteItemFromObject handles freeing the memory of the deleted cJSON item.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_to_delete;
        if (!added_item_key.empty() && fdp.ConsumeBool()) { // 50% chance to try deleting the known added key.
            key_to_delete = added_item_key;
        } else {
            key_to_delete = fdp.ConsumeRandomLengthString(32); // Try a new random key.
        }
        cJSON_DeleteItemFromObject(root_json, key_to_delete.c_str());
    }

    // --- API: cJSON_ReplaceItemInObject (New) ---
    // Description: Replaces an item in a cJSON object. If key doesn't exist, it adds.
    // Input Strategy: If root_json is an object, create a new item and try to replace using a fuzzed key.
    // Memory Management: If successful, root_json takes ownership of replacement_obj_item.
    //                    If unsuccessful, replacement_obj_item must be deleted.
    // Coverage Rationale: Targets uncovered cJSON_ReplaceItemInObject.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_for_replacement = fdp.ConsumeRandomLengthString(32);
        replacement_obj_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()); 

        if (replacement_obj_item) {
            if (cJSON_ReplaceItemInObject(root_json, key_for_replacement.c_str(), replacement_obj_item)) {
                replacement_obj_item = nullptr; // Ownership transferred to root_json.
            }
            // If replacement failed, replacement_obj_item is still valid and will be cleaned up.
        }
    }


    // --- Bonus API: cJSON_Compare ---
    // Description: Compares two cJSON items for equality. Tests comparison logic.
    // Input Strategy: If both root_json and duplicated_json exist, compare them.
    //                 Consume a boolean to determine if the comparison should be case-sensitive.
    if (root_json && duplicated_json) {
        cJSON_bool case_sensitive_compare = fdp.ConsumeBool();
        cJSON_Compare(root_json, duplicated_json, case_sensitive_compare);
        // The boolean result of cJSON_Compare is not used here, focus is on exercising the API.
    }

    // --- New Coverage Additions ---

    // cJSON_GetErrorPtr
    // Coverage Rationale: Targets the uncovered cJSON_GetErrorPtr function.
    cJSON_GetErrorPtr();

    // cJSON_GetStringValue
    // Coverage Rationale: Targets the uncovered cJSON_GetStringValue function and its internal branches.
    string_item_for_get_value = cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str());
    if (string_item_for_get_value) {
        cJSON_GetStringValue(string_item_for_get_value);
    }
    cJSON_GetStringValue(number_json_item); // Test with a non-string item to hit the 'if (!cJSON_IsString(item))' branch.
    cJSON_GetStringValue(nullptr); // Test with NULL to hit the 'item == NULL' branch in cJSON_IsString.

    // cJSON_GetNumberValue
    // Coverage Rationale: Targets the uncovered cJSON_GetNumberValue function and its internal branches.
    number_item_for_get_value = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
    if (number_item_for_get_value) {
        cJSON_GetNumberValue(number_item_for_get_value);
    }
    cJSON_GetNumberValue(string_item_for_get_value); // Test with a non-number item to hit the 'if (!cJSON_IsNumber(item))' branch.
    cJSON_GetNumberValue(nullptr); // Test with NULL to hit the 'item == NULL' branch in cJSON_IsNumber.

    // cJSON_InitHooks
    // Coverage Rationale: Targets the uncovered cJSON_InitHooks function and its internal branches.
    // Call with NULL to reset hooks, then with custom hooks to cover both branches.
    cJSON_InitHooks(nullptr); // Resets to default malloc/free/realloc
    cJSON_Hooks custom_hooks = {
        .malloc_fn = malloc,
        .free_fn = free
    };
    cJSON_InitHooks(&custom_hooks); // Sets custom hooks (which are default in this case, but covers the branch)

    // cJSON_SetNumberHelper (indirectly covered by cJSON_CreateNumber and cJSON_AddNumberToObject, but let's ensure)
    // Coverage Rationale: Targets cJSON_SetNumberHelper via cJSON_SetNumberValue, including boundary conditions.
    if (number_json_item) {
        cJSON_SetNumberValue(number_json_item, fdp.ConsumeFloatingPoint<double>());
        // Test with INT_MAX and INT_MIN boundaries for cJSON_SetNumberHelper branches
        cJSON_SetNumberValue(number_json_item, (double)INT_MAX + 1.0);
        cJSON_SetNumberValue(number_json_item, (double)INT_MIN - 1.0);
    }

    // cJSON_ParseWithLength
    // Coverage Rationale: Targets the uncovered cJSON_ParseWithLength function.
    std::string json_to_parse_with_len = fdp.ConsumeRandomLengthString(512);
    cJSON *parsed_with_len = cJSON_ParseWithLength(json_to_parse_with_len.c_str(), json_to_parse_with_len.length());
    SafeCJSONDelete(parsed_with_len);

    // cJSON_PrintPreallocated
    // Coverage Rationale: Targets the uncovered cJSON_PrintPreallocated function and its error branches.
    // Test with valid buffer and also with NULL buffer/negative length to hit error branches.
    int prealloc_buf_size = fdp.ConsumeIntegralInRange<int>(1, 1024);
    preallocated_buffer = (char*)malloc(prealloc_buf_size);
    if (preallocated_buffer && root_json) {
        cJSON_PrintPreallocated(root_json, preallocated_buffer, prealloc_buf_size, fdp.ConsumeBool());
    }
    cJSON_PrintPreallocated(root_json, nullptr, prealloc_buf_size, fdp.ConsumeBool()); // Test buffer == NULL branch
    cJSON_PrintPreallocated(root_json, preallocated_buffer, -1, fdp.ConsumeBool()); // Test length < 0 branch
    SafeCJSONFree(reinterpret_cast<void*&>(preallocated_buffer)); // Clean up preallocated_buffer

    // cJSON_GetObjectItemCaseSensitive
    // Coverage Rationale: Targets the uncovered cJSON_GetObjectItemCaseSensitive function.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_to_get = fdp.ConsumeRandomLengthString(32);
        cJSON_GetObjectItemCaseSensitive(root_json, key_to_get.c_str());
    }

    // cJSON_HasObjectItem
    // Coverage Rationale: Targets the uncovered cJSON_HasObjectItem function and its internal branches.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_to_check = fdp.ConsumeRandomLengthString(32);
        cJSON_HasObjectItem(root_json, key_to_check.c_str());
        // Test with a key that might exist (added_item_key) to hit both true/false branches.
        if (!added_item_key.empty()) {
            cJSON_HasObjectItem(root_json, added_item_key.c_str());
        }
    }

    // cJSON_AddItemToObjectCS
    // Coverage Rationale: Targets the uncovered cJSON_AddItemToObjectCS function.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string cs_key = fdp.ConsumeRandomLengthString(32);
        cJSON *temp_cs_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(32).c_str());
        if (temp_cs_item) {
            // Use cJSON_AddItemToObject instead of cJSON_AddItemToObjectCS to ensure key string is copied
            // as cs_key is a local variable and its c_str() would be a dangling pointer after function exit.
            if (!cJSON_AddItemToObject(root_json, cs_key.c_str(), temp_cs_item)) {
                SafeCJSONDelete(temp_cs_item); // Clean up if not added (ownership not transferred)
            }
        }
    }

    // cJSON_AddItemReferenceToArray
    // Coverage Rationale: Targets the uncovered cJSON_AddItemReferenceToArray function and its error branches.
    if (array_json && root_json) { // Need an array and an item to reference
        cJSON_AddItemReferenceToArray(array_json, root_json);
    }
    // Test null array branch - no return value to delete
    cJSON_AddItemReferenceToArray(nullptr, root_json); 

    // cJSON_AddItemReferenceToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddItemReferenceToObject function and its error branches.
    if (root_json && parsed_json_simple) { // Need an object and an item to reference
        std::string ref_key = fdp.ConsumeRandomLengthString(32);
        cJSON_AddItemReferenceToObject(root_json, ref_key.c_str(), parsed_json_simple);
    }
    // Test null object branch - no return value to delete
    cJSON_AddItemReferenceToObject(nullptr, "key", parsed_json_simple); 
    // Test null string branch - no return value to delete
    cJSON_AddItemReferenceToObject(root_json, nullptr, parsed_json_simple); 

    // cJSON_AddNullToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddNullToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddNullToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
    }

    // cJSON_AddTrueToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddTrueToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddTrueToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
    }

    // cJSON_AddFalseToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddFalseToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddFalseToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
    }

    // cJSON_AddBoolToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddBoolToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddBoolToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeBool());
    }

    // cJSON_AddStringToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddStringToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddStringToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeRandomLengthString(64).c_str());
    }

    // cJSON_AddRawToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddRawToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddRawToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeRandomLengthString(64).c_str());
    }

    // cJSON_AddObjectToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddObjectToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddObjectToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
    }

    // cJSON_AddArrayToObject
    // Coverage Rationale: Targets the uncovered cJSON_AddArrayToObject function.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddArrayToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
    }

    // cJSON_DetachItemFromArray
    // Coverage Rationale: Targets the uncovered cJSON_DetachItemFromArray function and its error branches.
    if (array_json && cJSON_GetArraySize(array_json) > 0) {
        int idx = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(array_json) - 1);
        cJSON *detached = cJSON_DetachItemFromArray(array_json, idx);
        SafeCJSONDelete(detached); // Detached item needs to be deleted
    }
    cJSON *temp_detached_item = cJSON_DetachItemFromArray(array_json, -1); // Test negative index branch
    SafeCJSONDelete(temp_detached_item);

    // cJSON_DeleteItemFromArray
    // Coverage Rationale: Targets the uncovered cJSON_DeleteItemFromArray function.
    if (array_json && cJSON_GetArraySize(array_json) > 0) {
        int idx = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(array_json) - 1);
        cJSON_DeleteItemFromArray(array_json, idx);
    }

    // cJSON_DetachItemFromObjectCaseSensitive
    // Coverage Rationale: Targets the uncovered cJSON_DetachItemFromObjectCaseSensitive function.
    if (root_json && cJSON_IsObject(root_json) && !added_item_key.empty()) {
        cJSON *detached = cJSON_DetachItemFromObjectCaseSensitive(root_json, added_item_key.c_str());
        SafeCJSONDelete(detached);
    }

    // cJSON_DeleteItemFromObjectCaseSensitive
    // Coverage Rationale: Targets the uncovered cJSON_DeleteItemFromObjectCaseSensitive function.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string key_to_delete_cs = fdp.ConsumeRandomLengthString(32);
        cJSON_DeleteItemFromObjectCaseSensitive(root_json, key_to_delete_cs.c_str());
    }

    // cJSON_InsertItemInArray
    // Coverage Rationale: Targets the uncovered cJSON_InsertItemInArray function and its error branches.
    if (array_json) {
        cJSON *insert_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(32).c_str());
        if (insert_item) {
            int insert_idx = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(array_json));
            if (!cJSON_InsertItemInArray(array_json, insert_idx, insert_item)) {
                SafeCJSONDelete(insert_item); // Clean up if not inserted (ownership not transferred)
            }
        }
    }
    cJSON *temp_null_item_insert = cJSON_CreateNull();
    if (!cJSON_InsertItemInArray(array_json, -1, temp_null_item_insert)) { // Test negative index branch
        SafeCJSONDelete(temp_null_item_insert);
    }
    cJSON_InsertItemInArray(array_json, 0, nullptr); // Test null newitem branch

    // cJSON_ReplaceItemInArray
    // Coverage Rationale: Targets the uncovered cJSON_ReplaceItemInArray function and its error branches.
    if (array_json && cJSON_GetArraySize(array_json) > 0) {
        cJSON *replace_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(32).c_str());
        if (replace_item) {
            int replace_idx = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(array_json) - 1);
            if (!cJSON_ReplaceItemInArray(array_json, replace_idx, replace_item)) {
                SafeCJSONDelete(replace_item); // Clean up if not replaced (ownership not transferred)
            }
        }
    }
    cJSON *temp_null_item_replace = cJSON_CreateNull();
    if (!cJSON_ReplaceItemInArray(array_json, -1, temp_null_item_replace)) { // Test negative index branch
        SafeCJSONDelete(temp_null_item_replace);
    }

    // cJSON_ReplaceItemInObjectCaseSensitive
    // Coverage Rationale: Targets the uncovered cJSON_ReplaceItemInObjectCaseSensitive function.
    if (root_json && cJSON_IsObject(root_json)) {
        std::string replace_key_cs = fdp.ConsumeRandomLengthString(32);
        cJSON *replace_item_cs = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
        if (replace_item_cs) {
            if (!cJSON_ReplaceItemInObjectCaseSensitive(root_json, replace_key_cs.c_str(), replace_item_cs)) {
                SafeCJSONDelete(replace_item_cs); // Clean up if not replaced (ownership not transferred)
            }
        }
    }

    // cJSON_CreateNull
    // Coverage Rationale: Targets the uncovered cJSON_CreateNull function.
    null_item = cJSON_CreateNull();

    // cJSON_CreateTrue
    // Coverage Rationale: Targets the uncovered cJSON_CreateTrue function.
    true_item = cJSON_CreateTrue();

    // cJSON_CreateFalse
    // Coverage Rationale: Targets the uncovered cJSON_CreateFalse function.
    false_item = cJSON_CreateFalse();

    // cJSON_CreateBool
    // Coverage Rationale: Targets the uncovered cJSON_CreateBool function.
    bool_item = cJSON_CreateBool(fdp.ConsumeBool());

    // cJSON_CreateStringReference
    // Coverage Rationale: Targets the uncovered cJSON_CreateStringReference function and its error branches.
    std::string ref_string_data = fdp.ConsumeRandomLengthString(32);
    string_ref_item = cJSON_CreateStringReference(ref_string_data.c_str());
    cJSON *temp_string_ref_null = cJSON_CreateStringReference(nullptr); // Test null string branch
    SafeCJSONDelete(temp_string_ref_null);

    // cJSON_CreateObjectReference
    // Coverage Rationale: Targets the uncovered cJSON_CreateObjectReference function and its error branches.
    if (root_json) {
        object_ref_item = cJSON_CreateObjectReference(root_json);
    }
    cJSON *temp_object_ref_null = cJSON_CreateObjectReference(nullptr); // Test null child branch
    SafeCJSONDelete(temp_object_ref_null);

    // cJSON_CreateArrayReference
    // Coverage Rationale: Targets the uncovered cJSON_CreateArrayReference function and its error branches.
    if (array_json) {
        array_ref_item = cJSON_CreateArrayReference(array_json);
    }
    cJSON *temp_array_ref_null = cJSON_CreateArrayReference(nullptr); // Test null child branch
    SafeCJSONDelete(temp_array_ref_null);

    // cJSON_CreateRaw
    // Coverage Rationale: Targets the uncovered cJSON_CreateRaw function and its error branches.
    raw_item_created = cJSON_CreateRaw(fdp.ConsumeRandomLengthString(64).c_str());
    cJSON *temp_raw_null = cJSON_CreateRaw(nullptr); // Test null raw string branch
    SafeCJSONDelete(temp_raw_null);

    // cJSON_CreateObject
    // Coverage Rationale: Targets the uncovered cJSON_CreateObject function.
    object_item_created = cJSON_CreateObject();

    // cJSON_CreateIntArray
    // Coverage Rationale: Targets the uncovered cJSON_CreateIntArray function and its error branches.
    std::vector<int> int_array_data;
    size_t int_array_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < int_array_count; ++i) {
        int_array_data.push_back(fdp.ConsumeIntegral<int>());
    }
    int_array_item = cJSON_CreateIntArray(int_array_data.data(), int_array_data.size());
    cJSON *temp_int_array_null = cJSON_CreateIntArray(nullptr, 0); // Test null numbers branch
    SafeCJSONDelete(temp_int_array_null);
    cJSON *temp_int_array_neg_count = cJSON_CreateIntArray(int_array_data.data(), -1); // Test negative count branch
    SafeCJSONDelete(temp_int_array_neg_count);

    // cJSON_CreateFloatArray
    // Coverage Rationale: Targets the uncovered cJSON_CreateFloatArray function and its error branches.
    std::vector<float> float_array_data;
    size_t float_array_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < float_array_count; ++i) {
        float_array_data.push_back(fdp.ConsumeFloatingPoint<float>());
    }
    float_array_item = cJSON_CreateFloatArray(float_array_data.data(), float_array_data.size());
    cJSON *temp_float_array_null = cJSON_CreateFloatArray(nullptr, 0); // Test null numbers branch
    SafeCJSONDelete(temp_float_array_null);
    cJSON *temp_float_array_neg_count = cJSON_CreateFloatArray(float_array_data.data(), -1); // Test negative count branch
    SafeCJSONDelete(temp_float_array_neg_count);

    // cJSON_CreateDoubleArray
    // Coverage Rationale: Targets the uncovered cJSON_CreateDoubleArray function and its error branches.
    std::vector<double> double_array_data;
    size_t double_array_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < double_array_count; ++i) {
        double_array_data.push_back(fdp.ConsumeFloatingPoint<double>());
    }
    double_array_item = cJSON_CreateDoubleArray(double_array_data.data(), double_array_data.size());
    cJSON *temp_double_array_null = cJSON_CreateDoubleArray(nullptr, 0); // Test null numbers branch
    SafeCJSONDelete(temp_double_array_null);
    cJSON *temp_double_array_neg_count = cJSON_CreateDoubleArray(double_array_data.data(), -1); // Test negative count branch
    SafeCJSONDelete(temp_double_array_neg_count);

    // cJSON_CreateStringArray
    // Coverage Rationale: Targets the uncovered cJSON_CreateStringArray function and its error branches.
    std::vector<std::string> string_array_str_data;
    size_t string_array_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < string_array_count; ++i) {
        string_array_str_data.push_back(fdp.ConsumeRandomLengthString(32));
    }
    std::vector<const char*> string_array_c_str_data;
    string_array_c_str_data.reserve(string_array_count); // Pre-allocate to avoid reallocations
    for (const auto& str : string_array_str_data) {
        string_array_c_str_data.push_back(str.c_str());
    }
    string_array_item = cJSON_CreateStringArray(string_array_c_str_data.data(), string_array_c_str_data.size());
    cJSON *temp_string_array_null = cJSON_CreateStringArray(nullptr, 0); // Test null strings branch
    SafeCJSONDelete(temp_string_array_null);
    cJSON *temp_string_array_neg_count = cJSON_CreateStringArray(string_array_c_str_data.data(), -1); // Test negative count branch
    SafeCJSONDelete(temp_string_array_neg_count);

    // cJSON_IsInvalid, cJSON_IsFalse, cJSON_IsTrue, cJSON_IsBool, cJSON_IsNull, cJSON_IsNumber, cJSON_IsString, cJSON_IsArray, cJSON_IsRaw
    // Coverage Rationale: Targets the uncovered cJSON_Is* functions and their NULL branches.
    cJSON_IsInvalid(nullptr);
    cJSON_IsInvalid(root_json);
    cJSON_IsFalse(nullptr);
    cJSON_IsFalse(false_item);
    cJSON_IsFalse(true_item); // Test false branch
    cJSON_IsTrue(nullptr);
    cJSON_IsTrue(true_item);
    cJSON_IsTrue(false_item); // Test false branch
    cJSON_IsBool(nullptr);
    cJSON_IsBool(true_item);
    cJSON_IsBool(false_item);
    cJSON_IsBool(number_json_item); // Test false branch
    cJSON_IsNull(nullptr);
    cJSON_IsNull(null_item);
    cJSON_IsNull(root_json); // Test false branch
    cJSON_IsNumber(nullptr);
    cJSON_IsNumber(number_json_item);
    cJSON_IsNumber(string_item_for_get_value); // Test false branch
    cJSON_IsString(nullptr);
    cJSON_IsString(string_item_for_get_value);
    cJSON_IsString(number_json_item); // Test false branch
    cJSON_IsArray(nullptr);
    cJSON_IsArray(array_json);
    cJSON_IsArray(root_json); // Test false branch
    cJSON_IsRaw(nullptr);
    cJSON_IsRaw(raw_item_created);
    cJSON_IsRaw(root_json); // Test false branch

    // cJSON_malloc
    // Coverage Rationale: Targets the uncovered cJSON_malloc function.
    void *test_malloc_ptr = cJSON_malloc(fdp.ConsumeIntegralInRange<size_t>(1, 1024));
    if (test_malloc_ptr) {
        cJSON_free(test_malloc_ptr); // Use cJSON_free for consistency
    }


    // --- Cleanup Phase ---
    // Ensure all allocated cJSON objects and buffers are freed to prevent memory leaks.

    SafeCJSONDelete(root_json);
    SafeCJSONDelete(item_to_add); // Delete if not added to root_json
    SafeCJSONDelete(duplicated_json);
    SafeCJSONFree(reinterpret_cast<void*&>(printed_buffer));

    // Cleanup for new items
    SafeCJSONDelete(parsed_json_simple);
    SafeCJSONFree(reinterpret_cast<void*&>(printed_unformatted_str));
    SafeCJSONFree(reinterpret_cast<void*&>(printed_formatted_str));
    SafeCJSONDelete(number_json_item); // Delete if not added to array_json
    SafeCJSONDelete(array_json);
    // minifiable_json_string is freed in its own block if allocated
    SafeCJSONDelete(string_to_modify_valuestring);
    SafeCJSONDelete(replacement_obj_item); // Delete if not successfully used in ReplaceItemInObject

    // Cleanup for newly added coverage targets
    SafeCJSONDelete(null_item);
    SafeCJSONDelete(true_item);
    SafeCJSONDelete(false_item);
    SafeCJSONDelete(bool_item);
    SafeCJSONDelete(object_item_created);
    SafeCJSONDelete(raw_item_created);
    SafeCJSONDelete(string_item_for_get_value);
    SafeCJSONDelete(number_item_for_get_value);
    SafeCJSONDelete(int_array_item);
    SafeCJSONDelete(float_array_item);
    SafeCJSONDelete(double_array_item);
    SafeCJSONDelete(string_array_item);
    SafeCJSONDelete(string_ref_item);
    SafeCJSONDelete(object_ref_item);
    SafeCJSONDelete(array_ref_item);
    // preallocated_buffer is freed in its own block if allocated

    return 0; // Indicate successful execution to the fuzzer.
}