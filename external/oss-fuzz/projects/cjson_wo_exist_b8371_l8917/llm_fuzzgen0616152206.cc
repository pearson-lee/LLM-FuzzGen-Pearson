#include "/src/cjson/cJSON.h" // Required header for cJSON library functions.
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <vector>  // For creating arrays of data for cJSON array creation functions
#include <cstring> // For strcpy, strlen
#include <cstdlib> // For malloc, free (used for cJSON_Minify example)

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
    //                 consume a string for the key and attempt to add item_to_add.
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

    return 0; // Indicate successful execution to the fuzzer.
}