#include "/src/cjson/cJSON.h" // Required header for cJSON library functions.
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstddef> // For size_t
#include <cstdint> // For uint8_t

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

    // --- API 2: cJSON_CreateString ---
    // Description: Creates a new cJSON string item. This tests item creation.
    // Input Strategy: Consume a string from the fuzzer data for the value of the JSON string.
    // Memory Management: cJSON_CreateString allocates a new cJSON object,
    //                    which must be freed using cJSON_Delete if not added to another JSON structure.
    std::string string_value_for_item = fdp.ConsumeRandomLengthString(128);
    item_to_add = cJSON_CreateString(string_value_for_item.c_str());

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
    cJSON* json_to_print = (fdp.ConsumeBool() && duplicated_json) ? duplicated_json : root_json;
    if (json_to_print) {
        int prebuffer_size = fdp.ConsumeIntegralInRange<int>(0, 2048); // Test with various buffer sizes.
        cJSON_bool format_print = fdp.ConsumeBool();
        printed_buffer = cJSON_PrintBuffered(json_to_print, prebuffer_size, format_print);
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

    // Delete root_json. If item_to_add was successfully added to it,
    // it will be deleted as part of root_json's children.
    SafeCJSONDelete(root_json);

    // Delete item_to_add IF it was not successfully added to root_json (i.e., if item_to_add is not nullptr).
    SafeCJSONDelete(item_to_add);

    // Delete duplicated_json if it was created.
    SafeCJSONDelete(duplicated_json);

    // Free the buffer allocated by cJSON_PrintBuffered.
    SafeCJSONFree(reinterpret_cast<void*&>(printed_buffer));

    return 0; // Indicate successful execution to the fuzzer.
}