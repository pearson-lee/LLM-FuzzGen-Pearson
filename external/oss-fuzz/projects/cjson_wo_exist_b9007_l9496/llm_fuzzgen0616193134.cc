#include "/src/cjson/cJSON.h" // Required header for cJSON library functions.
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <vector> // For creating arrays of numbers/strings
#include <memory> // For std::unique_ptr

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

    // --- New API Calls for Coverage Improvement ---

    // Target: cJSON_Minify (0% coverage)
    // Description: Minifies a JSON string by removing whitespace and comments.
    // Input Strategy: Provide a fuzzed string that might contain whitespace, single-line, and multi-line comments.
    // Memory Management: cJSON_Minify modifies the string in place.
    {
        std::string minify_input_str = fdp.ConsumeRandomLengthString(1024);
        // Create a mutable copy for cJSON_Minify, which modifies the string in place.
        std::vector<char> minify_buffer(minify_input_str.begin(), minify_input_str.end());
        minify_buffer.push_back('\0'); // Ensure null termination
        if (!minify_buffer.empty()) {
            cJSON_Minify(minify_buffer.data());
        }
    }

    // Target: cJSON_CreateNull, cJSON_CreateTrue, cJSON_CreateFalse, cJSON_CreateBool, cJSON_CreateNumber, cJSON_CreateRaw, cJSON_CreateArray, cJSON_CreateObject (all 0% coverage)
    // Description: Exercise various cJSON creation functions.
    // Input Strategy: Randomly create different types of cJSON items.
    // Memory Management: Each created item needs to be deleted if not added to another cJSON object.
    cJSON *created_item = nullptr;
    int create_choice = fdp.ConsumeIntegralInRange<int>(0, 7); // 8 different creation functions

    switch (create_choice) {
        case 0: // cJSON_CreateNull
            created_item = cJSON_CreateNull();
            break;
        case 1: // cJSON_CreateTrue
            created_item = cJSON_CreateTrue();
            break;
        case 2: // cJSON_CreateFalse
            created_item = cJSON_CreateFalse();
            break;
        case 3: // cJSON_CreateBool
            created_item = cJSON_CreateBool(fdp.ConsumeBool());
            break;
        case 4: // cJSON_CreateNumber
            created_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            break;
        case 5: // cJSON_CreateRaw
            {
                std::string raw_string = fdp.ConsumeRandomLengthString(128);
                created_item = cJSON_CreateRaw(raw_string.c_str());
            }
            break;
        case 6: // cJSON_CreateArray
            created_item = cJSON_CreateArray();
            break;
        case 7: // cJSON_CreateObject
            created_item = cJSON_CreateObject();
            break;
    }

    // If an item was created and root_json is an object, try to add it.
    // This also covers cJSON_Add*ToObject functions indirectly if the created_item is of that type.
    if (root_json && cJSON_IsObject(root_json) && created_item) {
        std::string new_item_key = fdp.ConsumeRandomLengthString(32);
        if (cJSON_AddItemToObject(root_json, new_item_key.c_str(), created_item)) {
            created_item = nullptr; // Ownership transferred
        }
    }
    // Clean up created_item if it was not added to root_json.
    SafeCJSONDelete(created_item);


    // Target: cJSON_GetArraySize, cJSON_GetArrayItem (both 0% coverage)
    // Description: Test array manipulation functions.
    // Input Strategy: Create an array and add items to it, then try to get size and items.
    // Memory Management: Ensure created array and items are properly deleted.
    cJSON *test_array = cJSON_CreateArray();
    if (test_array) {
        int num_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
        for (int i = 0; i < num_elements; ++i) {
            std::string array_item_str = fdp.ConsumeRandomLengthString(64);
            cJSON *array_item = cJSON_CreateString(array_item_str.c_str());
            if (array_item) {
                if (!cJSON_AddItemToArray(test_array, array_item)) {
                    SafeCJSONDelete(array_item); // If adding fails, delete it here.
                }
            }
        }

        // Exercise cJSON_GetArraySize
        cJSON_GetArraySize(test_array);

        // Exercise cJSON_GetArrayItem
        if (num_elements > 0) {
            int index_to_get = fdp.ConsumeIntegralInRange<int>(0, num_elements - 1);
            cJSON_GetArrayItem(test_array, index_to_get);
        }
    }
    SafeCJSONDelete(test_array); // Clean up the test array and its children.

    // Target: cJSON_Parse (0% coverage)
    // Description: Parses a JSON string without options.
    // Input Strategy: Use a fuzzed string.
    // Memory Management: The returned cJSON object must be deleted.
    {
        std::string parse_input = fdp.ConsumeRandomLengthString(1024);
        cJSON *parsed_no_opts = cJSON_Parse(parse_input.c_str());
        SafeCJSONDelete(parsed_no_opts); // Clean up the parsed object.
    }

    // Target: cJSON_Print (0% coverage) and cJSON_PrintUnformatted (0% coverage)
    // Description: Prints a cJSON item with or without formatting.
    // Input Strategy: Use root_json or duplicated_json if available.
    // Memory Management: The returned char* buffer must be freed using cJSON_free.
    if (root_json) {
        char *formatted_print = cJSON_Print(root_json);
        SafeCJSONFree(reinterpret_cast<void*&>(formatted_print)); // Clean up the buffer.

        char *unformatted_print = cJSON_PrintUnformatted(root_json);
        SafeCJSONFree(reinterpret_cast<void*&>(unformatted_print)); // Clean up the buffer.
    }

    // Target: cJSON_PrintPreallocated (0% coverage)
    // Description: Prints a cJSON item into a preallocated buffer.
    // Input Strategy: Allocate a buffer and pass it to the function.
    // Memory Management: The preallocated buffer is managed by the fuzzer, not cJSON.
    {
        int prealloc_buffer_size = fdp.ConsumeIntegralInRange<int>(1, 2048);
        // Use std::unique_ptr for automatic memory management of the preallocated buffer.
        std::unique_ptr<char[]> preallocated_buffer(new char[prealloc_buffer_size]);
        if (root_json && preallocated_buffer) {
            cJSON_bool format_prealloc = fdp.ConsumeBool();
            cJSON_PrintPreallocated(root_json, preallocated_buffer.get(), prealloc_buffer_size, format_prealloc);
        }
    }

    // Target: cJSON_IsInvalid, cJSON_IsFalse, cJSON_IsTrue, cJSON_IsBool, cJSON_IsNull, cJSON_IsNumber, cJSON_IsString, cJSON_IsArray, cJSON_IsRaw (all 0% coverage)
    // Description: Exercise various cJSON type checking functions.
    // Input Strategy: Call these functions on existing cJSON objects (root_json, duplicated_json, or newly created ones).
    // Memory Management: These functions do not allocate memory, so no special cleanup is needed.
    if (root_json) {
        cJSON_IsInvalid(root_json);
        cJSON_IsFalse(root_json);
        cJSON_IsTrue(root_json);
        cJSON_IsBool(root_json);
        cJSON_IsNull(root_json);
        cJSON_IsNumber(root_json);
        cJSON_IsString(root_json);
        cJSON_IsArray(root_json);
        cJSON_IsRaw(root_json);
    }
    if (duplicated_json) {
        cJSON_IsInvalid(duplicated_json);
        cJSON_IsFalse(duplicated_json);
        cJSON_IsTrue(duplicated_json);
        cJSON_IsBool(duplicated_json);
        cJSON_IsNull(duplicated_json);
        cJSON_IsNumber(duplicated_json);
        cJSON_IsString(duplicated_json);
        cJSON_IsArray(duplicated_json);
        cJSON_IsRaw(duplicated_json);
    }

    // Target: cJSON_AddNullToObject, cJSON_AddTrueToObject, cJSON_AddFalseToObject, cJSON_AddBoolToObject, cJSON_AddNumberToObject, cJSON_AddStringToObject, cJSON_AddRawToObject, cJSON_AddObjectToObject, cJSON_AddArrayToObject (all 0% coverage)
    // Description: Directly call various cJSON object addition functions.
    // Input Strategy: If root_json is an object, add different types of items to it.
    // Memory Management: These functions create and add items, and the parent object takes ownership.
    if (root_json && cJSON_IsObject(root_json)) {
        cJSON_AddNullToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
        cJSON_AddTrueToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
        cJSON_AddFalseToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
        cJSON_AddBoolToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeBool());
        cJSON_AddNumberToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeFloatingPoint<double>());
        cJSON_AddStringToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeRandomLengthString(128).c_str());
        
        // For cJSON_AddRawToObject, cJSON_AddObjectToObject, cJSON_AddArrayToObject, ensure valid inputs.
        std::string raw_val = fdp.ConsumeRandomLengthString(128);
        cJSON_AddRawToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str(), raw_val.c_str());
        
        cJSON_AddObjectToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
        cJSON_AddArrayToObject(root_json, fdp.ConsumeRandomLengthString(32).c_str());
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