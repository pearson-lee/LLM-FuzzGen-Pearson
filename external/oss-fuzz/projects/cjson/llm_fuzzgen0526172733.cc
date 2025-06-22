#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include "/src/cjson/cJSON.h" // Always emit #include with the full project-relative path

// Custom deleter for cJSON objects to be used with std::unique_ptr.
// This ensures that cJSON_Delete is called automatically when the unique_ptr goes out of scope,
// preventing memory leaks.
struct CJSONDeleter {
    void operator()(cJSON* item) const {
        if (item) {
            cJSON_Delete(item);
        }
    }
};

// Define a type alias for unique_ptr managing cJSON objects.
using UniqueCJSONPtr = std::unique_ptr<cJSON, CJSONDeleter>;

// Helper function to create a fuzzed cJSON item.
// This function is crucial for generating diverse cJSON structures
// to be used as inputs for other cJSON API functions.
UniqueCJSONPtr CreateFuzzedCjsonItem(FuzzedDataProvider& fdp) {
    // Randomly choose the type of cJSON item to create
    int type = fdp.ConsumeIntegralInRange<int>(0, 7); // 0-7 for different cJSON types

    cJSON* raw_item = nullptr; // Use a raw pointer internally for creation

    switch (type) {
        case 0: // Null
            raw_item = cJSON_CreateNull();
            break;
        case 1: // True
            raw_item = cJSON_CreateTrue();
            break;
        case 2: // False
            raw_item = cJSON_CreateFalse();
            break;
        case 3: // Number
            raw_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
            break;
        case 4: // String
            raw_item = cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str());
            break;
        case 5: { // Array
            raw_item = cJSON_CreateArray();
            if (raw_item) { // Only proceed if array was successfully created
                int num_elements = fdp.ConsumeIntegralInRange<int>(0, 5); // Limit array size to avoid excessive recursion
                for (int i = 0; i < num_elements; ++i) {
                    UniqueCJSONPtr child_item = CreateFuzzedCjsonItem(fdp);
                    if (child_item) {
                        cJSON* released_child = child_item.release(); // Release ownership from child_item
                        // cJSON_AddItemToArray takes ownership if successful.
                        // If it fails, we must delete the released_child.
                        if (!cJSON_AddItemToArray(raw_item, released_child)) {
                            cJSON_Delete(released_child); // Delete if cJSON didn't take ownership
                        }
                    }
                }
            }
            break;
        }
        case 6: { // Object
            raw_item = cJSON_CreateObject();
            if (raw_item) { // Only proceed if object was successfully created
                int num_members = fdp.ConsumeIntegralInRange<int>(0, 5); // Limit object size
                for (int i = 0; i < num_members; ++i) {
                    std::string key = fdp.ConsumeRandomLengthString(10);
                    UniqueCJSONPtr child_item = CreateFuzzedCjsonItem(fdp);
                    if (child_item) {
                        cJSON* released_child = child_item.release(); // Release ownership from child_item
                        // cJSON_AddItemToObject takes ownership if successful.
                        // If it fails, we must delete the released_child.
                        if (!cJSON_AddItemToObject(raw_item, key.c_str(), released_child)) {
                            cJSON_Delete(released_child); // Delete if cJSON didn't take ownership
                        }
                    }
                }
            }
            break;
        }
        case 7: { // Raw
            std::string raw_string = fdp.ConsumeRandomLengthString(20);
            raw_item = cJSON_CreateRaw(raw_string.c_str());
            break;
        }
    }
    return UniqueCJSONPtr(raw_item); // Wrap the raw pointer in a unique_ptr for return
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. cJSON_ParseWithOpts: High-impact input processing API.
    std::string json_string = fdp.ConsumeRandomLengthString();
    bool require_null_terminated = fdp.ConsumeBool();
    const char *return_parse_end = nullptr;

    UniqueCJSONPtr parsed_json_item(cJSON_ParseWithOpts(json_string.c_str(), &return_parse_end, require_null_terminated));

    // Added to cover cJSON_ParseWithOpts lines 1093-1095 (if value == NULL)
    cJSON_ParseWithOpts(nullptr, &return_parse_end, require_null_terminated);

    // 2. cJSON_PrintBuffered: Resource management and output formatting.
    if (parsed_json_item) {
        // Adjusted range to include negative values to hit `if (prebuffer < 0)` branch in cJSON_PrintBuffered.
        int buffer_size = fdp.ConsumeIntegralInRange<int>(-10, 1024);
        bool format = fdp.ConsumeBool();
        char* printed_string = cJSON_PrintBuffered(parsed_json_item.get(), buffer_size, format);
        if (printed_string) {
            free(printed_string);
        }
    }

    // 3. cJSON_ReplaceItemInArray: Array manipulation and edge cases.
    UniqueCJSONPtr array_item = CreateFuzzedCjsonItem(fdp);
    if (array_item && cJSON_IsArray(array_item.get())) {
        int index_to_replace = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(array_item.get()) + 5);
        UniqueCJSONPtr new_item = CreateFuzzedCjsonItem(fdp);
        if (new_item) {
            // Added to cover cJSON_ReplaceItemViaPointer lines 2323-2325 (replacement == item)
            // This is achieved by sometimes replacing an item with itself.
            if (fdp.ConsumeBool() && cJSON_GetArrayItem(array_item.get(), index_to_replace) != nullptr) {
                // We need to ensure that if we replace an item with itself,
                // the original item is not deleted by the unique_ptr.
                // The cJSON_ReplaceItemInArray function handles ownership.
                // If new_item is the same as the item being replaced,
                // cJSON_ReplaceItemInArray will detach the old item and then
                // add the new_item (which is the same as the old item).
                // The old item (which is new_item in this case) will be deleted by cJSON_Delete.
                // To avoid double-free or use-after-free, we should not reset new_item to an existing item.
                // Instead, we can just pass the existing item directly if we want to test this path.
                // However, the original code's intent was to sometimes replace with an existing item.
                // Let's simplify this to avoid potential ownership issues with unique_ptr and cJSON's internal management.
                // The coverage for replacement == item is better achieved by ensuring the 'new_item'
                // is indeed the same pointer as the one being replaced, which is tricky with unique_ptr.
                // For now, let's remove the problematic line that tries to reset new_item.
                // The primary goal is to fix the build error and memory leaks.
            }

            cJSON* raw_new_item = new_item.release(); // Release ownership
            // cJSON_ReplaceItemInArray takes ownership if successful.
            // If not successful, we must delete the raw_new_item.
            if (!cJSON_ReplaceItemInArray(array_item.get(), index_to_replace, raw_new_item)) {
                cJSON_Delete(raw_new_item); // Delete if cJSON didn't take ownership
            }
        }
    }

    // 4. cJSON_DetachItemFromArray: Array manipulation and memory management.
    UniqueCJSONPtr array_to_detach_from = CreateFuzzedCjsonItem(fdp);
    if (array_to_detach_from && cJSON_IsArray(array_to_detach_from.get())) {
        int index_to_detach = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(array_to_detach_from.get()) + 5);
        UniqueCJSONPtr detached_item(cJSON_DetachItemFromArray(array_to_detach_from.get(), index_to_detach));
    }

    // 5. cJSON_Duplicate: Deep/shallow copy and memory allocation.
    UniqueCJSONPtr item_to_duplicate = CreateFuzzedCjsonItem(fdp);
    if (item_to_duplicate) {
        bool recurse = fdp.ConsumeBool();
        UniqueCJSONPtr duplicated_item(cJSON_Duplicate(item_to_duplicate.get(), recurse));
    }

    // Additional fuzzing calls to improve coverage based on report:

    // Call cJSON_GetArraySize with NULL to cover the `if (array == NULL)` branch (line 1852).
    cJSON_GetArraySize(nullptr);

    // Call cJSON_IsArray with NULL to cover the `if (item == NULL)` branch (line 2982).
    cJSON_IsArray(nullptr);

    // Added to cover cJSON_IsObject lines 2992-2994 (if item == NULL)
    cJSON_IsObject(nullptr);

    // Call cJSON_Duplicate with NULL to cover the `if (!item)` branch (line 2738).
    cJSON_Duplicate(nullptr, fdp.ConsumeBool());

    // Call cJSON_AddItemToArray with NULL item/array or array == item to cover branches (line 1979).
    UniqueCJSONPtr item_for_add = CreateFuzzedCjsonItem(fdp);
    UniqueCJSONPtr array_for_add = CreateFuzzedCjsonItem(fdp);
    if (item_for_add && array_for_add && cJSON_IsArray(array_for_add.get())) {
        // Case: item == NULL
        cJSON_AddItemToArray(array_for_add.get(), nullptr);
        // Case: array == NULL (covered by passing nullptr directly)
        cJSON_AddItemToArray(nullptr, item_for_add.get());
        // Case: array == item
        // This case is tricky with unique_ptr as cJSON_AddItemToArray takes ownership.
        // If array_for_add and item_for_add point to the same object,
        // and cJSON_AddItemToArray succeeds, it will try to manage the same memory twice.
        // It's safer to avoid this specific test case with unique_ptr unless cJSON guarantees
        // it handles self-referential additions gracefully without double-free.
        // For now, let's remove this potentially problematic line.
        // cJSON_AddItemToArray(item_for_add.get(), item_for_add.get());
    }

    // Call cJSON_AddItemToObject with NULL object/string/item or object == item to cover branches (line 2035).
    UniqueCJSONPtr item_for_add_obj = CreateFuzzedCjsonItem(fdp);
    UniqueCJSONPtr object_for_add_obj = CreateFuzzedCjsonItem(fdp);
    std::string key_for_add_obj = fdp.ConsumeRandomLengthString(10);
    if (item_for_add_obj && object_for_add_obj && cJSON_IsObject(object_for_add_obj.get())) {
        // Case: object == NULL
        cJSON_AddItemToObject(nullptr, key_for_add_obj.c_str(), item_for_add_obj.get());
        // Case: string == NULL
        cJSON_AddItemToObject(object_for_add_obj.get(), nullptr, item_for_add_obj.get());
        // Case: item == NULL
        cJSON_AddItemToObject(object_for_add_obj.get(), key_for_add_obj.c_str(), nullptr);
        // Case: object == item
        // Similar to cJSON_AddItemToArray, this can lead to double-free if not handled carefully by cJSON.
        // Removing for safety with unique_ptr.
        // cJSON_AddItemToObject(object_for_add_obj.get(), key_for_add_obj.c_str(), object_for_add_obj.get());
    }

    // Call cJSON_CreateString with a string that causes cJSON_strdup to return NULL (memory allocation failure).
    // This is hard to trigger reliably in fuzzing without custom hooks, but we can try with very large strings.
    // The existing fuzzer already uses ConsumeRandomLengthString, which can be large.
    // The 0-hit lines for cJSON_strdup (194-196, 201-203) are for NULL input or allocation failure.
    // We can explicitly pass NULL to cJSON_CreateString to hit the NULL input branch.
    cJSON_CreateString(nullptr);
    // Also for cJSON_CreateRaw
    cJSON_CreateRaw(nullptr);

    // To cover the `cJSON_Raw` case in `print_value` (lines 1421-1437),
    // we need to print a cJSON_Raw item. The existing fuzzer only prints `parsed_json_item`.
    // We will create a raw item and print it.
    UniqueCJSONPtr raw_item_to_print(cJSON_CreateRaw(fdp.ConsumeRandomLengthString(20).c_str()));
    if (raw_item_to_print) {
        int buffer_size = fdp.ConsumeIntegralInRange<int>(0, 1024);
        bool format = fdp.ConsumeBool();
        char* printed_string = cJSON_PrintBuffered(raw_item_to_print.get(), buffer_size, format);
        if (printed_string) {
            free(printed_string);
        }
    }

    // Added to cover cJSON_ParseWithLengthOpts lines 1114-1116 (value == NULL || 0 == buffer_length)
    // The `value == NULL` part is covered by cJSON_ParseWithOpts(nullptr, ...).
    // To cover `0 == buffer_length`, we explicitly call cJSON_ParseWithLengthOpts with a 0 length.
    cJSON_ParseWithLengthOpts(json_string.c_str(), 0, &return_parse_end, require_null_terminated);

    // Added to cover print_value lines 1385-1387 (item == NULL || output_buffer == NULL)
    // This is implicitly covered by cJSON_PrintBuffered(nullptr, ...) or if cJSON_PrintBuffered fails to allocate.
    // Explicitly calling with a null item to ensure coverage.
    char* dummy_printed_string = cJSON_PrintBuffered(nullptr, 10, false);
    if (dummy_printed_string) {
        free(dummy_printed_string);
    }

    // Added to cover print_value lines 1425-1427 (item->valuestring == NULL for cJSON_Raw)
    // Create a raw item and explicitly set its valuestring to NULL.
    // Since cJSON_New_Item is not a public API, we create a raw item and then manipulate it.
    // We must ensure proper memory management if we modify internal pointers.
    UniqueCJSONPtr raw_item_with_null_valuestring(cJSON_CreateRaw("dummy"));
    if (raw_item_with_null_valuestring) {
        // Free the string allocated by cJSON_CreateRaw before setting to NULL
        if (raw_item_with_null_valuestring->valuestring) {
            cJSON_free(raw_item_with_null_valuestring->valuestring);
            raw_item_with_null_valuestring->valuestring = nullptr; // Explicitly set to NULL
        }
        char* printed_string_null_raw = cJSON_PrintBuffered(raw_item_with_null_valuestring.get(), 10, false);
        if (printed_string_null_raw) {
            free(printed_string_null_raw);
        }
    }

    // Added to cover parse_string lines 804-807 (prevent buffer overflow when last input character is a backslash)
    // Input like "\"" or "\"abc\""
    UniqueCJSONPtr parsed_backslash_string(cJSON_ParseWithOpts("\"\\", nullptr, false));
    UniqueCJSONPtr parsed_incomplete_string(cJSON_ParseWithOpts("\"abc", nullptr, false));
    UniqueCJSONPtr parsed_invalid_escape(cJSON_ParseWithOpts("\"\\z\"", nullptr, false)); // Covers parse_string default case (line 878)

    // Added to cover utf16_literal_to_utf8 lines 671-674 (input ends unexpectedly)
    UniqueCJSONPtr parsed_incomplete_utf16(cJSON_ParseWithOpts("\"\\u123\"", nullptr, false));
    // Added to cover utf16_literal_to_utf8 lines 681-683 (invalid first surrogate)
    UniqueCJSONPtr parsed_invalid_first_surrogate(cJSON_ParseWithOpts("\"\\uDC00\"", nullptr, false));
    // Added to cover utf16_literal_to_utf8 lines 693-696 (second surrogate incomplete)
    UniqueCJSONPtr parsed_incomplete_second_surrogate(cJSON_ParseWithOpts("\"\\uD800\\u\"", nullptr, false));
    // Added to cover utf16_literal_to_utf8 lines 700-702 (missing second half of surrogate pair)
    UniqueCJSONPtr parsed_missing_second_half(cJSON_ParseWithOpts("\"\\uD800X\"", nullptr, false));
    // Added to cover utf16_literal_to_utf8 lines 708-711 (invalid second half of surrogate pair)
    UniqueCJSONPtr parsed_invalid_second_half(cJSON_ParseWithOpts("\"\\uD800\\uD7FF\"", nullptr, false));
    // Added to cover utf16_literal_to_utf8 lines 749-752 (invalid unicode codepoint)
    // This is hard to trigger directly as valid codepoints are generated.
    // The existing fuzzer's random string generation might eventually hit this with malformed inputs.

    // Added to cover parse_hex4 lines 644-646 (invalid hex digit)
    UniqueCJSONPtr parsed_invalid_hex(cJSON_ParseWithOpts("\"\\uGHIJ\"", nullptr, false));

    // Added to cover parse_number lines 357-359 (strtod failed to parse)
    UniqueCJSONPtr parsed_invalid_number_minus(cJSON_ParseWithOpts("-", nullptr, false));
    UniqueCJSONPtr parsed_invalid_number_dot(cJSON_ParseWithOpts(".", nullptr, false));

    // Added to cover parse_array lines 1466-1469 (not an array)
    UniqueCJSONPtr parsed_not_array(cJSON_ParseWithOpts("abc", nullptr, false));
    // Added to cover parse_array lines 1481-1484 (array ends unexpectedly)
    UniqueCJSONPtr parsed_incomplete_array(cJSON_ParseWithOpts("[ ", nullptr, false));
    // Added to cover parse_array lines 1524-1526 (expected end of array)
    UniqueCJSONPtr parsed_array_missing_bracket(cJSON_ParseWithOpts("[1,", nullptr, false));

    // Added to cover parse_object lines 1626-1628 (not an object)
    UniqueCJSONPtr parsed_not_object(cJSON_ParseWithOpts("abc", nullptr, false));
    // Added to cover parse_object lines 1639-1642 (object ends unexpectedly)
    UniqueCJSONPtr parsed_incomplete_object(cJSON_ParseWithOpts("{ ", nullptr, false));
    // Added to cover parse_object lines 1671-1673 (nothing comes after the comma)
    UniqueCJSONPtr parsed_object_trailing_comma(cJSON_ParseWithOpts("{\"a\":1,", nullptr, false));
    // Added to cover parse_object lines 1689-1691 (invalid object - missing colon)
    UniqueCJSONPtr parsed_object_missing_colon(cJSON_ParseWithOpts("{\"a\"1}", nullptr, false));
    // Added to cover parse_object lines 1705-1707 (expected end of object)
    UniqueCJSONPtr parsed_object_missing_bracket(cJSON_ParseWithOpts("{\"a\":1", nullptr, false));


    return 0;
}