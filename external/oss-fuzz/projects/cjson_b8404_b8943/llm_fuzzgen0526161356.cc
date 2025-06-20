#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // Required for std::unique_ptr
#include <utility> // Required for std::move
#include <fuzzer/FuzzedDataProvider.h>
#include <cmath> // Required for isnan, isinf

// Include the main cJSON header
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON objects to be used with std::unique_ptr.
struct CJSONDeleter {
    void operator()(cJSON* item) const {
        if (item) {
            cJSON_Delete(item);
        }
    }
};

// Forward declaration for a helper function to create fuzzed cJSON items.
std::unique_ptr<cJSON, CJSONDeleter> CreateFuzzedCjsonItem(FuzzedDataProvider& fdp) {
    // Use a switch to create different types of cJSON items
    // Added cJSON_Raw to the types to improve coverage for print_value's cJSON_Raw case.
    int type = fdp.ConsumeIntegralInRange<int>(0, 6); // 0: Null, 1: Bool, 2: Number, 3: String, 4: Array, 5: Object, 6: Raw

    cJSON* item = nullptr;
    switch (type) {
        case 0: // Null
            item = cJSON_CreateNull();
            break;
        case 1: // Bool
            item = cJSON_CreateBool(fdp.ConsumeBool());
            break;
        case 2: { // Number
            double num = fdp.ConsumeFloatingPoint<double>();
            // Added checks for NaN and Infinity to cover print_number's isnan/isinf branch.
            if (fdp.ConsumeBool()) {
                num = std::numeric_limits<double>::quiet_NaN();
            } else if (fdp.ConsumeBool()) {
                num = std::numeric_limits<double>::infinity();
            }
            item = cJSON_CreateNumber(num);
            break;
        }
        case 3: { // String
            // Added a chance to create a string with a null internal value to cover print_string_ptr's null input branch.
            if (fdp.ConsumeBool()) {
                item = cJSON_CreateString(nullptr);
            } else {
                item = cJSON_CreateString(fdp.ConsumeRandomLengthString(fdp.remaining_bytes()).c_str());
            }
            break;
        }
        case 4: { // Array
            item = cJSON_CreateArray();
            if (item) {
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 5); // Limit array size
                for (size_t i = 0; i < num_elements; ++i) {
                    // Recursively create sub-items, but limit depth to avoid stack overflow
                    if (fdp.remaining_bytes() > 10) { // Simple depth control
                        std::unique_ptr<cJSON, CJSONDeleter> sub_item = CreateFuzzedCjsonItem(fdp);
                        if (sub_item) {
                            // cJSON_AddItemToArray takes ownership.
                            // If 'item' is not an array, cJSON_AddItemToArray will do nothing,
                            // but it still takes ownership of 'sub_item' and will delete it when 'item' is deleted.
                            // So, we can unconditionally release here.
                            cJSON_AddItemToArray(item, sub_item.release());
                        }
                    }
                }
            }
            break;
        }
        case 5: { // Object
            item = cJSON_CreateObject();
            if (item) {
                size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 5); // Limit object size
                for (size_t i = 0; i < num_elements; ++i) {
                    std::string key = fdp.ConsumeRandomLengthString(10);
                    // Recursively create sub-items, but limit depth
                    if (fdp.remaining_bytes() > 10) { // Simple depth control
                        std::unique_ptr<cJSON, CJSONDeleter> sub_item = CreateFuzzedCjsonItem(fdp);
                        if (sub_item) {
                            // cJSON_AddItemToObject takes ownership.
                            // Similar to arrays, we can unconditionally release here.
                            cJSON_AddItemToObject(item, key.c_str(), sub_item.release());
                        }
                    }
                }
            }
            break;
        }
        case 6: { // Raw
            // Added cJSON_Raw type creation to cover print_value's cJSON_Raw case.
            std::string raw_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
            item = cJSON_CreateRaw(raw_string.c_str());
            break;
        }
    }
    return std::unique_ptr<cJSON, CJSONDeleter>(item);
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Exercise CJSONDeleter::operator() (0.0% coverage)
    // This is implicitly tested by using std::unique_ptr with CJSONDeleter.
    // When the unique_ptr goes out of scope, the deleter will be called.
    // We create a cJSON item and let unique_ptr manage its lifetime.
    std::unique_ptr<cJSON, CJSONDeleter> root_item = CreateFuzzedCjsonItem(fdp);

    // Ensure we have a valid root item for subsequent operations
    if (!root_item) {
        return 0;
    }

    // 2. Exercise unsigned char * print(const const cJSON *, cJSON_bool, const const internal_hooks *) (38.46% coverage)
    // This is a low-level internal print function. We can call it via cJSON_Print or cJSON_PrintUnformatted.
    // cJSON_Print and cJSON_PrintUnformatted internally call 'print'.
    // We'll use cJSON_Print and cJSON_PrintUnformatted to cover this.
    cJSON_bool formatted = fdp.ConsumeBool();
    char* printed_string = nullptr;
    if (formatted) {
        printed_string = cJSON_Print(root_item.get());
    } else {
        printed_string = cJSON_PrintUnformatted(root_item.get());
    }
    // Free the allocated string to prevent memory leaks
    if (printed_string) {
        cJSON_free(printed_string);
    }

    // 3. Exercise cJSON_bool replace_item_in_object(cJSON *, const char *, cJSON *, cJSON_bool) (47.05% coverage)
    // This function replaces an item in an object.
    if (root_item->type == cJSON_Object) {
        std::string key_to_replace = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
        std::unique_ptr<cJSON, CJSONDeleter> new_item_ptr = CreateFuzzedCjsonItem(fdp);

        if (new_item_ptr) {
            // cJSON_ReplaceItemInObject takes ownership of the new_item.
            // However, if cJSON_strdup fails internally when setting the key for new_item,
            // cJSON_ReplaceItemInObject returns false and does NOT delete new_item.
            // In this specific failure case, we must manually delete new_item.
            cJSON* raw_new_item = new_item_ptr.release(); // Transfer ownership to raw pointer
            if (!cJSON_ReplaceItemInObject(root_item.get(), key_to_replace.c_str(), raw_new_item)) {
                // If replacement/addition failed, and cJSON_ReplaceItemInObject did not take ownership
                // (e.g., due to internal cJSON_strdup failure), we must delete it.
                cJSON_Delete(raw_new_item);
            }
        }

        // Added to cover cJSON_ReplaceItemViaPointer's 'replacement == item' branch (lines 2323-2325).
        // This requires duplicating an existing item and attempting to replace it with itself.
        if (fdp.ConsumeBool() && root_item->child != nullptr) {
            cJSON* existing_item = root_item->child; // Get an existing item
            // Duplicate the existing item. cJSON_Duplicate allocates new memory.
            cJSON* duplicated_item = cJSON_Duplicate(existing_item, true);
            if (duplicated_item) {
                // Attempt to replace the existing item with its duplicate.
                // If existing_item and duplicated_item are the same pointer, it hits the branch.
                // This is not the case here, but we can try to replace an item with itself.
                // To hit 'replacement == item', we need to pass the same pointer for 'item' and 'replacement'.
                // Let's try to replace an item with itself.
                cJSON_ReplaceItemViaPointer(root_item.get(), existing_item, existing_item);
                cJSON_Delete(duplicated_item); // Clean up the duplicate
            }
        }
    }

    // 4. Exercise char * cJSON_PrintBuffered(const cJSON *, int, cJSON_bool) (54.16% coverage)
    // This function prints to a pre-allocated buffer.
    int buffer_size = fdp.ConsumeIntegralInRange<int>(0, 1024); // Vary buffer size
    char* buffer = (char*)cJSON_malloc(buffer_size + 1); // +1 for null terminator
    if (buffer) {
        cJSON_bool format_buffered = fdp.ConsumeBool();
        // cJSON_PrintPreallocated returns true on success, false on failure (e.g., buffer too small)
        cJSON_PrintPreallocated(root_item.get(), buffer, buffer_size, format_buffered);
        cJSON_free(buffer); // Free the buffer to prevent memory leaks
    }

    // Added to cover cJSON_PrintPreallocated's (length < 0) branch (lines 1309-1312).
    // Pass a negative buffer size.
    cJSON_PrintPreallocated(root_item.get(), nullptr, -1, fdp.ConsumeBool());
    // Added to cover cJSON_PrintPreallocated's (buffer == NULL) branch (lines 1309-1312).
    // Pass a null buffer.
    cJSON_PrintPreallocated(root_item.get(), nullptr, fdp.ConsumeIntegralInRange<int>(0, 1024), fdp.ConsumeBool());


    // 5. Exercise cJSON_bool cJSON_AddItemReferenceToObject(cJSON *, const char *, cJSON *) (57.14% coverage)
    // This function adds a reference to an existing item in an object.
    // It does NOT take ownership of the added item.
    if (root_item->type == cJSON_Object) {
        std::string ref_key = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
        // Create an item that will be referenced. This item must be managed separately.
        std::unique_ptr<cJSON, CJSONDeleter> referenced_item = CreateFuzzedCjsonItem(fdp);

        if (referenced_item) {
            // Add a reference. The referenced_item is NOT deleted by cJSON_AddItemReferenceToObject.
            // The return value of cJSON_AddItemReferenceToObject is cJSON_bool, indicating success.
            // If it returns false, the item was not added.
            cJSON_AddItemReferenceToObject(root_item.get(), ref_key.c_str(), referenced_item.get());
            // 'referenced_item' unique_ptr will ensure proper deletion when it goes out of scope.
        }

        // Added to cover cJSON_AddItemReferenceToObject's (object == NULL) or (string == NULL) branches (lines 2089-2092).
        // Call with null object.
        cJSON_AddItemReferenceToObject(nullptr, ref_key.c_str(), referenced_item.get());
        // Call with null string.
        cJSON_AddItemReferenceToObject(root_item.get(), nullptr, referenced_item.get());
    }

    // Added to cover get_object_item's case_sensitive branch (lines 1909-1914).
    // Call cJSON_GetObjectItemCaseSensitive.
    if (root_item->type == cJSON_Object) {
        std::string search_key = fdp.ConsumeRandomLengthString(10);
        cJSON* found_item = cJSON_GetObjectItemCaseSensitive(root_item.get(), search_key.c_str());
        // No need to delete found_item as it's a pointer to an existing item.
    }

    // Added to cover case_insensitive_strcmp's (string1 == NULL) or (string2 == NULL) branches (lines 136-138).
    // This is indirectly covered by calling cJSON_GetObjectItemCaseSensitive with a key that might not exist,
    // leading to internal comparisons with potentially null strings if cJSON's internal structure allows it.
    // However, to explicitly hit it, we would need to call the internal function directly, which is not exposed.
    // The existing fuzzer's use of cJSON_ReplaceItemInObject and cJSON_AddItemToObject already generates various string inputs.

    // The 'root_item' unique_ptr will automatically call CJSONDeleter::operator()
    // when it goes out of scope, ensuring proper memory deallocation for the main JSON object.

    return 0;
}