#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// Include the cJSON header with its full project-relative path
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON pointers to use with std::unique_ptr
struct CJSONDeleter {
    void operator()(cJSON* obj) const {
        if (obj) {
            cJSON_Delete(obj);
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Create a unique_ptr for cJSON objects to ensure automatic memory management
    // and prevent memory leaks.
    std::unique_ptr<cJSON, CJSONDeleter> root_object(cJSON_CreateObject());
    std::unique_ptr<cJSON, CJSONDeleter> root_array(cJSON_CreateArray());

    // Ensure root objects are created successfully before proceeding
    if (!root_object || !root_array) {
        return 0; // Not enough memory, or creation failed.
    }

    // Fuzzing cJSON_AddRawToObject
    {
        // Generate random strings for name and raw content
        std::string name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        std::string raw_json = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 256));

        // Call the target API
        // Memory for the raw_item created inside cJSON_AddRawToObject is managed by cJSON_Delete
        // when the root_object is deleted.
        cJSON_AddRawToObject(root_object.get(), name.c_str(), raw_json.c_str());
    }

    // Fuzzing cJSON_AddItemReferenceToObject
    {
        // Generate a random name for the item reference
        std::string ref_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        // Create a dummy cJSON item to be referenced. This item will be deleted when its unique_ptr goes out of scope.
        std::unique_ptr<cJSON, CJSONDeleter> item_to_reference(cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str()));

        if (item_to_reference) {
            // Call the target API. The reference created by cJSON_AddItemReferenceToObject
            // is managed by the root_object.
            // cJSON_AddItemReferenceToObject does not take ownership of item_to_reference.
            // item_to_reference will be deleted by its unique_ptr when it goes out of scope.
            cJSON_AddItemReferenceToObject(root_object.get(), ref_name.c_str(), item_to_reference.get());
        }
    }

    // Fuzzing cJSON_ReplaceItemInArray
    {
        // Populate the array with some dummy items first
        int num_items = fdp.ConsumeIntegralInRange<int>(0, 10);
        for (int i = 0; i < num_items; ++i) {
            std::unique_ptr<cJSON, CJSONDeleter> dummy_item(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (dummy_item) {
                cJSON_AddItemToArray(root_array.get(), dummy_item.release()); // release ownership to cJSON
            }
        }

        // Generate a random index and a new item to replace with
        int which = fdp.ConsumeIntegral<int>(); // Can be negative or out of bounds to test error handling
        std::unique_ptr<cJSON, CJSONDeleter> new_item_replace(cJSON_CreateBool(fdp.ConsumeBool()));

        if (new_item_replace) {
            cJSON* released_item = new_item_replace.release(); // release ownership
            // Call the target API. The old item at 'which' will be deleted by cJSON_ReplaceItemInArray,
            // and released_item will be managed by root_array if successful.
            if (!cJSON_ReplaceItemInArray(root_array.get(), which, released_item)) {
                // If replacement failed, delete the item manually as ownership was not transferred.
                cJSON_Delete(released_item);
            }
        }
    }

    // Fuzzing cJSON_InsertItemInArray
    {
        // Generate a random index and a new item to insert
        int which = fdp.ConsumeIntegral<int>(); // Can be negative or out of bounds
        std::unique_ptr<cJSON, CJSONDeleter> new_item_insert(cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str()));

        if (new_item_insert) {
            cJSON* released_item = new_item_insert.release(); // release ownership
            // Call the target API. released_item will be managed by root_array if successful.
            if (!cJSON_InsertItemInArray(root_array.get(), which, released_item)) {
                // If insertion failed, delete the item manually as ownership was not transferred.
                cJSON_Delete(released_item);
            }
        }
    }

    // Fuzzing cJSON_CreateString
    {
        // Generate a random string to create a new string item from
        std::string string_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));

        // Call the target API. The created cJSON object needs to be explicitly deleted.
        // The unique_ptr ensures that the created cJSON object is deleted when it goes out of scope.
        std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString(string_value.c_str()));
    }

    // All cJSON objects created and added to root_object or root_array are automatically
    // cleaned up when root_object and root_array unique_ptrs go out of scope.
    // Any standalone cJSON objects created (like string_item) are also managed by unique_ptrs.

    return 0;
}