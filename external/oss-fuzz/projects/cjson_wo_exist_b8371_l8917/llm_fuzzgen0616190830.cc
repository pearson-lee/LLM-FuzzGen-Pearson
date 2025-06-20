#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr
#include <cstring> // For strlen, strcpy, memcpy
#include <cmath> // For isnan, isinf

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

// Custom deleter for char* returned by cJSON_Print and cJSON_strdup
struct CJSONCharDeleter {
    void operator()(char* str) const {
        if (str) {
            cJSON_free(str);
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Create a unique_ptr for cJSON objects to ensure automatic memory management
    // and prevent memory leaks.
    std::unique_ptr<cJSON, CJSONDeleter> root_object(cJSON_CreateObject());
    std::unique_ptr<cJSON, CJSONDeleter> root_array(cJSON_CreateArray());

    // Vector to manage dynamically allocated strings that cJSON might store pointers to.
    std::vector<std::unique_ptr<char, CJSONCharDeleter>> managed_strings;

    // Ensure root objects are created successfully before proceeding
    if (!root_object || !root_array) {
        return 0; // Not enough memory, or creation failed.
    }

    // Fuzzing cJSON_AddRawToObject
    {
        // Generate random strings for name and raw content
        std::string name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        std::string raw_json = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 256));

        // Call the target API
        // Memory for the raw_item created inside cJSON_AddRawToObject is managed by cJSON_Delete
        // when the root_object is deleted.
        // cJSON_AddRawToObject copies the raw_json, but not the name.
        // Looking at cJSON.c, cJSON_AddRawToObject calls cJSON_AddItemToObject, which copies the string.
        // So, name.c_str() is fine here.
        cJSON_AddRawToObject(root_object.get(), name_str.c_str(), raw_json.c_str());
    }

    // Fuzzing cJSON_AddItemReferenceToObject
    {
        // Generate a random name for the item reference
        std::string ref_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        // Create a dummy cJSON item to be referenced. This item will be deleted when its unique_ptr goes out of scope.
        std::unique_ptr<cJSON, CJSONDeleter> item_to_reference(cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str()));

        if (item_to_reference) {
            // Call the target API. The reference created by cJSON_AddItemReferenceToObject
            // is managed by the root_object.
            // cJSON_AddItemReferenceToObject does not take ownership of item_to_reference.
            // item_to_reference will be deleted by its unique_ptr when it goes out of scope.
            // cJSON_AddItemReferenceToObject calls cJSON_AddItemToObject, which copies the string.
            // So, ref_name_str.c_str() is fine here.
            cJSON_AddItemReferenceToObject(root_object.get(), ref_name_str.c_str(), item_to_reference.get());
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

    // --- Start of new modifications for coverage improvement ---

    // Fuzzing cJSON_Parse and related parsing functions
    {
        std::string json_string = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
        // Added call to cJSON_Parse to cover parsing logic.
        // The unique_ptr ensures the parsed cJSON object is deleted.
        std::unique_ptr<cJSON, CJSONDeleter> parsed_json(cJSON_Parse(json_string.c_str()));

        // Fuzzing cJSON_Print and related printing functions
        if (parsed_json) {
            // Added call to cJSON_Print to cover printing logic.
            // The unique_ptr with CJSONCharDeleter ensures the printed string is freed.
            std::unique_ptr<char, CJSONCharDeleter> printed_json_str(cJSON_Print(parsed_json.get()));

            // Fuzzing cJSON_Duplicate (recursive and non-recursive)
            // Added calls to cJSON_Duplicate to cover object duplication logic.
            // Memory for duplicated objects is managed by unique_ptr.
            std::unique_ptr<cJSON, CJSONDeleter> duplicated_json_recursive(cJSON_Duplicate(parsed_json.get(), true));
            std::unique_ptr<cJSON, CJSONDeleter> duplicated_json_non_recursive(cJSON_Duplicate(parsed_json.get(), false));
        }
        // Test cJSON_Duplicate with NULL input to cover the NULL check branch.
        std::unique_ptr<cJSON, CJSONDeleter> duplicated_null(cJSON_Duplicate(NULL, fdp.ConsumeBool()));
    }

    // Fuzzing cJSON_InitHooks
    {
        // Added call to cJSON_InitHooks(NULL) to cover the hook reset path.
        cJSON_InitHooks(NULL); // Resets to default malloc/free/realloc

        // Added call to cJSON_InitHooks with custom (but default) hooks
        // to cover the non-NULL hook setting path.
        cJSON_Hooks custom_hooks;
        custom_hooks.malloc_fn = malloc;
        custom_hooks.free_fn = free;
        cJSON_InitHooks(&custom_hooks);
    }

    // Fuzzing cJSON_Minify
    {
        std::string minify_input_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512));
        // Added call to cJSON_Minify to cover JSON minification logic.
        // Need a mutable copy of the string for cJSON_Minify.
        // Memory for the duplicated string is managed by unique_ptr with CJSONCharDeleter.
        std::unique_ptr<char, CJSONCharDeleter> minify_target(
            (char*)cJSON_malloc(minify_input_str.length() + 1)
        );

        if (minify_target) {
            strcpy(minify_target.get(), minify_input_str.c_str());
            cJSON_Minify(minify_target.get());
        }

        // Test cJSON_Minify with NULL input to cover the NULL check branch.
        cJSON_Minify(NULL);
    }

    // Fuzzing cJSON_SetNumberHelper
    {
        // Added call to cJSON_SetNumberHelper to cover number setting logic and its branches.
        std::unique_ptr<cJSON, CJSONDeleter> number_item(cJSON_CreateNumber(0));
        if (number_item) {
            double value = fdp.ConsumeFloatingPoint<double>();
            cJSON_SetNumberHelper(number_item.get(), value);
        }
    }

    // Fuzzing cJSON_SetValuestring
    {
        // Added call to cJSON_SetValuestring to cover string value setting logic and its branches.
        std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString("initial_string"));
        if (string_item) {
            std::string new_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));
            cJSON_SetValuestring(string_item.get(), new_value.c_str());
        }
        // Test with NULL object to cover the NULL check branch.
        cJSON_SetValuestring(NULL, "test");
        // Test with NULL valuestring to cover the NULL check branch.
        std::unique_ptr<cJSON, CJSONDeleter> null_string_item(cJSON_CreateString(""));
        if (null_string_item) {
            cJSON_SetValuestring(null_string_item.get(), NULL);
        }
    }

    // Fuzzing cJSON_GetArraySize and cJSON_GetArrayItem
    {
        // Added calls to cJSON_GetArraySize and cJSON_GetArrayItem to cover array accessors.
        int array_size = cJSON_GetArraySize(root_array.get());
        if (array_size > 0) {
            int index = fdp.ConsumeIntegralInRange<int>(0, array_size - 1);
            // cJSON_GetArrayItem returns a pointer to an existing item, not a new one.
            // No new memory is allocated, so unique_ptr is not needed for the return value.
            cJSON* item_from_array = cJSON_GetArrayItem(root_array.get(), index);
            (void)item_from_array; // Suppress unused variable warning
        }
        // Test with NULL array to cover the NULL check branch.
        cJSON_GetArraySize(NULL);
        cJSON_GetArrayItem(NULL, 0);
        // Test with negative index for cJSON_GetArrayItem
        cJSON_GetArrayItem(root_array.get(), -1);
    }

    // Fuzzing cJSON_GetObjectItem and cJSON_GetObjectItemCaseSensitive
    {
        // Added calls to cJSON_GetObjectItem and cJSON_GetObjectItemCaseSensitive to cover object accessors.
        std::string key_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        char* key_c_str = (char*)cJSON_malloc(key_str.length() + 1);
        if (key_c_str) {
            strcpy(key_c_str, key_str.c_str());
            cJSON* item_from_object = cJSON_GetObjectItem(root_object.get(), key_c_str);
            cJSON* item_from_object_cs = cJSON_GetObjectItemCaseSensitive(root_object.get(), key_c_str);
            (void)item_from_object; // Suppress unused variable warning
            (void)item_from_object_cs; // Suppress unused variable warning
            cJSON_free(key_c_str); // Free immediately as cJSON does not store this pointer
        }
        // Test with NULL object or NULL string to cover the NULL check branches.
        cJSON_GetObjectItem(NULL, key_str.c_str()); // Still use std::string for NULL tests
        cJSON_GetObjectItem(root_object.get(), NULL);
    }

    // Fuzzing cJSON_HasObjectItem
    {
        // Added call to cJSON_HasObjectItem to cover its logic.
        std::string key_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        char* key_c_str = (char*)cJSON_malloc(key_str.length() + 1);
        if (key_c_str) {
            strcpy(key_c_str, key_str.c_str());
            cJSON_HasObjectItem(root_object.get(), key_c_str);
            cJSON_free(key_c_str); // Free immediately
        }
    }

    // Fuzzing cJSON_AddItemToObjectCS
    {
        // Added call to cJSON_AddItemToObjectCS to cover case-sensitive item addition.
        std::string name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        char* name_c_str = (char*)cJSON_malloc(name_str.length() + 1);
        if (name_c_str) {
            strcpy(name_c_str, name_str.c_str());
            managed_strings.emplace_back(name_c_str); // Add to our managed list

            std::unique_ptr<cJSON, CJSONDeleter> item_to_add(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (item_to_add) {
                // Pass the raw pointer from our managed string
                cJSON_AddItemToObjectCS(root_object.get(), managed_strings.back().get(), item_to_add.release()); // Transfer ownership
            }
        }
    }

    // Fuzzing cJSON_AddItemReferenceToArray
    {
        // Added call to cJSON_AddItemReferenceToArray to cover array reference addition.
        std::unique_ptr<cJSON, CJSONDeleter> item_to_ref_array(cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str()));
        if (item_to_ref_array) {
            cJSON_AddItemReferenceToArray(root_array.get(), item_to_ref_array.get()); // Does not take ownership
        }
        // Test with NULL array to cover the NULL check branch.
        cJSON_AddItemReferenceToArray(NULL, item_to_ref_array.get());
    }

    // Fuzzing cJSON_Create*Reference functions
    {
        // Added calls to cJSON_CreateStringReference, cJSON_CreateObjectReference, cJSON_CreateArrayReference.
        // These functions create references, so the original item must outlive the reference.
        // The unique_ptr for original_string/object/array ensures their lifetime.
        std::string ref_string_val = fdp.ConsumeRandomLengthString(64);
        std::unique_ptr<cJSON, CJSONDeleter> original_string(cJSON_CreateString(ref_string_val.c_str()));
        if (original_string) {
            std::unique_ptr<cJSON, CJSONDeleter> string_ref(cJSON_CreateStringReference(ref_string_val.c_str()));
        }

        std::unique_ptr<cJSON, CJSONDeleter> original_object(cJSON_CreateObject());
        if (original_object) {
            std::unique_ptr<cJSON, CJSONDeleter> object_ref(cJSON_CreateObjectReference(original_object.get()));
        }

        std::unique_ptr<cJSON, CJSONDeleter> original_array(cJSON_CreateArray());
        if (original_array) {
            std::unique_ptr<cJSON, CJSONDeleter> array_ref(cJSON_CreateArrayReference(original_array.get()));
        }
    }

    // Fuzzing cJSON_Add*ToObject functions
    {
        // Added calls to various cJSON_Add*ToObject functions to cover their creation and addition logic.
        std::string obj_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 32));
        // These functions copy the string, so c_str() is fine.
        cJSON_AddNullToObject(root_object.get(), obj_name_str.c_str());
        cJSON_AddTrueToObject(root_object.get(), obj_name_str.c_str());
        cJSON_AddFalseToObject(root_object.get(), obj_name_str.c_str());
        cJSON_AddBoolToObject(root_object.get(), obj_name_str.c_str(), fdp.ConsumeBool());
        cJSON_AddNumberToObject(root_object.get(), obj_name_str.c_str(), fdp.ConsumeFloatingPoint<double>());
        cJSON_AddStringToObject(root_object.get(), obj_name_str.c_str(), fdp.ConsumeRandomLengthString(64).c_str());
        cJSON_AddRawToObject(root_object.get(), obj_name_str.c_str(), fdp.ConsumeRandomLengthString(64).c_str()); // Added this line
        cJSON_AddObjectToObject(root_object.get(), obj_name_str.c_str());
        cJSON_AddArrayToObject(root_object.get(), obj_name_str.c_str());
    }

    // Fuzzing cJSON_Detach/Delete functions
    {
        // Detach/Delete from array
        if (cJSON_GetArraySize(root_array.get()) > 0) {
            int index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(root_array.get()) - 1);
            if (fdp.ConsumeBool()) { // Randomly choose to detach or delete
                std::unique_ptr<cJSON, CJSONDeleter> detached_item_array(cJSON_DetachItemFromArray(root_array.get(), index));
            } else {
                cJSON_DeleteItemFromArray(root_array.get(), index);
            }
        }

        // Detach/Delete from object
        if (cJSON_GetArraySize(root_object.get()) > 0) {
            std::string key_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
            char* key = (char*)cJSON_malloc(key_str.length() + 1);
            if (key) {
                strcpy(key, key_str.c_str());

                bool case_sensitive = fdp.ConsumeBool();
                bool detach_op = fdp.ConsumeBool();

                if (detach_op) {
                    if (case_sensitive) {
                        std::unique_ptr<cJSON, CJSONDeleter> detached_item_object_cs(cJSON_DetachItemFromObjectCaseSensitive(root_object.get(), key));
                    } else {
                        std::unique_ptr<cJSON, CJSONDeleter> detached_item_object(cJSON_DetachItemFromObject(root_object.get(), key));
                    }
                } else {
                    if (case_sensitive) {
                        cJSON_DeleteItemFromObjectCaseSensitive(root_object.get(), key);
                    } else {
                        cJSON_DeleteItemFromObject(root_object.get(), key);
                    }
                }
                cJSON_free(key); // Free the allocated memory
            }
        }
        // Test cJSON_DetachItemViaPointer with NULL inputs to cover NULL check branches.
        cJSON_DetachItemViaPointer(NULL, NULL);
        cJSON_DetachItemViaPointer(root_object.get(), NULL);
    }

    // Fuzzing cJSON_ReplaceItemInObject and cJSON_ReplaceItemInObjectCaseSensitive
    {
        // Added calls to cJSON_ReplaceItemInObject and cJSON_ReplaceItemInObjectCaseSensitive.
        std::string key_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
        char* key = (char*)cJSON_malloc(key_str.length() + 1);
        if (key) {
            strcpy(key, key_str.c_str());

            std::unique_ptr<cJSON, CJSONDeleter> new_val_obj(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (new_val_obj) {
                cJSON* released_new_val = new_val_obj.release(); // Ownership transferred to cJSON_ReplaceItemInObject
                if (!cJSON_ReplaceItemInObject(root_object.get(), key, released_new_val)) {
                    cJSON_Delete(released_new_val); // If replacement failed, delete manually
                }
            }
            std::unique_ptr<cJSON, CJSONDeleter> new_val_obj_cs(cJSON_CreateBool(fdp.ConsumeBool()));
            if (new_val_obj_cs) {
                cJSON* released_new_val_cs = new_val_obj_cs.release(); // Ownership transferred
                if (!cJSON_ReplaceItemInObjectCaseSensitive(root_object.get(), key, released_new_val_cs)) {
                    cJSON_Delete(released_new_val_cs); // If replacement failed, delete manually
                }
            }
            cJSON_free(key); // Free the allocated memory
        }
    }

    // Fuzzing cJSON_CreateNull, cJSON_CreateTrue, cJSON_CreateFalse
    {
        // Added calls to cJSON_CreateNull, cJSON_CreateTrue, cJSON_CreateFalse to cover their creation logic.
        std::unique_ptr<cJSON, CJSONDeleter> null_item(cJSON_CreateNull());
        std::unique_ptr<cJSON, CJSONDeleter> true_item(cJSON_CreateTrue());
        std::unique_ptr<cJSON, CJSONDeleter> false_item(cJSON_CreateFalse());
    }

    // Fuzzing cJSON_Create*Array functions
    {
        // Added calls to cJSON_CreateIntArray, cJSON_CreateFloatArray, cJSON_CreateDoubleArray, cJSON_CreateStringArray.
        // Memory for created arrays is managed by unique_ptr.

        // cJSON_CreateIntArray
        std::vector<int> int_array_data;
        int num_ints = fdp.ConsumeIntegralInRange<int>(0, 10);
        for (int i = 0; i < num_ints; ++i) {
            int_array_data.push_back(fdp.ConsumeIntegral<int>());
        }
        std::unique_ptr<cJSON, CJSONDeleter> int_array(cJSON_CreateIntArray(int_array_data.data(), int_array_data.size()));

        // cJSON_CreateFloatArray
        std::vector<float> float_array_data;
        int num_floats = fdp.ConsumeIntegralInRange<int>(0, 10);
        for (int i = 0; i < num_floats; ++i) {
            float_array_data.push_back(fdp.ConsumeFloatingPoint<float>());
        }
        std::unique_ptr<cJSON, CJSONDeleter> float_array(cJSON_CreateFloatArray(float_array_data.data(), float_array_data.size()));

        // cJSON_CreateDoubleArray
        std::vector<double> double_array_data;
        int num_doubles = fdp.ConsumeIntegralInRange<int>(0, 10);
        for (int i = 0; i < num_doubles; ++i) {
            double_array_data.push_back(fdp.ConsumeFloatingPoint<double>());
        }
        std::unique_ptr<cJSON, CJSONDeleter> double_array(cJSON_CreateDoubleArray(double_array_data.data(), double_array_data.size()));

        // cJSON_CreateStringArray
        std::vector<std::string> string_array_data_str;
        int num_strings = fdp.ConsumeIntegralInRange<int>(0, 10);
        string_array_data_str.reserve(num_strings); // Reserve memory to prevent reallocations
        std::vector<const char*> string_array_data_c_str;
        string_array_data_c_str.reserve(num_strings); // Also reserve for the c_str pointers

        for (int i = 0; i < num_strings; ++i) {
            string_array_data_str.push_back(fdp.ConsumeRandomLengthString(32));
            string_array_data_c_str.push_back(string_array_data_str.back().c_str());
        }
        std::unique_ptr<cJSON, CJSONDeleter> string_array(cJSON_CreateStringArray(string_array_data_c_str.data(), string_array_data_c_str.size()));
    }

    // Fuzzing cJSON_Is* functions
    {
        // Added calls to cJSON_Is* functions to cover type checking logic.
        cJSON_IsInvalid(root_object.get());
        cJSON_IsFalse(root_object.get());
        cJSON_IsTrue(root_object.get());
        cJSON_IsBool(root_object.get());
        cJSON_IsNull(root_object.get());
        cJSON_IsNumber(root_object.get());
        cJSON_IsString(root_object.get());
        cJSON_IsArray(root_object.get());
        cJSON_IsObject(root_object.get());
        cJSON_IsRaw(root_object.get());

        // Test with NULL input to cover NULL check branches.
        cJSON_IsInvalid(NULL);
        cJSON_IsFalse(NULL);
        cJSON_IsTrue(NULL);
        cJSON_IsBool(NULL);
        cJSON_IsNull(NULL);
        cJSON_IsNumber(NULL);
        cJSON_IsString(NULL);
        cJSON_IsArray(NULL);
        cJSON_IsObject(NULL);
        cJSON_IsRaw(NULL);
    }

    // Fuzzing cJSON_Compare
    {
        // Added calls to cJSON_Compare to cover comparison logic.
        // Compare same objects
        cJSON_Compare(root_object.get(), root_object.get(), fdp.ConsumeBool());
        cJSON_Compare(root_array.get(), root_array.get(), fdp.ConsumeBool());

        // Compare different objects
        std::unique_ptr<cJSON, CJSONDeleter> obj1(cJSON_Parse("{\"a\":1}"));
        std::unique_ptr<cJSON, CJSONDeleter> obj2(cJSON_Parse("{\"b\":2}"));
        if (obj1 && obj2) {
            cJSON_Compare(obj1.get(), obj2.get(), fdp.ConsumeBool());
        }

        // Compare with NULL inputs to cover NULL check branches.
        cJSON_Compare(NULL, NULL, fdp.ConsumeBool());
        cJSON_Compare(root_object.get(), NULL, fdp.ConsumeBool());
        cJSON_Compare(NULL, root_object.get(), fdp.ConsumeBool());
    }

    // All cJSON objects created and added to root_object or root_array are automatically
    // cleaned up when root_object and root_array unique_ptrs go out of scope.
    // Any standalone cJSON objects created (like string_item) are also managed by unique_ptrs.

    return 0;
}