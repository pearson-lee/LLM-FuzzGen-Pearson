#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdint> // For uint8_t, size_t

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON objects to use with std::unique_ptr
struct CJSONDeleter {
    void operator()(cJSON* json) const {
        if (json) {
            cJSON_Delete(json);
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Declare all string variables at the beginning to ensure their lifetime
    std::string json_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
    std::string key_add_num = fdp.ConsumeRandomLengthString(32);
    std::string key_replace = fdp.ConsumeRandomLengthString(32);
    std::string new_item_string = fdp.ConsumeRandomLengthString(64); // For cJSON_ReplaceItemInObjectCaseSensitive
    std::string key_add_str = fdp.ConsumeRandomLengthString(32);
    std::string value_add_str = fdp.ConsumeRandomLengthString(64);
    std::string key_add_bool = fdp.ConsumeRandomLengthString(32);
    std::string key_add_null = fdp.ConsumeRandomLengthString(32);
    std::string key_add_array = fdp.ConsumeRandomLengthString(32);
    std::string key_add_object = fdp.ConsumeRandomLengthString(32);
    std::string key_add_raw = fdp.ConsumeRandomLengthString(32);
    std::string value_add_raw = fdp.ConsumeRandomLengthString(64);
    std::string key_add_item_to_obj = fdp.ConsumeRandomLengthString(32);
    std::string key_delete = fdp.ConsumeRandomLengthString(32);
    std::string key_detach = fdp.ConsumeRandomLengthString(32);
    std::string key_get = fdp.ConsumeRandomLengthString(32);
    std::string key_has = fdp.ConsumeRandomLengthString(32);
    std::string new_valuestring = fdp.ConsumeRandomLengthString(64);
    std::string json_to_minify_str = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);

    // New string variables for newly added functions
    std::string key_add_item_ref_to_obj = fdp.ConsumeRandomLengthString(32); // Added for cJSON_AddItemReferenceToObject
    std::vector<std::string> string_array_elements; // Added for cJSON_CreateStringArray
    std::vector<double> double_array_elements; // Added for cJSON_CreateDoubleArray
    std::vector<float> float_array_elements; // Added for cJSON_CreateFloatArray
    std::vector<int> int_array_elements; // Added for cJSON_CreateIntArray


    const char* json_cstr = json_string.c_str();
    size_t json_len = json_string.length();

    // Fuzz cJSON_Parse and cJSON_ParseWithLength
    // Use unique_ptr for automatic memory management
    std::unique_ptr<cJSON, CJSONDeleter> parsed_json;

    // Choose between cJSON_Parse and cJSON_ParseWithLength
    if (fdp.ConsumeBool()) {
        parsed_json.reset(cJSON_Parse(json_cstr));
    } else {
        parsed_json.reset(cJSON_ParseWithLength(json_cstr, json_len));
    }

    if (parsed_json) {
        // Fuzz cJSON_AddNumberToObject (existing)
        double value_add_num = fdp.ConsumeFloatingPoint<double>();
        cJSON_AddNumberToObject(parsed_json.get(), key_add_num.c_str(), value_add_num);

        // Fuzz cJSON_ReplaceItemInObjectCaseSensitive (existing)
        if (parsed_json->type == cJSON_Object) {
            std::unique_ptr<cJSON, CJSONDeleter> new_item(cJSON_CreateString(new_item_string.c_str()));
            if (new_item) {
                if (cJSON_ReplaceItemInObjectCaseSensitive(parsed_json.get(), key_replace.c_str(), new_item.get())) {
                    new_item.release(); // Release ownership to cJSON
                }
            }

            // --- New additions for coverage ---

            // Fuzz cJSON_AddStringToObject
            cJSON_AddStringToObject(parsed_json.get(), key_add_str.c_str(), value_add_str.c_str()); // Added call to uncovered function based on coverage report.

            // Fuzz cJSON_AddBoolToObject, cJSON_AddTrueToObject, cJSON_AddFalseToObject
            if (fdp.ConsumeBool()) {
                cJSON_AddBoolToObject(parsed_json.get(), key_add_bool.c_str(), fdp.ConsumeBool() ? cJSON_True : cJSON_False); // Added call to uncovered function.
            } else {
                if (fdp.ConsumeBool()) {
                    cJSON_AddTrueToObject(parsed_json.get(), key_add_bool.c_str()); // Added call to uncovered function.
                } else {
                    cJSON_AddFalseToObject(parsed_json.get(), key_add_bool.c_str()); // Added call to uncovered function.
                }
            }

            // Fuzz cJSON_AddNullToObject
            cJSON_AddNullToObject(parsed_json.get(), key_add_null.c_str()); // Added call to uncovered function.

            // Fuzz cJSON_AddArrayToObject
            cJSON_AddArrayToObject(parsed_json.get(), key_add_array.c_str()); // Added call to uncovered function.

            // Fuzz cJSON_AddObjectToObject
            cJSON_AddObjectToObject(parsed_json.get(), key_add_object.c_str()); // Added call to uncovered function.

            // Fuzz cJSON_AddRawToObject
            cJSON_AddRawToObject(parsed_json.get(), key_add_raw.c_str(), value_add_raw.c_str()); // Added call to uncovered function.

            // Fuzz cJSON_AddItemToObject and cJSON_AddItemToObjectCS
            std::unique_ptr<cJSON, CJSONDeleter> item_to_add_to_obj(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (item_to_add_to_obj) {
                if (fdp.ConsumeBool()) {
                    if (cJSON_AddItemToObject(parsed_json.get(), key_add_item_to_obj.c_str(), item_to_add_to_obj.get())) { // Added call to uncovered function. Ownership transferred to parsed_json.
                        item_to_add_to_obj.release();
                    }
                } else {
                    if (cJSON_AddItemToObjectCS(parsed_json.get(), key_add_item_to_obj.c_str(), item_to_add_to_obj.get())) { // Added call to uncovered function. Ownership transferred to parsed_json.
                        item_to_add_to_obj.release();
                    }
                }
            }

            // Fuzz cJSON_AddItemReferenceToObject
            std::unique_ptr<cJSON, CJSONDeleter> item_to_ref_to_obj(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (item_to_ref_to_obj) {
                // cJSON_AddItemReferenceToObject does not take ownership, so no release() call needed.
                cJSON_AddItemReferenceToObject(parsed_json.get(), key_add_item_ref_to_obj.c_str(), item_to_ref_to_obj.get()); // Added call to uncovered function.
            }


            // Fuzz cJSON_DeleteItemFromObject and cJSON_DeleteItemFromObjectCaseSensitive
            if (fdp.ConsumeBool()) {
                cJSON_DeleteItemFromObject(parsed_json.get(), key_delete.c_str()); // Added call to uncovered function.
            } else {
                cJSON_DeleteItemFromObjectCaseSensitive(parsed_json.get(), key_delete.c_str()); // Added call to uncovered function.
            }

            // Fuzz cJSON_DetachItemFromObject and cJSON_DetachItemFromObjectCaseSensitive
            std::unique_ptr<cJSON, CJSONDeleter> detached_item; // Manages the detached item.
            if (fdp.ConsumeBool()) {
                detached_item.reset(cJSON_DetachItemFromObject(parsed_json.get(), key_detach.c_str())); // Added call to uncovered function.
            } else {
                detached_item.reset(cJSON_DetachItemFromObjectCaseSensitive(parsed_json.get(), key_detach.c_str())); // Added call to uncovered function.
            }
            // detached_item will be automatically deleted by unique_ptr when it goes out of scope.

            // Fuzz cJSON_GetObjectItem and cJSON_GetObjectItemCaseSensitive
            cJSON* got_item = nullptr;
            if (fdp.ConsumeBool()) {
                got_item = cJSON_GetObjectItem(parsed_json.get(), key_get.c_str()); // Added call to uncovered function. No ownership transfer.
            } else {
                got_item = cJSON_GetObjectItemCaseSensitive(parsed_json.get(), key_get.c_str()); // Added call to uncovered function. No ownership transfer.
            }
            (void)got_item; // Suppress unused variable warning

            // Fuzz cJSON_HasObjectItem
            cJSON_HasObjectItem(parsed_json.get(), key_has.c_str()); // Added call to uncovered function.

            // Fuzz cJSON_ReplaceItemInObject
            std::unique_ptr<cJSON, CJSONDeleter> replace_item_in_obj(cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str()));
            if (replace_item_in_obj) {
                // cJSON_ReplaceItemInObject takes ownership, so release() is called on success.
                if (cJSON_ReplaceItemInObject(parsed_json.get(), key_replace.c_str(), replace_item_in_obj.get())) { // Added call to uncovered function.
                    replace_item_in_obj.release();
                }
            }
        }

        // Fuzz cJSON_Duplicate
        std::unique_ptr<cJSON, CJSONDeleter> duplicated_json(cJSON_Duplicate(parsed_json.get(), fdp.ConsumeBool() ? cJSON_True : cJSON_False)); // Added call to uncovered function. Managed by unique_ptr.

        // Fuzz cJSON_Compare
        if (duplicated_json) {
            cJSON_Compare(parsed_json.get(), duplicated_json.get(), fdp.ConsumeBool() ? cJSON_True : cJSON_False); // Added call to uncovered function.
        }

        // Fuzz cJSON_GetArraySize and cJSON_GetArrayItem
        if (parsed_json->type == cJSON_Array) {
            int array_size = cJSON_GetArraySize(parsed_json.get()); // Added call to partially covered function (53.33%).
            if (array_size > 0) {
                int index = fdp.ConsumeIntegralInRange<int>(0, array_size - 1);
                cJSON* array_item = cJSON_GetArrayItem(parsed_json.get(), index); // Added call to uncovered function. No ownership transfer.
                (void)array_item; // Suppress unused variable warning
            }

            // Fuzz cJSON_AddItemToArray
            std::unique_ptr<cJSON, CJSONDeleter> item_to_add_to_array(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (item_to_add_to_array) {
                if (cJSON_AddItemToArray(parsed_json.get(), item_to_add_to_array.get())) { // Added call to partially covered function (86.95%). Ownership transferred to parsed_json.
                    item_to_add_to_array.release();
                }
            }

            // Fuzz cJSON_InsertItemInArray
            std::unique_ptr<cJSON, CJSONDeleter> item_to_insert_in_array(cJSON_CreateString(fdp.ConsumeRandomLengthString(32).c_str()));
            if (item_to_insert_in_array) {
                int insert_index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(parsed_json.get()));
                if (cJSON_InsertItemInArray(parsed_json.get(), insert_index, item_to_insert_in_array.get())) { // Added call to uncovered function. Ownership transferred to parsed_json.
                    item_to_insert_in_array.release();
                }
            }

            // Fuzz cJSON_ReplaceItemInArray
            std::unique_ptr<cJSON, CJSONDeleter> item_to_replace_in_array(cJSON_CreateBool(fdp.ConsumeBool()));
            if (item_to_replace_in_array) {
                // Ensure index is valid for replacement
                int replace_index = 0;
                if (cJSON_GetArraySize(parsed_json.get()) > 0) {
                    replace_index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(parsed_json.get()) - 1);
                }
                if (cJSON_ReplaceItemInArray(parsed_json.get(), replace_index, item_to_replace_in_array.get())) { // Added call to uncovered function. Ownership transferred to parsed_json.
                    item_to_replace_in_array.release();
                }
            }

            // Fuzz cJSON_DeleteItemFromArray
            if (cJSON_GetArraySize(parsed_json.get()) > 0) {
                int delete_index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(parsed_json.get()) - 1);
                cJSON_DeleteItemFromArray(parsed_json.get(), delete_index); // Added call to uncovered function.
            }

            // Fuzz cJSON_DetachItemFromArray
            if (cJSON_GetArraySize(parsed_json.get()) > 0) {
                int detach_index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(parsed_json.get()) - 1);
                std::unique_ptr<cJSON, CJSONDeleter> detached_array_item(cJSON_DetachItemFromArray(parsed_json.get(), detach_index)); // Added call to uncovered function. Managed by unique_ptr.
            }

            // Fuzz cJSON_AddItemReferenceToArray
            std::unique_ptr<cJSON, CJSONDeleter> item_to_ref_to_array(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (item_to_ref_to_array) {
                // cJSON_AddItemReferenceToArray does not take ownership, so no release() call needed.
                cJSON_AddItemReferenceToArray(parsed_json.get(), item_to_ref_to_array.get()); // Added call to partially covered function.
            }
        }

        // Fuzz cJSON_SetValuestring
        if (parsed_json->type == cJSON_String) {
            cJSON_SetValuestring(parsed_json.get(), new_valuestring.c_str()); // Added call to uncovered function.
        }

        // Fuzz cJSON_Is* functions (simple checks)
        cJSON_IsRaw(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsObject(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsArray(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsNull(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsBool(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsTrue(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsFalse(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsInvalid(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsNumber(parsed_json.get()); // Added call to uncovered function.
        cJSON_IsString(parsed_json.get()); // Added call to uncovered function.

        // Fuzz cJSON_Version
        (void)cJSON_Version(); // Added call to uncovered function.

        // Fuzz cJSON_GetErrorPtr
        (void)cJSON_GetErrorPtr(); // Added call to uncovered function.

        // Fuzz cJSON_Minify
        // Create a mutable copy of a fuzzed string for cJSON_Minify, ensuring null-termination.
        if (!json_to_minify_str.empty()) {
            std::vector<char> minify_buffer(json_to_minify_str.begin(), json_to_minify_str.end());
            minify_buffer.push_back('\0'); // Null-terminate the buffer.
            cJSON_Minify(minify_buffer.data()); // Added call to partially covered function (92.3%).
        }

        // Fuzz cJSON_PrintBuffered
        // cJSON_PrintBuffered allocates memory internally that needs to be freed.
        char* printed_buffer = cJSON_PrintBuffered(parsed_json.get(), fdp.ConsumeIntegralInRange<int>(1, 4096), fdp.ConsumeBool() ? cJSON_True : cJSON_False);
        if (printed_buffer) {
            cJSON_free(printed_buffer); // Free the buffer allocated by cJSON_PrintBuffered
        }

        // Fuzz cJSON_PrintPreallocated (existing)
        // Allocate a buffer for printing
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096); // Fuzz buffer size
        std::vector<char> print_buffer(buffer_size);
        cJSON_bool format = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

        cJSON_PrintPreallocated(parsed_json.get(), print_buffer.data(), static_cast<int>(buffer_size), format);

        // Fuzz cJSON_CreateStringReference, cJSON_CreateArrayReference, cJSON_CreateObjectReference
        std::unique_ptr<cJSON, CJSONDeleter> string_ref(cJSON_CreateStringReference(new_valuestring.c_str())); // Added call to uncovered function.
        std::unique_ptr<cJSON, CJSONDeleter> array_ref(cJSON_CreateArrayReference(parsed_json.get())); // Added call to uncovered function.
        std::unique_ptr<cJSON, CJSONDeleter> object_ref(cJSON_CreateObjectReference(parsed_json.get())); // Added call to uncovered function.

        // Fuzz cJSON_CreateStringArray, cJSON_CreateDoubleArray, cJSON_CreateFloatArray, cJSON_CreateIntArray
        // Populate string_array_elements
        int num_string_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
        string_array_elements.reserve(num_string_elements);
        std::vector<const char*> c_string_array_elements;
        for (int i = 0; i < num_string_elements; ++i) {
            string_array_elements.push_back(fdp.ConsumeRandomLengthString(32));
            c_string_array_elements.push_back(string_array_elements.back().c_str());
        }
        std::unique_ptr<cJSON, CJSONDeleter> string_array(cJSON_CreateStringArray(c_string_array_elements.data(), c_string_array_elements.size())); // Added call to uncovered function.

        // Populate double_array_elements
        int num_double_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
        double_array_elements.reserve(num_double_elements);
        for (int i = 0; i < num_double_elements; ++i) {
            double_array_elements.push_back(fdp.ConsumeFloatingPoint<double>());
        }
        std::unique_ptr<cJSON, CJSONDeleter> double_array(cJSON_CreateDoubleArray(double_array_elements.data(), double_array_elements.size())); // Added call to uncovered function.

        // Populate float_array_elements
        int num_float_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
        float_array_elements.reserve(num_float_elements);
        for (int i = 0; i < num_float_elements; ++i) {
            float_array_elements.push_back(fdp.ConsumeFloatingPoint<float>());
        }
        std::unique_ptr<cJSON, CJSONDeleter> float_array(cJSON_CreateFloatArray(float_array_elements.data(), float_array_elements.size())); // Added call to uncovered function.

        // Populate int_array_elements
        int num_int_elements = fdp.ConsumeIntegralInRange<int>(0, 10);
        int_array_elements.reserve(num_int_elements);
        for (int i = 0; i < num_int_elements; ++i) {
            int_array_elements.push_back(fdp.ConsumeIntegral<int>());
        }
        std::unique_ptr<cJSON, CJSONDeleter> int_array(cJSON_CreateIntArray(int_array_elements.data(), int_array_elements.size())); // Added call to uncovered function.

        // Fuzz cJSON_GetNumberValue and cJSON_GetStringValue
        if (parsed_json->type == cJSON_Number) {
            (void)cJSON_GetNumberValue(parsed_json.get()); // Added call to uncovered function.
        }
        if (parsed_json->type == cJSON_String) {
            (void)cJSON_GetStringValue(parsed_json.get()); // Added call to uncovered function.
        }

        // Fuzz cJSON_SetNumberHelper (internal, but exposed)
        if (parsed_json->type == cJSON_Number) {
            cJSON_SetNumberHelper(parsed_json.get(), fdp.ConsumeFloatingPoint<double>()); // Added call to uncovered function.
        }

        // Fuzz cJSON_malloc (internal, but exposed)
        size_t malloc_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
        void* allocated_mem = cJSON_malloc(malloc_size); // Added call to uncovered function.
        if (allocated_mem) {
            // Free the allocated memory to prevent leaks.
            cJSON_free(allocated_mem); // cJSON_free is used to deallocate memory allocated by cJSON_malloc.
        }

        // Fuzz cJSON_InitHooks (requires custom hooks, which is complex for fuzzing, skipping for now)
        // cJSON_InitHooks is typically used for custom memory allocation, which is outside the scope of simple coverage improvement.
        // It's also a global state modification, which should be minimized.
        // To cover the `cJSON_InitHooks` function, we need to provide a `cJSON_Hooks` struct.
        // This involves setting up custom allocate and deallocate functions.
        // For fuzzing, it's generally better to avoid modifying global state or custom memory allocators
        // unless specifically targeting those functionalities, as it can complicate memory tracking and
        // introduce non-determinism. Given the objective of "minimal, strategic, and memory-safe modifications
        // specifically aimed at improving code coverage," and the fact that `cJSON_InitHooks` is often
        // used for global configuration rather than per-fuzz-input operations, we will skip it for now.
        // If deeper coverage of memory allocation paths within cJSON were a primary goal,
        // a more complex setup involving custom hooks and careful memory management would be required.
    }

    // All cJSON objects are managed by unique_ptr and will be automatically deleted.
    return 0;
}