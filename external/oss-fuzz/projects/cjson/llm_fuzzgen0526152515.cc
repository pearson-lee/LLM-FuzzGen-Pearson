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

        // Fuzz cJSON_PrintPreallocated (existing)
        // Allocate a buffer for printing
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096); // Fuzz buffer size
        std::vector<char> print_buffer(buffer_size);
        cJSON_bool format = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

        cJSON_PrintPreallocated(parsed_json.get(), print_buffer.data(), static_cast<int>(buffer_size), format);
    }

    // All cJSON objects are managed by unique_ptr and will be automatically deleted.
    return 0;
}