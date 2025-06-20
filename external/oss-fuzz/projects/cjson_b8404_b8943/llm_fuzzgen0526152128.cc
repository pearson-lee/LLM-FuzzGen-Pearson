#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr

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

    // Consume data for cJSON_Parse and cJSON_ParseWithLength
    std::string json_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
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
        // Fuzz cJSON_AddNumberToObject
        std::string key_add = fdp.ConsumeRandomLengthString(32);
        double value_add = fdp.ConsumeFloatingPoint<double>();
        // cJSON_AddNumberToObject creates a new cJSON object and adds it to parsed_json.
        // The ownership of the newly created object is transferred to parsed_json.
        // No explicit deletion is needed for the added item.
        cJSON_AddNumberToObject(parsed_json.get(), key_add.c_str(), value_add);

        // Fuzz cJSON_ReplaceItemInObjectCaseSensitive
        if (parsed_json->type == cJSON_Object) {
            std::string key_replace = fdp.ConsumeRandomLengthString(32);
            // Create a new cJSON item to replace with
            std::unique_ptr<cJSON, CJSONDeleter> new_item(cJSON_CreateString(fdp.ConsumeRandomLengthString(64).c_str()));
            if (new_item) {
                // cJSON_ReplaceItemInObjectCaseSensitive takes ownership of new_item
                // if the replacement is successful. If it fails, new_item is not
                // added to parsed_json, and its ownership remains with unique_ptr.
                // Therefore, we only release ownership if the call is successful.
                if (cJSON_ReplaceItemInObjectCaseSensitive(parsed_json.get(), key_replace.c_str(), new_item.get())) {
                    new_item.release(); // Release ownership to cJSON
                }
            }
        }

        // Fuzz cJSON_PrintPreallocated
        // Allocate a buffer for printing
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096); // Fuzz buffer size
        std::vector<char> print_buffer(buffer_size);
        cJSON_bool format = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

        cJSON_PrintPreallocated(parsed_json.get(), print_buffer.data(), static_cast<int>(buffer_size), format);
    }

    // All cJSON objects are managed by unique_ptr and will be automatically deleted.
    return 0;
}