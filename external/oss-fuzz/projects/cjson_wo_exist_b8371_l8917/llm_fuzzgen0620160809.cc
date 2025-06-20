#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Custom deleter for unique_ptr to handle cJSON objects
struct cJSONDeleter {
    void operator()(cJSON* ptr) const {
        cJSON_Delete(ptr);
    }
};

using cJSONUniquePtr = std::unique_ptr<cJSON, cJSONDeleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Target: cJSON_ParseWithOpts to cover NULL value case
    // The existing fuzzer does not pass NULL to cJSON_ParseWithOpts.
    if (fdp.ConsumeBool()) {
        cJSON_ParseWithOpts(NULL, NULL, fdp.ConsumeBool());
    }

    std::string json_string = fdp.ConsumeRandomLengthString(1000);
    cJSONUniquePtr root(cJSON_Parse(json_string.c_str()));

    if (root) {
        // Target: cJSON_AddRawToObject to cover the error path where add_item_to_object fails.
        // This happens if we try to add an object to itself.
        std::string raw_string = fdp.ConsumeRandomLengthString(100);
        cJSON_AddRawToObject(root.get(), "raw_data", raw_string.c_str());

        // Create an object to add to itself to trigger the error path.
        cJSON* item_to_add = cJSON_CreateObject();
        if (item_to_add) {
            // This call to add_item_to_object inside cJSON_AddItemToObject will fail
            // because 'item_to_add' is being added to itself.
            cJSON_AddItemToObject(item_to_add, "self", item_to_add);
        }
        // No need to delete item_to_add if it was successfully added, but here it won't be.
        cJSON_Delete(item_to_add);


        // Target: cJSON_CreateStringArray to cover allocation paths.
        const int num_strings = fdp.ConsumeIntegralInRange<int>(1, 20);
        std::vector<const char*> string_pointers;
        std::vector<std::string> string_storage;
        string_storage.reserve(num_strings);
        for (int i = 0; i < num_strings; ++i) {
            string_storage.push_back(fdp.ConsumeRandomLengthString(50));
            string_pointers.push_back(string_storage.back().c_str());
        }
        cJSONUniquePtr string_array(cJSON_CreateStringArray(string_pointers.data(), num_strings));

        if (string_array) {
            // Target: cJSON_Duplicate to cover more complex object duplication.
            cJSONUniquePtr duplicated_array(cJSON_Duplicate(string_array.get(), fdp.ConsumeBool()));

            if (duplicated_array) {
                // Target: cJSON_PrintBuffered to exercise the 'ensure' function's reallocation logic.
                // Using a small initial buffer size is more likely to trigger reallocations.
                unsigned int buffer_size = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
                char* printed_json = cJSON_PrintBuffered(duplicated_array.get(), buffer_size, fdp.ConsumeBool());
                if (printed_json) {
                    // IMPORTANT: The buffer allocated by cJSON_PrintBuffered must be freed with cJSON_free.
                    cJSON_free(printed_json);
                }
            }
        }
    }

    return 0;
}