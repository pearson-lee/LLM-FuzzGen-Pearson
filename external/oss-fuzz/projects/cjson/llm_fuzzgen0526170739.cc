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

    // 2. cJSON_PrintBuffered: Resource management and output formatting.
    if (parsed_json_item) {
        int buffer_size = fdp.ConsumeIntegralInRange<int>(0, 1024);
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

    return 0;
}