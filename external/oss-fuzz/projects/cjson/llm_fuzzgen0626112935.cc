#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>

// Include the cJSON header using the project-relative path
#include "/src/cjson/cJSON.h"

// Custom deleter for std::unique_ptr to use cJSON_Delete
struct CJSON_Deleter {
    void operator()(cJSON* ptr) const {
        if (ptr) {
            cJSON_Delete(ptr);
        }
    }
};

// Define unique_ptr for cJSON
using unique_cJSON_ptr = std::unique_ptr<cJSON, CJSON_Deleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a fuzzed value to determine which API or sequence to test
    uint8_t api_selector = fdp.ConsumeIntegral<uint8_t>();

    // Create some base cJSON objects/arrays to use as inputs for modification functions
    unique_cJSON_ptr base_object = nullptr;
    unique_cJSON_ptr base_array = nullptr;

    // Create a base object if there's enough data
    if (fdp.remaining_bytes() > 0) {
        std::string json_string = fdp.ConsumeRandomLengthString();
        if (!json_string.empty()) {
            base_object.reset(cJSON_Parse(json_string.c_str()));
        }
    }

    // Create a base array if there's enough data
    if (fdp.remaining_bytes() > 0) {
        std::string json_array_string = fdp.ConsumeRandomLengthString();
         // Attempt to parse as an array, might fail, which is fine for fuzzing
        if (!json_array_string.empty()) {
             unique_cJSON_ptr parsed_item(cJSON_Parse(json_array_string.c_str()));
             if (parsed_item && cJSON_IsArray(parsed_item.get())) {
                 base_array = std::move(parsed_item);
             }
        }
    }

    // If no base array was created from parsing, create an empty one
    if (!base_array) {
        base_array.reset(cJSON_CreateArray());
    }

     // If no base object was created from parsing, create an empty one
    if (!base_object) {
        base_object.reset(cJSON_CreateObject());
    }


    // Consume data for potential item creation
    unique_cJSON_ptr item_to_use = nullptr;
    if (fdp.remaining_bytes() > 0) {
        uint8_t item_type = fdp.ConsumeIntegral<uint8_t>();
        switch (item_type % 6) { // Limit item types for simplicity
            case 0: item_to_use.reset(cJSON_CreateNull()); break;
            case 1: item_to_use.reset(cJSON_CreateBool(fdp.ConsumeBool())); break;
            case 2: item_to_use.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>())); break;
            case 3: item_to_use.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str())); break;
            case 4: item_to_use.reset(cJSON_CreateArray()); break; // Create empty array
            case 5: item_to_use.reset(cJSON_CreateObject()); break; // Create empty object
        }
    }


    // Exercise selected low-coverage APIs
    switch (api_selector % 5) {
        case 0: {
            // cJSON_CreateDoubleArray (0% coverage)
            size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<double> numbers;
            for (size_t i = 0; i < count; ++i) {
                numbers.push_back(fdp.ConsumeFloatingPoint<double>());
            }
            unique_cJSON_ptr double_array(cJSON_CreateDoubleArray(numbers.data(), count));
            // double_array will be automatically deleted
            break;
        }
        case 1: {
            // cJSON_InsertItemInArray (0% coverage)
            if (base_array && item_to_use) {
                int index = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(base_array.get()) + 5); // Test out-of-bounds
                // cJSON_InsertItemInArray takes ownership of item_to_use on success
                cJSON_InsertItemInArray(base_array.get(), index, item_to_use.release());
            }
            break;
        }
        case 2: {
            // cJSON_DetachItemFromObject (0% coverage)
            if (base_object) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                unique_cJSON_ptr detached_item(cJSON_DetachItemFromObject(base_object.get(), key.c_str()));
                // detached_item will be automatically deleted if found and detached
            }
            break;
        }
        case 3: {
            // cJSON_ReplaceItemInObjectCaseSensitive (0% coverage)
            if (base_object && item_to_use) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                 // cJSON_ReplaceItemInObjectCaseSensitive takes ownership of item_to_use on success
                cJSON_ReplaceItemInObjectCaseSensitive(base_object.get(), key.c_str(), item_to_use.release());
            }
            break;
        }
        case 4: {
            // cJSON_Compare (low coverage)
            // Need two cJSON objects to compare. Use base_object and base_array, or create new ones.
            unique_cJSON_ptr obj1 = nullptr;
            unique_cJSON_ptr obj2 = nullptr;

            if (fdp.remaining_bytes() > 0) {
                 std::string json_string1 = fdp.ConsumeRandomLengthString();
                 if (!json_string1.empty()) {
                     obj1.reset(cJSON_Parse(json_string1.c_str()));
                 }
            }
             if (fdp.remaining_bytes() > 0) {
                 std::string json_string2 = fdp.ConsumeRandomLengthString();
                 if (!json_string2.empty()) {
                     obj2.reset(cJSON_Parse(json_string2.c_str()));
                 }
            }

            // If parsing failed, use the base objects or create simple ones
            if (!obj1) obj1 = std::move(base_object); // Transfer ownership
            if (!obj2) obj2 = std::move(base_array); // Transfer ownership (comparing object and array is valid)

            if (!obj1) obj1.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (!obj2) obj2.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str()));


            // Perform comparison
            if (obj1 && obj2) {
                 // The 'case_sensitive' flag is important for coverage
                cJSON_Compare(obj1.get(), obj2.get(), fdp.ConsumeBool());
            }

            // obj1 and obj2 are automatically deleted
            break;
        }
    }

    // base_object, base_array, and item_to_use (if not transferred) are automatically deleted by unique_ptr

    return 0;
}