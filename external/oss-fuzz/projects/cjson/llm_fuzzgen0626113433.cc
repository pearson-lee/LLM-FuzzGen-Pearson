#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cmath>  // For fabs, HUGE_VAL
#include <limits> // For std::numeric_limits
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

// Helper function to create a cJSON item based on fuzzed data
unique_cJSON_ptr CreateFuzzedCJSONItem(FuzzedDataProvider& fdp) {
    if (fdp.remaining_bytes() == 0) {
        return nullptr;
    }
    uint8_t item_type = fdp.ConsumeIntegral<uint8_t>();
    switch (item_type % 8) { // Increased types to include Array/Object creation
        case 0: return unique_cJSON_ptr(cJSON_CreateNull());
        case 1: return unique_cJSON_ptr(cJSON_CreateBool(fdp.ConsumeBool()));
        case 2: return unique_cJSON_ptr(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
        case 3: return unique_cJSON_ptr(cJSON_CreateString(fdp.ConsumeRandomLengthString().c_str()));
        case 4: return unique_cJSON_ptr(cJSON_CreateArray()); // Create empty array
        case 5: return unique_cJSON_ptr(cJSON_CreateObject()); // Create empty object
        case 6: { // Create a small fuzzed array
            unique_cJSON_ptr array = unique_cJSON_ptr(cJSON_CreateArray());
            if (array) {
                size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                for (size_t i = 0; i < count; ++i) {
                    unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                    if (child) {
                        cJSON_AddItemToArray(array.get(), child.release()); // Transfer ownership
                    }
                }
            }
            return array;
        }
        case 7: { // Create a small fuzzed object
             unique_cJSON_ptr object = unique_cJSON_ptr(cJSON_CreateObject());
             if (object) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     std::string key = fdp.ConsumeRandomLengthString(10);
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child && !key.empty()) {
                         cJSON_AddItemToObject(object.get(), key.c_str(), child.release()); // Transfer ownership
                     }
                 }
             }
             return object;
        }
    }
    return nullptr; // Should not reach here
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a fuzzed value to determine which API or sequence to test
    // Increased selector range to cover more APIs
    uint8_t api_selector = fdp.ConsumeIntegral<uint8_t>();

    // Exercise selected APIs based on coverage reports
    switch (api_selector % 17) { // Increased cases to cover more APIs
        case 0: {
            // cJSON_CreateDoubleArray (low branch coverage)
            // Added inputs to trigger overflow checks
            size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<double> numbers;
            for (size_t i = 0; i < count; ++i) {
                // Add values that might trigger INT_MAX/INT_MIN checks
                uint8_t value_selector = fdp.ConsumeIntegral<uint8_t>();
                if (value_selector % 4 == 0) {
                    numbers.push_back(static_cast<double>(std::numeric_limits<int>::max()));
                } else if (value_selector % 4 == 1) {
                    numbers.push_back(static_cast<double>(std::numeric_limits<int>::min()));
                } else {
                    numbers.push_back(fdp.ConsumeFloatingPoint<double>());
                }
            }
            unique_cJSON_ptr double_array(cJSON_CreateDoubleArray(numbers.data(), count));
            // double_array will be automatically deleted
            break;
        }
        case 1: {
            // cJSON_InsertItemInArray (low fuzz target coverage on null checks)
            // Made base_array and item_to_use creation conditional
            unique_cJSON_ptr base_array = nullptr;
            if (fdp.ConsumeBool()) { // Sometimes create the array
                 base_array.reset(cJSON_CreateArray());
            }

            unique_cJSON_ptr item_to_use = nullptr;
            if (fdp.ConsumeBool()) { // Sometimes create the item
                item_to_use = CreateFuzzedCJSONItem(fdp);
            }

            if (base_array && item_to_use) {
                int index = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(base_array.get()) + 5); // Test out-of-bounds
                // cJSON_InsertItemInArray takes ownership of item_to_use on success
                cJSON_InsertItemInArray(base_array.get(), index, item_to_use.release());
            }
            // base_array and item_to_use (if not transferred) are automatically deleted
            break;
        }
        case 2: {
            // cJSON_DetachItemFromObject (low fuzz target coverage on null checks)
            // Made base_object creation conditional
            unique_cJSON_ptr base_object = nullptr;
            if (fdp.ConsumeBool()) { // Sometimes create the object
                base_object.reset(cJSON_CreateObject());
                 // Add some items to the object if created
                if (base_object && fdp.remaining_bytes() > 0) {
                    size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                    for (size_t i = 0; i < count; ++i) {
                        std::string key = fdp.ConsumeRandomLengthString(10);
                        unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                        if (child && !key.empty()) {
                            cJSON_AddItemToObject(base_object.get(), key.c_str(), child.release()); // Transfer ownership
                        }
                    }
                }
            }

            if (base_object) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                unique_cJSON_ptr detached_item(cJSON_DetachItemFromObject(base_object.get(), key.c_str()));
                // detached_item will be automatically deleted if found and detached
            }
            // base_object is automatically deleted
            break;
        }
        case 3: {
            // cJSON_ReplaceItemInObjectCaseSensitive (low fuzz target coverage on null checks)
            // Made base_object and item_to_use creation conditional
            unique_cJSON_ptr base_object = nullptr;
            if (fdp.ConsumeBool()) { // Sometimes create the object
                 base_object.reset(cJSON_CreateObject());
                 // Add some items to the object if created
                if (base_object && fdp.remaining_bytes() > 0) {
                    size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                    for (size_t i = 0; i < count; ++i) {
                        std::string key = fdp.ConsumeRandomLengthString(10);
                        unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                        if (child && !key.empty()) {
                            cJSON_AddItemToObject(base_object.get(), key.c_str(), child.release()); // Transfer ownership
                        }
                    }
                }
            }

            unique_cJSON_ptr item_to_use = nullptr;
            if (fdp.ConsumeBool()) { // Sometimes create the item
                item_to_use = CreateFuzzedCJSONItem(fdp);
            }

            if (base_object && item_to_use) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                 // cJSON_ReplaceItemInObjectCaseSensitive takes ownership of item_to_use on success
                cJSON_ReplaceItemInObjectCaseSensitive(base_object.get(), key.c_str(), item_to_use.release());
            }
            // base_object and item_to_use (if not transferred) are automatically deleted
            break;
        }
        case 4: {
            // cJSON_Compare (low fuzz target coverage on null checks)
            // Removed fallback creation to allow null inputs
            unique_cJSON_ptr obj1 = nullptr;
            if (fdp.remaining_bytes() > 0 && fdp.ConsumeBool()) { // Sometimes attempt to parse
                 std::string json_string1 = fdp.ConsumeRandomLengthString();
                 if (!json_string1.empty()) {
                     obj1.reset(cJSON_Parse(json_string1.c_str()));
                 }
            }

            unique_cJSON_ptr obj2 = nullptr;
             if (fdp.remaining_bytes() > 0 && fdp.ConsumeBool()) { // Sometimes attempt to parse
                 std::string json_string2 = fdp.ConsumeRandomLengthString();
                 if (!json_string2.empty()) {
                     obj2.reset(cJSON_Parse(json_string2.c_str()));
                 }
            }

            // Perform comparison - now allows obj1 or obj2 to be null
            cJSON_Compare(obj1.get(), obj2.get(), fdp.ConsumeBool());

            // obj1 and obj2 are automatically deleted
            break;
        }
        case 5: {
            // cJSON_SetNumberHelper (0% coverage)
            unique_cJSON_ptr number_item = unique_cJSON_ptr(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
            if (number_item) {
                cJSON_SetNumberHelper(number_item.get(), fdp.ConsumeFloatingPoint<double>());
            }
            // number_item is automatically deleted
            break;
        }
        case 6: {
            // cJSON_DetachItemFromArray (0% coverage)
            unique_cJSON_ptr base_array = unique_cJSON_ptr(cJSON_CreateArray());
            if (base_array && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child) {
                         cJSON_AddItemToArray(base_array.get(), child.release()); // Transfer ownership
                     }
                 }
            }

            if (base_array) {
                int index = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(base_array.get()) + 5);
                unique_cJSON_ptr detached_item(cJSON_DetachItemFromArray(base_array.get(), index));
                // detached_item is automatically deleted
            }
            // base_array is automatically deleted
            break;
        }
         case 7: {
            // cJSON_DeleteItemFromArray (0% coverage)
            unique_cJSON_ptr base_array = unique_cJSON_ptr(cJSON_CreateArray());
            if (base_array && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child) {
                         cJSON_AddItemToArray(base_array.get(), child.release()); // Transfer ownership
                     }
                 }
            }

            if (base_array) {
                int index = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(base_array.get()) + 5);
                cJSON_DeleteItemFromArray(base_array.get(), index); // Function deletes the item
            }
            // base_array is automatically deleted
            break;
        }
        case 8: {
            // cJSON_DetachItemFromObjectCaseSensitive (0% coverage)
            unique_cJSON_ptr base_object = unique_cJSON_ptr(cJSON_CreateObject());
            if (base_object && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     std::string key = fdp.ConsumeRandomLengthString(10);
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child && !key.empty()) {
                         cJSON_AddItemToObject(base_object.get(), key.c_str(), child.release()); // Transfer ownership
                     }
                 }
            }

            if (base_object) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                unique_cJSON_ptr detached_item(cJSON_DetachItemFromObjectCaseSensitive(base_object.get(), key.c_str()));
                 // detached_item is automatically deleted
            }
            // base_object is automatically deleted
            break;
        }
        case 9: {
            // cJSON_DeleteItemFromObject (0% coverage)
            unique_cJSON_ptr base_object = unique_cJSON_ptr(cJSON_CreateObject());
            if (base_object && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     std::string key = fdp.ConsumeRandomLengthString(10);
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child && !key.empty()) {
                         cJSON_AddItemToObject(base_object.get(), key.c_str(), child.release()); // Transfer ownership
                     }
                 }
            }

            if (base_object) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                cJSON_DeleteItemFromObject(base_object.get(), key.c_str()); // Function deletes the item
            }
            // base_object is automatically deleted
            break;
        }
        case 10: {
            // cJSON_DeleteItemFromObjectCaseSensitive (0% coverage)
            unique_cJSON_ptr base_object = unique_cJSON_ptr(cJSON_CreateObject());
            if (base_object && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     std::string key = fdp.ConsumeRandomLengthString(10);
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child && !key.empty()) {
                         cJSON_AddItemToObject(base_object.get(), key.c_str(), child.release()); // Transfer ownership
                     }
                 }
            }

            if (base_object) {
                std::string key = fdp.ConsumeRandomLengthString(20);
                cJSON_DeleteItemFromObjectCaseSensitive(base_object.get(), key.c_str()); // Function deletes the item
            }
            // base_object is automatically deleted
            break;
        }
        case 11: {
            // cJSON_ReplaceItemInArray (0% coverage)
            unique_cJSON_ptr base_array = unique_cJSON_ptr(cJSON_CreateArray());
            if (base_array && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                 for (size_t i = 0; i < count; ++i) {
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child) {
                         cJSON_AddItemToArray(base_array.get(), child.release()); // Transfer ownership
                     }
                 }
            }

            unique_cJSON_ptr new_item = CreateFuzzedCJSONItem(fdp);

            if (base_array && new_item) {
                int index = fdp.ConsumeIntegralInRange<int>(-5, cJSON_GetArraySize(base_array.get()) + 5);
                // cJSON_ReplaceItemInArray takes ownership of new_item
                cJSON_ReplaceItemInArray(base_array.get(), index, new_item.release());
            }
            // base_array and new_item (if not transferred) are automatically deleted
            break;
        }
        case 12: {
            // cJSON_CreateStringReference (0% coverage)
            std::string ref_string = fdp.ConsumeRandomLengthString();
            if (!ref_string.empty()) {
                unique_cJSON_ptr string_ref(cJSON_CreateStringReference(ref_string.c_str()));
                // string_ref is automatically deleted
            }
            break;
        }
        case 13: {
            // cJSON_CreateObjectReference (0% coverage)
            unique_cJSON_ptr base_object = unique_cJSON_ptr(cJSON_CreateObject());
             if (base_object && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 2); // Small object for reference
                 for (size_t i = 0; i < count; ++i) {
                     std::string key = fdp.ConsumeRandomLengthString(5);
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child && !key.empty()) {
                         cJSON_AddItemToObject(base_object.get(), key.c_str(), child.release()); // Transfer ownership
                     }
                 }
            }
            if (base_object) {
                unique_cJSON_ptr object_ref(cJSON_CreateObjectReference(base_object.get()));
                // object_ref is automatically deleted
            }
            // base_object is automatically deleted
            break;
        }
        case 14: {
            // cJSON_CreateArrayReference (0% coverage)
            unique_cJSON_ptr base_array = unique_cJSON_ptr(cJSON_CreateArray());
             if (base_array && fdp.remaining_bytes() > 0) {
                 size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 2); // Small array for reference
                 for (size_t i = 0; i < count; ++i) {
                     unique_cJSON_ptr child = CreateFuzzedCJSONItem(fdp);
                     if (child) {
                         cJSON_AddItemToArray(base_array.get(), child.release()); // Transfer ownership
                     }
                 }
            }
            if (base_array) {
                unique_cJSON_ptr array_ref(cJSON_CreateArrayReference(base_array.get()));
                // array_ref is automatically deleted
            }
            // base_array is automatically deleted
            break;
        }
        case 15: {
            // cJSON_CreateIntArray (0% coverage)
            size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<int> numbers;
            for (size_t i = 0; i < count; ++i) {
                numbers.push_back(fdp.ConsumeIntegral<int>());
            }
            unique_cJSON_ptr int_array(cJSON_CreateIntArray(numbers.data(), count));
            // int_array is automatically deleted
            break;
        }
        case 16: {
            // cJSON_CreateFloatArray (0% coverage)
            size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<float> numbers;
            for (size_t i = 0; i < count; ++i) {
                numbers.push_back(fdp.ConsumeFloatingPoint<float>());
            }
            unique_cJSON_ptr float_array(cJSON_CreateFloatArray(numbers.data(), count));
            // float_array is automatically deleted
            break;
        }
    }

    // All unique_ptr objects go out of scope and are automatically deleted

    return 0;
}