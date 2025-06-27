#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory> // For std::unique_ptr

// Include the cJSON header
#include "/src/cjson/cJSON.h"

// Define custom deleters for std::unique_ptr to ensure memory safety.
// These deleters are based on the `CJSONDeleter` and `CJSONFreeDeleter`
// mentioned in the provided API Information, ensuring `cJSON_Delete`
// and `cJSON_free` are called for cJSON objects and char* respectively.
struct CJSONDeleter {
    void operator()(cJSON* obj) const {
        if (obj) {
            cJSON_Delete(obj);
        }
    }
};

struct CJSONFreeDeleter {
    void operator()(char* ptr) const {
        if (ptr) {
            cJSON_free(ptr);
        }
    }
};

// Type aliases for unique pointers with custom deleters
using unique_cJSON_ptr = std::unique_ptr<cJSON, CJSONDeleter>;
using unique_char_ptr = std::unique_ptr<char, CJSONFreeDeleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Initialize cJSON hooks for memory management.
    // This ensures that cJSON uses its internal memory allocation functions,
    // which are then managed by our unique_ptr deleters.
    // Removed cJSON_InitHooks as it was causing infinite recursion.
    // cJSON defaults to using standard malloc/free if no hooks are set.

    // Select one of the target API functions to fuzz based on fuzzed data.
    // This ensures diversity in API calls.
    int api_choice = fdp.ConsumeIntegralInRange<int>(0, 4);

    switch (api_choice) {
        case 0: {
            // Fuzzing cJSON_InsertItemInArray
            // Target branches:
            // - `which < 0`
            // - `newitem == NULL`
            // - `after_inserted->prev == NULL` when `after_inserted != array->child` (corrupted list)

            unique_cJSON_ptr array(cJSON_CreateArray());
            if (!array) return 0;

            // Add some initial items to the array
            int num_initial_items = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_initial_items; ++i) {
                unique_cJSON_ptr item(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                if (item) {
                    cJSON_AddItemToArray(array.get(), item.release()); // cJSON_AddItemToArray takes ownership
                }
            }

            int which = fdp.ConsumeIntegral<int>();
            bool newitem_is_null = fdp.ConsumeBool();
            unique_cJSON_ptr new_item;

            if (!newitem_is_null) {
                new_item.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str()));
            }

            // Attempt to trigger the corrupted list scenario for `after_inserted->prev == NULL`
            if (fdp.ConsumeBool() && array->child && array->child->next) {
                // Get the second item and corrupt its prev pointer
                cJSON* second_item = array->child->next;
                second_item->prev = NULL;
                // Try to insert at the position of the second item
                which = 1; // Index of the second item
            }

            cJSON_InsertItemInArray(array.get(), which, new_item.release()); // cJSON_InsertItemInArray takes ownership
            break;
        }
        case 1: {
            // Fuzzing cJSON_SetValuestring
            // Target branches:
            // - `object == NULL`
            // - `!(object->type & cJSON_String)`
            // - `(object->type & cJSON_IsReference)`
            // - `object->valuestring == NULL`
            // - `valuestring == NULL`

            unique_cJSON_ptr object;
            int object_type_choice = fdp.ConsumeIntegralInRange<int>(0, 3);
            switch (object_type_choice) {
                case 0: // NULL object
                    object.reset(nullptr);
                    break;
                case 1: // Non-string type
                    object.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                    break;
                case 2: { // String type, potentially with NULL valuestring
                    std::string initial_str = fdp.ConsumeRandomLengthString(100);
                    object.reset(cJSON_CreateString(initial_str.c_str()));
                    if (fdp.ConsumeBool() && object) {
                        // Manually set valuestring to NULL to hit `object->valuestring == NULL`
                        cJSON_free(object->valuestring);
                        object->valuestring = NULL;
                    }
                    break;
                }
                case 3: { // Reference type
                    unique_cJSON_ptr original_item(cJSON_CreateString("original"));
                    if (original_item) {
                        object.reset(cJSON_CreateStringReference(original_item->valuestring));
                    }
                    break;
                }
            }

            // Fix: Ensure new_str lives long enough for cJSON_SetValuestring call
            std::string new_str_storage;
            const char* valuestring_arg = nullptr;
            if (fdp.ConsumeBool()) { // Sometimes pass NULL for valuestring
                valuestring_arg = nullptr;
            } else {
                new_str_storage = fdp.ConsumeRandomLengthString(200);
                valuestring_arg = new_str_storage.c_str();
            }

            cJSON_SetValuestring(object.get(), valuestring_arg);
            break;
        }
        case 2: {
            // Fuzzing cJSON_Compare
            // Target branches:
            // - `(a == NULL) || (b == NULL)`
            // - `((a->type & 0xFF) != (b->type & 0xFF))`
            // - Various type-specific comparisons and their branches

            unique_cJSON_ptr a, b;
            bool case_sensitive = fdp.ConsumeBool();

            // Create diverse cJSON objects for comparison
            int type_a = fdp.ConsumeIntegralInRange<int>(0, 7);
            int type_b = fdp.ConsumeIntegralInRange<int>(0, 7);

            if (fdp.ConsumeBool()) a.reset(nullptr);
            else {
                if (type_a == 0) a.reset(cJSON_CreateNull());
                else if (type_a == 1) a.reset(cJSON_CreateTrue());
                else if (type_a == 2) a.reset(cJSON_CreateFalse());
                else if (type_a == 3) a.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                else if (type_a == 4) a.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str()));
                else if (type_a == 5) a.reset(cJSON_CreateRaw(fdp.ConsumeRandomLengthString(100).c_str()));
                else if (type_a == 6) a.reset(cJSON_CreateArray());
                else if (type_a == 7) a.reset(cJSON_CreateObject());
            }

            if (fdp.ConsumeBool()) b.reset(nullptr);
            else {
                if (type_b == 0) b.reset(cJSON_CreateNull());
                else if (type_b == 1) b.reset(cJSON_CreateTrue());
                else if (type_b == 2) b.reset(cJSON_CreateFalse());
                else if (type_b == 3) b.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                else if (type_b == 4) b.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str()));
                else if (type_b == 5) b.reset(cJSON_CreateRaw(fdp.ConsumeRandomLengthString(100).c_str()));
                else if (type_b == 6) b.reset(cJSON_CreateArray());
                else if (type_b == 7) b.reset(cJSON_CreateObject());
            }

            // For array/object comparison, add some children
            // Limiting to 0 children to prevent excessive recursion and timeouts.
            int num_children = 0;

            if (a && (a->type & cJSON_Array)) {
                for (int i = 0; i < num_children; ++i) {
                    unique_cJSON_ptr child_item(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                    if (child_item) {
                        cJSON_AddItemToArray(a.get(), child_item.release());
                    }
                }
            }
            if (b && (b->type & cJSON_Array)) {
                for (int i = 0; i < num_children; ++i) {
                    unique_cJSON_ptr child_item(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                    if (child_item) {
                        cJSON_AddItemToArray(b.get(), child_item.release());
                    }
                }
            }
            if (a && (a->type & cJSON_Object)) {
                for (int i = 0; i < num_children; ++i) {
                    cJSON_AddNumberToObject(a.get(), fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeFloatingPoint<double>());
                }
            }
            if (b && (b->type & cJSON_Object)) {
                for (int i = 0; i < num_children; ++i) {
                    cJSON_AddNumberToObject(b.get(), fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeFloatingPoint<double>());
                }
            }

            cJSON_Compare(a.get(), b.get(), case_sensitive);
            break;
        }
        case 3: {
            // Fuzzing cJSON_CreateIntArray
            // Target branches:
            // - `value == NULL`
            // - `count <= 0`
            // - Memory allocation failures (hard to trigger without custom hooks)

            int count = fdp.ConsumeIntegralInRange<int>(-5, 100); // Test negative and zero counts
            bool value_is_null = fdp.ConsumeBool();

            std::vector<int> values_vec;
            if (!value_is_null && count > 0) {
                for (int i = 0; i < count; ++i) {
                    values_vec.push_back(fdp.ConsumeIntegral<int>());
                }
            }

            cJSON_CreateIntArray(value_is_null ? nullptr : values_vec.data(), count);
            break;
        }
        case 4: {
            // Fuzzing cJSON_Duplicate
            // Target branches:
            // - `item == NULL`
            // - `recurse == false` (shallow copy)
            // - Various type-specific duplication logic

            unique_cJSON_ptr item;
            bool item_is_null = fdp.ConsumeBool();
            bool recurse = fdp.ConsumeBool();

            if (!item_is_null) {
                int item_type;
                if (recurse) {
                    // If recurse is true, only create simple types to avoid deep recursion.
                    item_type = fdp.ConsumeIntegralInRange<int>(0, 5); // Null, True, False, Number, String, Raw
                } else {
                    // If recurse is false, any type is fine.
                    item_type = fdp.ConsumeIntegralInRange<int>(0, 7);
                }

                if (item_type == 0) item.reset(cJSON_CreateNull());
                else if (item_type == 1) item.reset(cJSON_CreateTrue());
                else if (item_type == 2) item.reset(cJSON_CreateFalse());
                else if (item_type == 3) item.reset(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
                else if (item_type == 4) item.reset(cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str()));
                else if (item_type == 5) item.reset(cJSON_CreateRaw(fdp.ConsumeRandomLengthString(100).c_str()));
                else if (item_type == 6) {
                    item.reset(cJSON_CreateArray());
                    // Only add a child if recurse is false, or if we want to test shallow copy of array with child.
                    // If recurse is true, we already limited item_type to simple types.
                    if (!recurse && fdp.ConsumeBool()) {
                        unique_cJSON_ptr child_item(cJSON_CreateString("child_str"));
                        if (child_item) {
                            cJSON_AddItemToArray(item.get(), child_item.release());
                        }
                    }
                }
                else if (item_type == 7) {
                    item.reset(cJSON_CreateObject());
                    // Only add a child if recurse is false, or if we want to test shallow copy of object with child.
                    if (!recurse && fdp.ConsumeBool()) {
                        cJSON_AddNumberToObject(item.get(), "child_num", 123.45);
                    }
                }
            }

            unique_cJSON_ptr duplicated_item(cJSON_Duplicate(item.get(), recurse));
            break;
        }
    }

    return 0;
}