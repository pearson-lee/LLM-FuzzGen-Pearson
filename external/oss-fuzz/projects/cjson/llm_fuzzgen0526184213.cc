#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h" // Main cJSON header

// Custom deleter for cJSON objects to ensure cJSON_Delete is called.
// This is crucial for memory safety and preventing leaks.
struct CJSONDeleter {
    void operator()(cJSON* json) const {
        if (json) {
            cJSON_Delete(json);
        }
    }
};
// Define a unique_ptr type for cJSON objects with the custom deleter.
using unique_cJSON_ptr = std::unique_ptr<cJSON, CJSONDeleter>;

// Helper function to create a fuzzed cJSON item.
// This function's source was provided in the API information and has 0% runtime coverage.
// It's included here to ensure it's exercised and to generate diverse cJSON structures
// for the other target APIs.
cJSON *CreateFuzzedCjsonItem(FuzzedDataProvider &fdp) {
    // Consume an integral to determine the type of cJSON item to create.
    // The range covers Object, Array, String, Number, Bool, Null, Raw.
    int type_choice = fdp.ConsumeIntegralInRange<int>(0, 6);
    switch (type_choice) {
        case 0: return cJSON_CreateObject();
        case 1: return cJSON_CreateArray();
        // Consume a random length string for string and raw types.
        case 2: return cJSON_CreateString(fdp.ConsumeRandomLengthString(32).c_str());
        // Consume a floating point number for number type.
        case 3: return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
        // Consume a boolean for bool type.
        case 4: return cJSON_CreateBool(fdp.ConsumeBool());
        case 5: return cJSON_CreateNull();
        case 6: return cJSON_CreateRaw(fdp.ConsumeRandomLengthString(32).c_str());
        default: return nullptr; // Should not happen with the given range.
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Create a root cJSON object to perform operations on.
    // Using unique_cJSON_ptr ensures automatic deletion and memory safety.
    unique_cJSON_ptr root_item(CreateFuzzedCjsonItem(fdp));
    if (!root_item) {
        // If root_item creation fails, there's nothing to fuzz.
        // This branch (lines 52-53) was previously uncovered.
        return 0;
    }

    // Fuzzing loop: continue as long as there's enough fuzzed data remaining.
    // This allows for multiple operations on the same cJSON structure,
    // increasing the chances of finding state-related bugs.
    while (fdp.remaining_bytes() > 0) {
        // Select one of the target APIs to call.
        // The actions are mapped to the selected low-coverage APIs.
        // Increased range to include new actions.
        int action = fdp.ConsumeIntegralInRange<int>(0, 7);

        switch (action) {
            case 0: { // Target API: cJSON_ReplaceItemInObject (exercises internal replace_item_in_object)
                // This API is chosen because it calls the low-coverage internal function
                // `replace_item_in_object` (47.05% coverage).
                if (root_item->type == cJSON_Object) {
                    std::string key = fdp.ConsumeRandomLengthString(16); // Fuzz the key string
                    unique_cJSON_ptr new_item(CreateFuzzedCjsonItem(fdp)); // Create a new item to replace with
                    if (new_item) {
                        // cJSON_ReplaceItemInObject takes ownership of `new_item` only on success.
                        // If it fails, `new_item` must be deleted by the unique_ptr.
                        if (!cJSON_ReplaceItemInObject(root_item.get(), key.c_str(), new_item.get())) {
                            // If replacement failed, the item was not adopted, so delete it.
                            // The unique_ptr will handle deletion when it goes out of scope.
                        } else {
                            // If replacement succeeded, release ownership from unique_ptr.
                            new_item.release();
                        }
                    }
                }
                break;
            }
            case 1: { // Target API: cJSON_AddItemReferenceToArray (57.14% coverage)
                if (root_item->type == cJSON_Array) {
                    unique_cJSON_ptr item_to_add(CreateFuzzedCjsonItem(fdp)); // Create an item to add
                    if (item_to_add) {
                        // cJSON_AddItemReferenceToArray creates a reference, meaning it does not take
                        // ownership of `item_to_add`. Therefore, `item_to_add` remains managed by its
                        // unique_ptr and will be deleted when it goes out of scope.
                        cJSON_AddItemReferenceToArray(root_item.get(), item_to_add.get());
                    }
                }
                // Added call with NULL array to cover lines 2080-2082 in cJSON_AddItemReferenceToArray.
                else if (fdp.ConsumeBool()) {
                    unique_cJSON_ptr item_to_add(CreateFuzzedCjsonItem(fdp));
                    if (item_to_add) {
                        cJSON_AddItemReferenceToArray(nullptr, item_to_add.get());
                    }
                }
                break;
            }
            case 2: { // Target API: cJSON_ReplaceItemInArray (57.14% coverage)
                if (root_item->type == cJSON_Array && cJSON_GetArraySize(root_item.get()) > 0) {
                    // Fuzz the index within the bounds of the array size.
                    int index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(root_item.get()) - 1);
                    unique_cJSON_ptr new_item(CreateFuzzedCjsonItem(fdp)); // Create a new item for replacement
                    if (new_item) {
                        // cJSON_ReplaceItemInArray takes ownership of `new_item` only on success.
                        // If it fails, `new_item` must be deleted by the unique_ptr.
                        if (!cJSON_ReplaceItemInArray(root_item.get(), index, new_item.get())) {
                            // If replacement failed, the item was not adopted, so delete it.
                            // The unique_ptr will handle deletion when it goes out of scope.
                        } else {
                            // If replacement succeeded, release ownership from unique_ptr.
                            new_item.release();
                        }
                    }
                }
                break;
            }
            case 3: { // Target API: cJSON_DetachItemFromArray (57.14% coverage)
                if (root_item->type == cJSON_Array && cJSON_GetArraySize(root_item.get()) > 0) {
                    // Fuzz the index within the bounds of the array size.
                    int index = fdp.ConsumeIntegralInRange<int>(0, cJSON_GetArraySize(root_item.get()) - 1);
                    // cJSON_DetachItemFromArray returns the detached item, which now needs to be
                    // explicitly deleted. Assigning it to a unique_cJSON_ptr ensures this.
                    unique_cJSON_ptr detached_item(cJSON_DetachItemFromArray(root_item.get(), index));
                    // `detached_item` will be automatically deleted when it goes out of scope.
                }
                // Added call with negative index to cover lines 2244-2246 in cJSON_DetachItemFromArray.
                else if (fdp.ConsumeBool()) {
                    unique_cJSON_ptr detached_item(cJSON_DetachItemFromArray(root_item.get(), fdp.ConsumeIntegralInRange<int>(-10, -1)));
                }
                // Added call with NULL array to cover lines 2208-2210 in cJSON_DetachItemViaPointer.
                else if (fdp.ConsumeBool()) {
                    unique_cJSON_ptr detached_item(cJSON_DetachItemFromArray(nullptr, 0));
                }
                break;
            }
            case 4: { // Target API: CreateFuzzedCjsonItem (0.0% coverage)
                // This case explicitly calls CreateFuzzedCjsonItem to ensure its internal paths
                // are thoroughly fuzzed, as it had 0% runtime coverage.
                // The created item is immediately managed by a unique_ptr and deleted.
                unique_cJSON_ptr temp_item(CreateFuzzedCjsonItem(fdp));
                // `temp_item` will be automatically deleted when it goes out of scope.
                break;
            }
            case 5: { // New Target API: cJSON_AddStringToObject (to improve cJSON_Delete and cJSON_strdup coverage)
                // This action aims to cover lines 269-272 in cJSON_Delete and lines 194-196, 201-203 in cJSON_strdup.
                // It also helps cover add_item_to_object's else branch (lines 1994-2002).
                if (root_item->type == cJSON_Object) {
                    std::string key = fdp.ConsumeRandomLengthString(16);
                    std::string value = fdp.ConsumeRandomLengthString(32);
                    // cJSON_AddStringToObject creates a new item and adds it, taking ownership.
                    // No unique_ptr release needed here as it's handled internally.
                    cJSON_AddStringToObject(root_item.get(), key.c_str(), value.c_str());
                }
                // Added call with NULL string to cover lines 2486-2489 in cJSON_CreateString and 194-196 in cJSON_strdup.
                else if (fdp.ConsumeBool()) {
                    std::string key = fdp.ConsumeRandomLengthString(16);
                    unique_cJSON_ptr temp_item(cJSON_CreateString(nullptr));
                }
                break;
            }
            case 6: { // New Target API: cJSON_GetArraySize (to cover NULL input branch)
                // This action aims to cover lines 1852-1854 in cJSON_GetArraySize.
                if (fdp.ConsumeBool()) {
                    cJSON_GetArraySize(nullptr);
                } else if (root_item->type == cJSON_Array) {
                    cJSON_GetArraySize(root_item.get());
                }
                break;
            }
            case 7: { // New Target API: cJSON_DetachItemViaPointer (to cover various branches)
                // This action aims to cover multiple branches in cJSON_DetachItemViaPointer.
                if (root_item->type == cJSON_Array && cJSON_GetArraySize(root_item.get()) > 0) {
                    int array_size = cJSON_GetArraySize(root_item.get());
                    // Try to detach the first item (item == parent->child)
                    if (fdp.ConsumeBool() && array_size > 0) {
                        unique_cJSON_ptr detached_item(cJSON_DetachItemViaPointer(root_item.get(), root_item->child));
                    }
                    // Try to detach a middle item (item != parent->child, item->next != NULL)
                    else if (fdp.ConsumeBool() && array_size > 1) {
                        unique_cJSON_ptr detached_item(cJSON_DetachItemViaPointer(root_item.get(), root_item->child->next));
                    }
                    // Try to detach the last item (item->next == NULL, item != parent->child)
                    else if (fdp.ConsumeBool() && array_size > 0) {
                        cJSON* last_item = root_item->child;
                        while (last_item && last_item->next) {
                            last_item = last_item->next;
                        }
                        if (last_item && last_item != root_item->child) {
                            unique_cJSON_ptr detached_item(cJSON_DetachItemViaPointer(root_item.get(), last_item));
                        }
                    }
                }
                // Try to detach with NULL parent or item to cover lines 2208-2210.
                else if (fdp.ConsumeBool()) {
                    unique_cJSON_ptr temp_item(CreateFuzzedCjsonItem(fdp));
                    unique_cJSON_ptr detached_item(cJSON_DetachItemViaPointer(nullptr, temp_item.get()));
                }
                else if (fdp.ConsumeBool()) {
                    unique_cJSON_ptr detached_item(cJSON_DetachItemViaPointer(root_item.get(), nullptr));
                }
                break;
            }
        }
    }

    // The `root_item` unique_ptr will automatically call CJSONDeleter::operator()
    // when it goes out of scope, ensuring all allocated resources are freed.
    return 0;
}