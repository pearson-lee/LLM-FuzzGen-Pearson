#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h" // Include the main cJSON header
#include <memory> // For std::unique_ptr
#include <string> // For std::string

// Custom deleter for cJSON objects, to be used with std::unique_ptr
// This ensures that cJSON_Delete is called automatically when a unique_ptr goes out of scope,
// preventing memory leaks.
struct CJSONDeleter {
    void operator()(cJSON* json) const {
        if (json) {
            cJSON_Delete(json);
        }
    }
};

// Define a type alias for unique_ptr with our custom deleter
using unique_cJSON_ptr = std::unique_ptr<cJSON, CJSONDeleter>;

// Helper function to create a fuzzed cJSON object
unique_cJSON_ptr CreateFuzzedCjsonItem(FuzzedDataProvider& fdp) {
    // Randomly choose a type of cJSON object to create
    int type = fdp.ConsumeIntegralInRange<int>(0, 7); // 0-6 for cJSON types, 7 for null

    if (type == 0) { // cJSON_CreateNull
        return unique_cJSON_ptr(cJSON_CreateNull());
    } else if (type == 1) { // cJSON_CreateTrue
        return unique_cJSON_ptr(cJSON_CreateTrue());
    } else if (type == 2) { // cJSON_CreateFalse
        return unique_cJSON_ptr(cJSON_CreateFalse());
    } else if (type == 3) { // cJSON_CreateNumber
        return unique_cJSON_ptr(cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>()));
    } else if (type == 4) { // cJSON_CreateString
        std::string s = fdp.ConsumeRandomLengthString(); // Store string to ensure lifetime
        return unique_cJSON_ptr(cJSON_CreateString(s.c_str()));
    } else if (type == 5) { // cJSON_CreateArray
        unique_cJSON_ptr array(cJSON_CreateArray());
        if (array) {
            // Populate array with random number of items
            int num_items = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_items; ++i) {
                // Recursively create items for the array
                unique_cJSON_ptr item = CreateFuzzedCjsonItem(fdp);
                if (item) {
                    // cJSON_AddItemToArray takes ownership, so release from unique_ptr
                    cJSON_AddItemToArray(array.get(), item.release());
                }
            }
        }
        return array;
    } else if (type == 6) { // cJSON_CreateObject
        unique_cJSON_ptr object(cJSON_CreateObject());
        if (object) {
            // Populate object with random number of key-value pairs
            int num_items = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_items; ++i) {
                std::string key = fdp.ConsumeRandomLengthString(10);
                unique_cJSON_ptr value = CreateFuzzedCjsonItem(fdp);
                if (value) {
                    // cJSON_AddItemToObject takes ownership, so release from unique_ptr
                    cJSON_AddItemToObject(object.get(), key.c_str(), value.release());
                }
            }
        }
        return object;
    } else { // Default to null if type is 7 or invalid
        return unique_cJSON_ptr(cJSON_CreateNull());
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Fuzzing CJSONDeleter::operator()
    // This is implicitly tested by using unique_cJSON_ptr, as it calls the deleter
    // when the unique_ptr goes out of scope. We'll create and destroy some objects.
    {
        unique_cJSON_ptr json_obj1 = CreateFuzzedCjsonItem(fdp);
        unique_cJSON_ptr json_obj2 = CreateFuzzedCjsonItem(fdp);
        // Objects will be deleted when they go out of scope.
    }

    // 2. Fuzzing cJSON_InitHooks
    // This function takes a cJSON_Hooks struct. We'll create a fuzzed version of it.
    cJSON_Hooks hooks;
    hooks.malloc_fn = fdp.ConsumeBool() ? malloc : nullptr; // Fuzz with or without custom malloc
    hooks.free_fn = fdp.ConsumeBool() ? free : nullptr;     // Fuzz with or without custom free

    cJSON_InitHooks(&hooks); // Initialize hooks with fuzzed values

    // 3. Fuzzing print(const const cJSON *, cJSON_bool, const const internal_hooks *)
    // This function is internal and not directly exposed in cJSON.h.
    // However, cJSON_Print and cJSON_PrintBuffered internally use this.
    // We will call cJSON_PrintBuffered to exercise the underlying 'print' function.
    unique_cJSON_ptr json_to_print = CreateFuzzedCjsonItem(fdp);
    if (json_to_print) {
        int buffer_size = fdp.ConsumeIntegralInRange<int>(1, 1024); // Fuzz buffer size
        cJSON_bool formatted = fdp.ConsumeBool() ? cJSON_True : cJSON_False; // Fuzz formatting option

        char* printed_string = cJSON_PrintBuffered(json_to_print.get(), buffer_size, formatted);
        if (printed_string) {
            free(printed_string); // Free the allocated string
        }
    }

    // 4. Fuzzing ensure(const printbuffer *, size_t)
    // This is an internal function related to printbuffer management.
    // It's indirectly covered by calls to cJSON_PrintBuffered, which manages its own printbuffer.
    // To directly exercise it, we would need to expose printbuffer internals, which is not
    // feasible or recommended for a fuzz target. The call to cJSON_PrintBuffered above
    // will exercise the 'ensure' function as part of its buffer management.

    // 5. Fuzzing replace_item_in_object(cJSON *, const char *, cJSON *, cJSON_bool)
    // This is an internal function. The public API `cJSON_ReplaceItemInObject` and
    // `cJSON_ReplaceItemViaPointer` use this. We will use `cJSON_ReplaceItemInObject`
    // to exercise it.
    unique_cJSON_ptr root_object = unique_cJSON_ptr(cJSON_CreateObject());
    if (root_object) {
        // Add some initial items to the object
        cJSON_AddItemToObject(root_object.get(), "key1", cJSON_CreateString("value1"));
        cJSON_AddItemToObject(root_object.get(), "key2", cJSON_CreateNumber(123));

        std::string key_to_replace = fdp.ConsumeRandomLengthString(10);
        unique_cJSON_ptr new_item = CreateFuzzedCjsonItem(fdp);
        cJSON_bool case_sensitive = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

        // Attempt to replace an item in the object
        // Note: The internal `replace_item_in_object` takes a cJSON_bool for case sensitivity.
        // The public `cJSON_ReplaceItemInObject` does not expose this directly.
        // We'll call `cJSON_ReplaceItemInObject` and rely on its internal call to `replace_item_in_object`.
        // To truly fuzz the `case_sensitive` parameter of the internal function, we'd need a custom wrapper
        // or direct access, which is not standard fuzzing practice for internal functions.
        // For now, we'll just call the public API.
        if (new_item) {
            // cJSON_ReplaceItemInObject takes ownership of new_item if successful.
            // If it fails, we need to delete new_item manually.
            cJSON* released_item = new_item.release(); // Release ownership
            if (!cJSON_ReplaceItemInObject(root_object.get(), key_to_replace.c_str(), released_item)) {
                // If replacement failed, delete the item that was released
                cJSON_Delete(released_item);
            }
        }
    }

    return 0;
}