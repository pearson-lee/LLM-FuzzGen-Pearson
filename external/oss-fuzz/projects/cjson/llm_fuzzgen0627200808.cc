#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>

// Include cJSON header
#include "/src/cjson/cJSON.h"

// Custom deleter for cJSON objects to ensure cJSON_Delete is called.
// This prevents memory leaks for cJSON items created during fuzzing.
struct CJSONDeleter {
    void operator()(cJSON* obj) const {
        if (obj) {
            cJSON_Delete(obj);
        }
    }
};

// Custom deleter for char* allocated by cJSON_strdup (or similar cJSON internal allocations).
// This ensures memory allocated by cJSON's internal malloc is freed by cJSON's internal free.
struct CJSONFreeDeleter {
    void operator()(char* ptr) const {
        if (ptr) {
            cJSON_free(ptr);
        }
    }
};

// Global variables for custom allocation hooks.
// These hooks are used to simulate allocation failures, which helps
// achieve better coverage for error handling paths in cJSON.
static cJSON_Hooks global_fuzz_hooks;
static bool fail_allocation = false;
static size_t allocation_fail_counter = 0;
static size_t allocation_fail_at = 0;

// Custom allocation function that can be configured to return NULL
// after a certain number of calls, simulating memory exhaustion.
static void *custom_allocate(size_t size) {
    if (fail_allocation && allocation_fail_counter == allocation_fail_at) {
        return NULL;
    }
    allocation_fail_counter++;
    return malloc(size);
}

// Custom deallocation function, simply calls free.
static void custom_deallocate(void *pointer) {
    free(pointer);
}

// Entry point for the fuzzer. LLVMFuzzerTestOneInput is called repeatedly
// with different input data by the fuzzer engine.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Initialize cJSON with custom allocation hooks.
    // This allows us to control memory allocation behavior during fuzzing.
    global_fuzz_hooks.malloc_fn = custom_allocate;
    global_fuzz_hooks.free_fn = custom_deallocate;
    cJSON_InitHooks(&global_fuzz_hooks);

    // Configure allocation failure for the current fuzzing iteration.
    // This introduces non-determinism in allocation failures, helping to
    // explore different error paths.
    fail_allocation = fdp.ConsumeBool();
    allocation_fail_at = fdp.ConsumeIntegralInRange<size_t>(0, 100); // Fail after N allocations
    allocation_fail_counter = 0; // Reset counter for each new input

    // --- Fuzzing cJSON_CreateTrue and cJSON_CreateFalse ---
    // These functions have a missed branch related to allocation failure.
    // By using custom allocation hooks, we can force cJSON_New_Item (called internally)
    // to return NULL, thereby covering the missed branch.
    {
        std::unique_ptr<cJSON, CJSONDeleter> true_item(cJSON_CreateTrue());
        std::unique_ptr<cJSON, CJSONDeleter> false_item(cJSON_CreateFalse());
    }

    // --- Fuzzing cJSON_SetValuestring ---
    // This function has a missed branch related to `object->valuestring` being NULL
    // during a reallocation scenario. While directly forcing `object->valuestring` to NULL
    // for a valid cJSON_String is complex, we can focus on triggering reallocation.
    {
        std::string initial_string = fdp.ConsumeRandomLengthString(100);
        std::unique_ptr<cJSON, CJSONDeleter> string_item(cJSON_CreateString(initial_string.c_str()));
        if (string_item) {
            // Provide a longer string to trigger reallocation within cJSON_SetValuestring.
            std::string longer_string = fdp.ConsumeRandomLengthString(200);
            cJSON_SetValuestring(string_item.get(), longer_string.c_str());
        }
    }

    // --- Fuzzing cJSON_Compare ---
    // This function has missed branches in its switch statements (default cases).
    // These branches are hit when cJSON objects have invalid or unexpected `type` values.
    {
        // Use FuzzedDataProvider to generate arbitrary type choices, including those
        // that might not correspond to valid cJSON_type enum values.
        int type_choice1 = fdp.ConsumeIntegralInRange<int>(0, 10);
        int type_choice2 = fdp.ConsumeIntegralInRange<int>(0, 10);
        bool case_sensitive = fdp.ConsumeBool();

        std::unique_ptr<cJSON, CJSONDeleter> item1;
        std::unique_ptr<cJSON, CJSONDeleter> item2;

        // Helper lambda to create cJSON items, including those with invalid types
        // to hit the 'default' cases in cJSON_Compare's switch statements.
        auto create_cjson_item = [&](int type_choice) -> cJSON* {
            switch (type_choice) {
                case 0: { // For type_choice = 0, create a valid object and then set an invalid type.
                          // This is crucial for hitting the 'default' branches in cJSON_Compare.
                    cJSON* obj = cJSON_CreateObject();
                    if (obj) {
                        obj->type = fdp.ConsumeIntegral<int>(); // Set an arbitrary, potentially invalid type
                    }
                    return obj;
                }
                case 1: return cJSON_CreateFalse();
                case 2: return cJSON_CreateTrue();
                case 3: return cJSON_CreateNull();
                case 4: return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
                case 5: return cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str());
                case 6: return cJSON_CreateArray();
                case 7: return cJSON_CreateObject();
                case 8: return cJSON_CreateRaw(fdp.ConsumeRandomLengthString(100).c_str());
                default: { // For type_choice > 8, create a valid object and then set an invalid type.
                           // This is crucial for hitting the 'default' branches in cJSON_Compare.
                    cJSON* obj = cJSON_CreateObject();
                    if (obj) {
                        obj->type = fdp.ConsumeIntegral<int>(); // Set an arbitrary, potentially invalid type
                    }
                    return obj;
                }
            }
        };

        item1.reset(create_cjson_item(type_choice1));
        item2.reset(create_cjson_item(type_choice2));

        if (item1 && item2) {
            cJSON_Compare(item1.get(), item2.get(), case_sensitive);
        }
    }

    // --- Fuzzing cJSON_PrintBuffered (to exercise internal `ensure` function) ---
    // The `ensure` function, an internal helper for buffer management, has low coverage.
    // `cJSON_PrintBuffered` uses `ensure` for its internal print buffer.
    // By providing large and varied JSON inputs, we can force `ensure` to perform
    // reallocations and hit its various code paths, including potential failure scenarios
    // due to our custom allocation hooks.
    {
        std::string json_string = fdp.ConsumeRandomLengthString(1024); // Large input to generate complex JSON
        std::unique_ptr<cJSON, CJSONDeleter> parsed_item(cJSON_Parse(json_string.c_str()));

        if (parsed_item) {
            int prebuffer_size = fdp.ConsumeIntegralInRange<int>(0, 2048); // Vary the output buffer size
            cJSON_bool format = fdp.ConsumeBool() ? cJSON_True : cJSON_False;

            // Call cJSON_PrintBuffered, which internally uses `ensure` for its dynamic buffer.
            // The function returns a char* that needs to be freed using cJSON_free.
            std::unique_ptr<char, CJSONFreeDeleter> printed_json(
                cJSON_PrintBuffered(parsed_item.get(), prebuffer_size, format)
            );
        }
    }

    return 0;
}