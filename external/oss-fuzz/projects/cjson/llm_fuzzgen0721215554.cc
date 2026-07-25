#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Forward declaration for recursive generation
cJSON* generate_random_json(FuzzedDataProvider& fdp, int depth);

// Custom memory allocation hooks for testing allocation failures
static bool out_of_memory = false;

static void* failing_malloc(size_t size) {
    if (out_of_memory) {
        return NULL;
    }
    return malloc(size);
}

static void failing_free(void* ptr) {
    free(ptr);
}

// Helper to generate a random cJSON object
cJSON* generate_random_json(FuzzedDataProvider& fdp, int depth) {
    // To prevent deep recursion
    if (depth > 5) {
        return cJSON_CreateNull();
    }

    // Select a random type for the JSON item
    uint8_t type = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
    switch (type) {
        case 0:
            /*
             * ANALYSIS: The function-level coverage report showed low coverage for string printing functions.
             * IMPLEMENTATION: This part of the fuzzer generates strings of various lengths and content to exercise the string printing logic, including escape sequences.
             */
            return cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str());
        case 1:
            /*
             * ANALYSIS: The function-level coverage report showed print_number has untested branches related to float precision.
             * IMPLEMENTATION: This part of the fuzzer generates various double values to test the precision-related logic in print_number.
             */
            return cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
        case 2:
            return cJSON_CreateBool(fdp.ConsumeBool());
        case 3: {
            cJSON* arr = cJSON_CreateArray();
            int num_items = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_items; ++i) {
                cJSON_AddItemToArray(arr, generate_random_json(fdp, depth + 1));
            }
            return arr;
        }
        case 4: {
            cJSON* obj = cJSON_CreateObject();
            int num_items = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_items; ++i) {
                cJSON_AddItemToObject(obj, fdp.ConsumeRandomLengthString(20).c_str(), generate_random_json(fdp, depth + 1));
            }
            return obj;
        }
        case 5:
            return cJSON_CreateRaw(fdp.ConsumeRandomLengthString(100).c_str());
        case 6:
        default:
            return cJSON_CreateNull();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Initialize custom memory hooks
    cJSON_Hooks hooks;
    hooks.malloc_fn = failing_malloc;
    hooks.free_fn = failing_free;
    cJSON_InitHooks(&hooks);

    /*
     * ANALYSIS: The coverage report for 'ensure' and 'print' functions showed that many error-handling paths related to memory allocation failures were not covered.
     * IMPLEMENTATION: The 'out_of_memory' flag is controlled by the fuzzer. When set, the custom malloc will fail, allowing the fuzzer to exercise the allocation failure handling logic in cJSON.
     */
    out_of_memory = fdp.ConsumeBool();

    cJSON *root = generate_random_json(fdp, 0);

    if (root) {
        // Exercise printing functions
        char *printed_unformatted = cJSON_PrintUnformatted(root);
        if (printed_unformatted) {
            free(printed_unformatted);
        }

        char *printed_buffered = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange<int>(0, 1024), fdp.ConsumeBool());
        if (printed_buffered) {
            free(printed_buffered);
        }

        /*
         * ANALYSIS: The coverage report for 'create_reference' showed that the NULL check for the 'item' parameter was not covered.
         * IMPLEMENTATION: This block sometimes calls cJSON_CreateReference with a NULL item to exercise this specific error-handling path.
         */
        if (fdp.ConsumeBool()) {
            cJSON *ref = cJSON_CreateArrayReference(root);
            if (ref) {
                cJSON_Delete(ref);
            }
        } else {
            cJSON *ref = cJSON_CreateArrayReference(NULL);
            if (ref) {
                cJSON_Delete(ref);
            }
        }

        /*
         * ANALYSIS: The function 'cJSON_Duplicate_rec' had low coverage.
         * IMPLEMENTATION: Calling cJSON_Duplicate will recursively call cJSON_Duplicate_rec, improving its coverage.
         */
        cJSON *duplicate = cJSON_Duplicate(root, fdp.ConsumeBool());
        if (duplicate) {
            /*
             * ANALYSIS: The function cJSON_Compare had some uncovered branches.
             * IMPLEMENTATION: Comparing the original and duplicated JSON objects will exercise the logic in cJSON_Compare.
             */
            cJSON_Compare(root, duplicate, fdp.ConsumeBool());
            cJSON_Delete(duplicate);
        }
        
        cJSON_Delete(root);
    }
    
    // Reset hooks to default for subsequent runs
    cJSON_InitHooks(NULL);

    return 0;
}