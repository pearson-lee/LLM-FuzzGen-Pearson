/* BLOCKER_STRATEGY_CONTRACT
required_state: The `printbuffer` `p` in `ensure` must have `p->hooks.reallocate == NULL`, and the subsequent call to `p->hooks.allocate` must return `NULL`.
state_constructor: First, a cJSON object is created using the default allocators. Then, cJSON hooks are initialized with a custom `malloc_fn` that is programmed to fail on its second call, and a `NULL` `free_fn`. The `NULL` `free_fn` ensures that the internal `reallocate` hook becomes `NULL`.
trigger_api: `cJSON_PrintUnformatted` is called on a cJSON object large enough to require a buffer reallocation. The first allocation (for the initial print buffer) succeeds. The subsequent call to `ensure` for reallocation triggers the second allocation call, which is designed to fail, thus satisfying the predicate.
preserved_invariants: The original FuzzedDataProvider consumption sequence is preserved. The blocker-specific logic is self-contained, creates its own objects, and does not rely on the fuzzer's input data, ensuring seed compatibility.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <string>
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

// Blocker-specific allocation helpers
static int allocation_counter = 0;
static int fail_on_allocation = -1; // -1 means never fail

static void* selective_failing_malloc(size_t size) {
    allocation_counter++;
    if (allocation_counter == fail_on_allocation) {
        return NULL;
    }
    return malloc(size);
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
         * ANALYSIS: The function-level coverage report showed that cJSON_Print was not being called.
         * IMPLEMENTATION: This block calls cJSON_Print to exercise the formatted printing logic.
         */
        char *printed_formatted = cJSON_Print(root);
        if (printed_formatted) {
            /*
             * ANALYSIS: The function-level coverage report showed that cJSON_Minify was completely uncovered.
             * IMPLEMENTATION: This block calls cJSON_Minify on a freshly printed string to exercise the minification logic.
             * The string from cJSON_Print is malloc'd and thus writable, which is required by cJSON_Minify.
             */
            cJSON_Minify(printed_formatted);
            free(printed_formatted);
        }

        /*
         * ANALYSIS: The coverage report for 'create_reference' showed that the NULL check for the 'item' parameter was not covered.
         * IMPLEMENTATION: This block sometimes calls cJSON_CreateArrayReference with a NULL item to exercise this specific error-handling path.
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
    
    /*
     * ANALYSIS: The coverage report for cJSON_ReplaceItemViaPointer showed the 'replacement == NULL' branch was never taken.
     * IMPLEMENTATION: This block creates an object, gets a pointer to an item within it, and calls cJSON_ReplaceItemViaPointer with a NULL replacement to cover this error path.
     */
    cJSON *parent = cJSON_CreateObject();
    if (parent) {
        cJSON_AddItemToObject(parent, "child", cJSON_CreateNumber(42));
        cJSON *child = cJSON_GetObjectItem(parent, "child");
        if (child) {
            cJSON_ReplaceItemViaPointer(parent, child, NULL);
        }
        cJSON_Delete(parent);
    }

    /*
     * ANALYSIS: The function-level coverage report showed that cJSON_Minify's NULL check was not covered.
     * IMPLEMENTATION: This call to cJSON_Minify with a NULL argument specifically targets the initial NULL check in the function.
     */
    cJSON_Minify(NULL);

    // Blocker-specific logic to satisfy the predicate in 'print_value'
    // By calling the printing functions with a NULL item, we ensure the
    // 'item == NULL' condition in 'print_value' is met.
    char *printed_null = cJSON_PrintUnformatted(NULL);
    if (printed_null) {
        free(printed_null);
    }
    printed_null = cJSON_Print(NULL);
    if (printed_null) {
        free(printed_null);
    }
    // Use constant values to avoid altering the fdp stream.
    printed_null = cJSON_PrintBuffered(NULL, 256, true);
    if (printed_null) {
        free(printed_null);
    }


    /*
     * BLOCKER-SPECIFIC LOGIC FOR 'ensure'
     * ANALYSIS: The blocker at cJSON.c:525 is in a branch taken when p->hooks.reallocate is NULL.
     * The predicate 'if (!newbuffer)' is satisfied if p->hooks.allocate then fails.
     * This requires the initial buffer allocation to succeed, but the reallocation to fail.
     * IMPLEMENTATION: We use a selective failing allocator that fails on the 2nd call.
     * We set hooks with this allocator and a NULL free_fn (which makes reallocate NULL).
     * We print a large object to trigger reallocation, causing the 2nd allocation to be called and fail inside ensure().
     */
    {
        // Create the object with default allocators before installing the failing hooks.
        cJSON *obj = cJSON_CreateString(std::string(300, 'A').c_str());
        if (obj) {
            cJSON_Hooks blocker_hooks;
            blocker_hooks.malloc_fn = selective_failing_malloc;
            blocker_hooks.free_fn = NULL; // Makes internal reallocate hook NULL
            cJSON_InitHooks(&blocker_hooks);

            allocation_counter = 0;
            fail_on_allocation = 2; // 1st alloc in print() succeeds, 2nd in ensure() fails

            char *printed = cJSON_PrintUnformatted(obj);
            if (printed) {
                // This path should not be taken if the trigger is successful.
                // The current deallocate hook is 'free', so we can use it.
                cJSON_free(printed);
            }

            // Must delete the object while hooks are still active, as it was created
            // with default allocators and cJSON_Delete will use the hook's free.
            cJSON_Delete(obj);

            fail_on_allocation = -1; // Reset for safety
        }
    }


    // Reset hooks to default for subsequent runs
    cJSON_InitHooks(NULL);

    return 0;
}
