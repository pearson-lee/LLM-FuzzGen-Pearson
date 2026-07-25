#include <cstddef>
#include <cstdint>
#include <stdlib.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Global flag to control custom malloc behavior
static bool g_fail_malloc = false;

// Custom malloc that can be configured to fail
static void *malloc_sometimes_fails(size_t size) {
    if (g_fail_malloc) {
        return NULL;
    }
    return malloc(size);
}

// Standard free
static void free_wrapper(void *ptr) {
    free(ptr);
}

// Fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    cJSON_Hooks original_hooks = {malloc, free};

    /*
     * ANALYSIS: The coverage report for functions like cJSON_CreateTrue, cJSON_CreateFalse,
     *           cJSON_CreateObject, and cJSON_PrintBuffered shows 0 hits on branches
     *           that handle allocation failures (e.g., when malloc returns NULL).
     * IMPLEMENTATION: The following code block installs custom memory allocation hooks
     *                 that can be deterministically made to fail based on fuzzer input.
     *                 This allows the fuzzer to explore the previously unreachable
     *                 error-handling code paths related to memory allocation failures.
     */
    if (fdp.ConsumeBool()) {
        g_fail_malloc = true;
        cJSON_Hooks failing_hooks = {malloc_sometimes_fails, free_wrapper};
        cJSON_InitHooks(&failing_hooks);
    }

    // Exercise creation functions where allocation might fail
    cJSON *json_true = cJSON_CreateTrue();
    if (json_true) cJSON_Delete(json_true);

    cJSON *json_false = cJSON_CreateFalse();
    if (json_false) cJSON_Delete(json_false);

    cJSON *json_obj = cJSON_CreateObject();
    if (json_obj) cJSON_Delete(json_obj);

    /*
     * ANALYSIS: The line-level coverage report for create_reference shows that the
     *           initial check `if (item == NULL)` is never taken because it's never
     *           called with a NULL argument.
     * IMPLEMENTATION: To cover this branch, we explicitly call cJSON_CreateObjectReference
     *                 with a NULL argument, which directly calls the internal create_reference
     *                 function and triggers the uncovered path.
     */
    cJSON *ref = cJSON_CreateObjectReference(NULL);
    if (ref) cJSON_Delete(ref);

    // Restore original hooks to ensure cleanup happens correctly
    if (g_fail_malloc) {
        cJSON_InitHooks(&original_hooks);
        g_fail_malloc = false;
    }

    /*
     * ANALYSIS: The line-level coverage for the static 'ensure' function, which is
     *           called by printing functions, showed that branches handling very large
     *           allocations (e.g., `needed > INT_MAX / 2`) were not being exercised.
     * IMPLEMENTATION: We create a JSON object with a very large string and then print it
     *                 using cJSON_PrintBuffered. This forces the internal 'ensure' function
     *                 to request a large buffer, thus exercising the code paths for
     *                 handling large memory allocations.
     */
    std::string random_str = fdp.ConsumeRandomLengthString(1024 * 10);
    cJSON *root = cJSON_CreateString(random_str.c_str());
    if (root) {
        // Use a small prebuffer to encourage reallocation
        char *printed_json = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange<int>(1, 1024), fdp.ConsumeBool());
        if (printed_json) {
            // Use the original_hooks' free function for cleanup
            original_hooks.free_fn(printed_json);
        }
        cJSON_Delete(root);
    }

    return 0;
}