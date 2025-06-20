#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Custom memory allocation functions to simulate allocation failures
static bool g_fail_malloc = false;
static void* failing_malloc(size_t size) {
    if (g_fail_malloc) {
        return nullptr;
    }
    return malloc(size);
}

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a cJSON object to be printed.
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    // Add a variety of elements to the JSON object.
    cJSON_AddStringToObject(root, "name", fdp.ConsumeRandomLengthString(100).c_str());
    cJSON_AddNumberToObject(root, "number", fdp.ConsumeFloatingPoint<double>());
    cJSON_AddBoolToObject(root, "bool", fdp.ConsumeBool());

    // Decide whether to use a buffered print with a small initial buffer
    // to exercise the buffer growth logic in `ensure`.
    if (fdp.ConsumeBool()) {
        // Use a small buffer size to trigger reallocations.
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 128);
        char *out = cJSON_PrintBuffered(root, buffer_size, fdp.ConsumeBool());
        if (out) {
            free(out);
        }
    }

    // Test the scenario where allocation fails.
    if (fdp.ConsumeBool()) {
        cJSON_Hooks hooks = {
            .malloc_fn = failing_malloc,
            .free_fn = free
        };
        cJSON_InitHooks(&hooks);

        // Trigger an allocation that is expected to fail.
        g_fail_malloc = true;
        char *out_fail = cJSON_PrintBuffered(root, 1, fdp.ConsumeBool());
        if (out_fail) {
            // This part should ideally not be reached if malloc fails.
            free(out_fail);
        }
        g_fail_malloc = false;

        // Reset to default hooks.
        cJSON_InitHooks(NULL);
    }

    // Test cJSON_SetValuestring with a potentially long string.
    cJSON *item = cJSON_GetObjectItem(root, "name");
    if (item) {
        cJSON_SetValuestring(item, fdp.ConsumeRandomLengthString(200).c_str());
    }

    // Clean up the cJSON object.
    cJSON_Delete(root);

    return 0;
}