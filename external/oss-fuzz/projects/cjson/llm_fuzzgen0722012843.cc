#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Custom allocation hooks
static bool should_allocate_fail = false;

static void* failing_malloc(size_t size) {
    if (should_allocate_fail) {
        return NULL;
    }
    return malloc(size);
}

static void failing_free(void* ptr) {
    free(ptr);
}

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set up custom allocation hooks
    cJSON_Hooks hooks;
    hooks.malloc_fn = failing_malloc;
    hooks.free_fn = failing_free;
    cJSON_InitHooks(&hooks);

    // Create a cJSON object to work with
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_PrintBuffered had a branch
     *           with zero hits. The line-level report confirmed this was at line 1295,
     *           in the `if (!p.buffer)` check, which is triggered when allocation fails.
     * IMPLEMENTATION: The following code block sometimes sets should_allocate_fail to true
     *                 to simulate an allocation failure, specifically exercising this
     *                 uncovered error-handling path in cJSON_PrintBuffered.
     */
    if (fdp.ConsumeBool()) {
        should_allocate_fail = true;
        char *printed_json = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange<int>(1, 1024), fdp.ConsumeBool());
        if (printed_json) {
            free(printed_json);
        }
        should_allocate_fail = false;
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_CreateStringReference had a branch
     *           with zero hits. The line-level report confirmed this was at line 2509,
     *           in the `if (item != NULL)` check, which is triggered when allocation fails.
     * IMPLEMENTATION: The following code block sometimes sets should_allocate_fail to true
     *                 to simulate an allocation failure, specifically exercising this
     *                 uncovered error-handling path in cJSON_CreateStringReference.
     */
    if (fdp.ConsumeBool()) {
        should_allocate_fail = true;
        cJSON *string_ref = cJSON_CreateStringReference(fdp.ConsumeRandomLengthString(100).c_str());
        if (string_ref) {
            cJSON_Delete(string_ref);
        }
        should_allocate_fail = false;
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_SetValuestring had a branch
     *           with zero hits. The line-level report confirmed this was at line 437,
     *           in the `if (object->valuestring != NULL)` check.
     * IMPLEMENTATION: The following code creates a cJSON string object, sets its
     *                 `valuestring` to NULL, and then calls cJSON_SetValuestring to
     *                 exercise this previously uncovered path.
     */
    if (fdp.ConsumeBool()) {
        cJSON *string_item = cJSON_CreateString(fdp.ConsumeRandomLengthString(100).c_str());
        if (string_item) {
            // Manually set valuestring to NULL to hit the uncovered branch
            if (string_item->valuestring) {
                free(string_item->valuestring);
                string_item->valuestring = NULL;
            }
            cJSON_SetValuestring(string_item, fdp.ConsumeRandomLengthString(100).c_str());
            cJSON_Delete(string_item);
        }
    }

    cJSON_Delete(root);
    return 0;
}