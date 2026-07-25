#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

// Custom memory allocation functions to simulate allocation failures
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

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set up custom memory allocation hooks
    cJSON_Hooks hooks;
    hooks.malloc_fn = failing_malloc;
    hooks.free_fn = failing_free;
    cJSON_InitHooks(&hooks);

    // Consume a boolean to decide whether to simulate an out-of-memory error
    out_of_memory = fdp.ConsumeBool();

    // Create a cJSON object from the fuzzer input
    std::string json_string = fdp.ConsumeRemainingBytesAsString();
    cJSON* json = cJSON_Parse(json_string.c_str());
    if (json == NULL) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_Duplicate_rec had low coverage.
     *           The line-level report confirmed that the circular dependency check at line 2794
     *           was never hit: `if(depth >= CJSON_CIRCULAR_LIMIT)`.
     * IMPLEMENTATION: The following code block creates a deeply nested JSON object and then
     *                 duplicates it, which will exercise the recursion depth check.
     */
    if (fdp.ConsumeBool()) {
        cJSON* deep_json = cJSON_CreateObject();
        cJSON* current = deep_json;
        for (int i = 0; i < CJSON_CIRCULAR_LIMIT + 1; ++i) {
            cJSON* new_obj = cJSON_CreateObject();
            cJSON_AddItemToObject(current, "child", new_obj);
            current = new_obj;
        }
        cJSON* duplicate = cJSON_Duplicate(deep_json, true);
        cJSON_Delete(duplicate);
        cJSON_Delete(deep_json);
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_SetValuestring had a branch
     *           with zero hits at line 414: `if (object->valuestring == NULL || valuestring == NULL)`.
     *           The `object->valuestring == NULL` case was never tested.
     * IMPLEMENTATION: The following code block creates a cJSON string object, manually sets its
     *                 `valuestring` to NULL, and then calls `cJSON_SetValuestring` to cover this case.
     */
    if (fdp.ConsumeBool()) {
        cJSON* string_item = cJSON_CreateString("test");
        if (string_item) {
            free(string_item->valuestring);
            string_item->valuestring = NULL;
            cJSON_SetValuestring(string_item, "new_value");
            cJSON_Delete(string_item);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_CreateStringArray had a branch
     *           with zero hits at line 2706: `if ((count < 0) || (strings == NULL))`. The `count < 0`
     *           case was never tested.
     * IMPLEMENTATION: The following code block calls `cJSON_CreateStringArray` with a negative count
     *                 to exercise this error-handling path.
     */
    if (fdp.ConsumeBool()) {
        const char* strings[] = {"a", "b", "c"};
        cJSON* string_array = cJSON_CreateStringArray(strings, -1);
        if (string_array) {
            cJSON_Delete(string_array);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that the `print` and `ensure` functions
     *           had low coverage. Many uncovered branches were related to allocation failures and
     *           buffer resizing.
     * IMPLEMENTATION: The following code block uses `cJSON_PrintBuffered` with a small prebuffer size (1 byte)
     *                 to force the internal `ensure` function to reallocate memory, thus exercising
     *                 the buffer-growing logic.
     */
    if (fdp.ConsumeBool()) {
        char* printed_json = cJSON_PrintBuffered(json, 1, fdp.ConsumeBool());
        if (printed_json) {
            failing_free(printed_json);
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that the `print` and `ensure` functions
     *           had low coverage. Many uncovered branches were related to allocation failures.
     * IMPLEMENTATION: The following code block uses `cJSON_Print` which internally uses the `print`
     *                 function. By setting `out_of_memory` to true, we can simulate allocation failures
     *                 and exercise the error-handling paths in `print` and `ensure`.
     */
    if (fdp.ConsumeBool()) {
        out_of_memory = true;
        char* printed_json = cJSON_Print(json);
        if (printed_json) {
            failing_free(printed_json);
        }
        out_of_memory = false;
    }

    // Cleanup
    cJSON_Delete(json);

    return 0;
}