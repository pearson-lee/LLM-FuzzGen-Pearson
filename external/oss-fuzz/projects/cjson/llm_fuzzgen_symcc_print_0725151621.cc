#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <cJSON.h>

// A stateful malloc that fails on the second call.
static int malloc_count = 0;
static void* selective_failing_malloc(size_t size) {
    // The first allocation in print() is for the initial buffer. Let it succeed.
    // The second allocation is the one we want to fail to hit the blocker.
    if (malloc_count == 1) {
        malloc_count++;
        return NULL;
    }
    malloc_count++;
    return malloc(size);
}

static void selective_free(void* ptr) {
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // The input data is not directly used to construct the JSON object
    // because the blocker is about allocation failure, not parsing complex data.
    // We create a simple, constant object to reach the print function.
    cJSON* json = cJSON_CreateString("test_string");
    if (!json) {
        return 0;
    }

    // Reset the allocation counter for this run.
    malloc_count = 0;

    // Install hooks. Providing custom malloc/free disables realloc in cJSON,
    // which is necessary to enter the code path with the target allocation.
    cJSON_Hooks hooks;
    hooks.malloc_fn = selective_failing_malloc;
    hooks.free_fn = selective_free;
    cJSON_InitHooks(&hooks);

    // Call the print function. This will use our selective failing hooks.
    // The function is expected to return NULL because of the allocation failure.
    char* printed_json = cJSON_PrintUnformatted(json);
    if (printed_json) {
        // This block should not be reached. If it is, the allocation did not fail
        // as expected. We must use the installed hooks to free.
        hooks.free_fn(printed_json);
    }

    // Reset hooks to default to allow cJSON_Delete to work correctly.
    cJSON_InitHooks(NULL);
    cJSON_Delete(json);

    return 0;
}