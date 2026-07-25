/* BLOCKER_STRATEGY_CONTRACT
required_state: cJSON_CreateNumber must return NULL due to an allocation failure within the loop of cJSON_CreateDoubleArray.
state_constructor: Use cJSON_InitHooks to install a custom malloc function (failing_malloc) that is statefully programmed to return NULL on the second allocation attempt. The first allocation, for the array object itself, is allowed to succeed.
trigger_api: cJSON_CreateDoubleArray is called with a non-empty array of doubles while the failing malloc hook is active.
preserved_invariants: The FuzzedDataProvider consumption sequence is unchanged. The new logic is added after the original calls to cJSON_CreateDoubleArray and reuses the already-consumed data. The default memory hooks are restored after the targeted call to avoid side effects.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/cjson/cJSON.h"

// Define a simple struct to hold data for cJSON_Create...Array functions
template <typename T>
struct ArrayData {
    std::vector<T> data;
    int count;
};

// Helper to consume array data from FuzzedDataProvider
template <typename T>
ArrayData<T> ConsumeArrayData(FuzzedDataProvider& fdp) {
    // Limit the size to avoid excessive memory consumption
    size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 100);
    std::vector<T> data(count);
    size_t bytes_consumed = fdp.ConsumeData(data.data(), count * sizeof(T));
    // The number of elements is the number of bytes consumed divided by the size of T.
    size_t actual_count = bytes_consumed / sizeof(T);
    data.resize(actual_count);
    return {data, static_cast<int>(actual_count)};
}

// --- START BLOCKER-SPECIFIC HELPERS ---
// Global state for the stateful failing malloc hook.
static int malloc_fail_on_nth_call = -1;
static int malloc_call_count = 0;

// A stateful malloc implementation that fails on a specific call count.
static void* failing_malloc(size_t sz) {
    if (malloc_fail_on_nth_call != -1) {
        malloc_call_count++;
        if (malloc_call_count == malloc_fail_on_nth_call) {
            return NULL;
        }
    }
    return malloc(sz);
}
// --- END BLOCKER-SPECIFIC HELPERS ---


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a root object to attach other items to.
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    if (fdp.ConsumeBool()) {
        auto double_array_data = ConsumeArrayData<double>(fdp);
        cJSON* double_array = cJSON_CreateDoubleArray(double_array_data.data.data(), double_array_data.count);
        if (double_array) cJSON_AddItemToObject(root, "double_array", double_array);

        cJSON* double_array_neg_count = cJSON_CreateDoubleArray(double_array_data.data.data(), -1);
        if (double_array_neg_count) cJSON_Delete(double_array_neg_count);

        cJSON* double_array_null_data = cJSON_CreateDoubleArray(NULL, double_array_data.count);
        if (double_array_null_data) cJSON_Delete(double_array_null_data);

        // --- START BLOCKER-SPECIFIC LOGIC ---
        // The following code is added to trigger an allocation failure within
        // cJSON_CreateDoubleArray. The blocker at cJSON.c:2676 is a null check
        // on the result of cJSON_CreateNumber, which can fail if malloc returns NULL.
        // We install a custom memory hook to force the second allocation to fail.
        // The first allocation (for the array itself) succeeds, while the second
        // (for the first number in the array) fails. This triggers the `if (!n)` branch.
        if (double_array_data.count > 0) {
            cJSON_Hooks hooks;
            hooks.malloc_fn = failing_malloc;
            hooks.free_fn = free;
            cJSON_InitHooks(&hooks);

            // cJSON_CreateArray makes 1 allocation. cJSON_CreateNumber makes another.
            // We target the 2nd allocation to make cJSON_CreateNumber fail inside the loop.
            malloc_call_count = 0;
            malloc_fail_on_nth_call = 2;

            cJSON* double_array_alloc_fail = cJSON_CreateDoubleArray(double_array_data.data.data(), double_array_data.count);
            if (double_array_alloc_fail) {
                cJSON_Delete(double_array_alloc_fail);
            }

            // Restore default hooks and reset state for subsequent fuzz inputs.
            cJSON_InitHooks(NULL);
            malloc_fail_on_nth_call = -1;
        }
        // --- END BLOCKER-SPECIFIC LOGIC ---
    }

    if (fdp.ConsumeBool()) {
        auto float_array_data = ConsumeArrayData<float>(fdp);
        cJSON* float_array = cJSON_CreateFloatArray(float_array_data.data.data(), float_array_data.count);
        if (float_array) cJSON_AddItemToObject(root, "float_array", float_array);
    }

    if (fdp.ConsumeBool()) {
        auto int_array_data = ConsumeArrayData<int>(fdp);
        cJSON* int_array = cJSON_CreateIntArray(int_array_data.data.data(), int_array_data.count);
        if (int_array) cJSON_AddItemToObject(root, "int_array", int_array);
    }

    if (fdp.ConsumeBool()) {
        std::vector<const char*> string_ptrs;
        std::vector<std::string> string_data;
        int count = fdp.ConsumeIntegralInRange(0, 20);
        string_data.reserve(count);
        string_ptrs.reserve(count);
        for (int i = 0; i < count; ++i) {
            string_data.push_back(fdp.ConsumeRandomLengthString(50));
            string_ptrs.push_back(string_data.back().c_str());
        }
        cJSON* string_array = cJSON_CreateStringArray(string_ptrs.data(), count);
        if (string_array) cJSON_AddItemToObject(root, "string_array", string_array);
    }

    char *buffered_print = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange(1, 4096), fdp.ConsumeBool());
    if (buffered_print) {
        cJSON_free(buffered_print);
    }
    char *buffered_print_neg = cJSON_PrintBuffered(root, -1, fdp.ConsumeBool());
    if (buffered_print_neg) {
        // This should not be reached, but free if it is.
        cJSON_free(buffered_print_neg);
    }

    cJSON* true_item = cJSON_CreateTrue();
    if (true_item) cJSON_AddItemToObject(root, "true_item", true_item);

    cJSON* false_item = cJSON_CreateFalse();
    if (false_item) cJSON_AddItemToObject(root, "false_item", false_item);

    // Clean up all memory associated with the root object and its children.
    cJSON_Delete(root);

    return 0;
}
