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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a root object to attach other items to.
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    /*
     * ANALYSIS: The function-level coverage report showed several cJSON_Create...Array
     *           functions (Int, Float, Double, String) with identical low coverage scores
     *           (87.88% line, ~90% branch). The line-level report for cJSON_CreateDoubleArray
     *           revealed an uncovered branch at line 2676, where `n` (a new item) is checked
     *           for NULL after creation. This indicates allocation failures are not being tested.
     *           Additionally, the `if ((count < 0) || (numbers == NULL))` check needs testing.
     * IMPLEMENTATION: The following code calls cJSON_Create...Array functions with various
     *                 inputs to improve coverage.
     *                 1. A valid array of values.
     *                 2. A count of 0, which exercises the path where an empty array is created.
     *                 3. A negative count, to trigger the `count < 0` error handling.
     *                 4. A NULL pointer for the numbers array, to trigger the `numbers == NULL` error handling.
     */
    if (fdp.ConsumeBool()) {
        auto double_array_data = ConsumeArrayData<double>(fdp);
        cJSON* double_array = cJSON_CreateDoubleArray(double_array_data.data.data(), double_array_data.count);
        if (double_array) cJSON_AddItemToObject(root, "double_array", double_array);

        cJSON* double_array_neg_count = cJSON_CreateDoubleArray(double_array_data.data.data(), -1);
        if (double_array_neg_count) cJSON_Delete(double_array_neg_count);

        cJSON* double_array_null_data = cJSON_CreateDoubleArray(NULL, double_array_data.count);
        if (double_array_null_data) cJSON_Delete(double_array_null_data);
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

    /*
     * ANALYSIS: The function-level coverage report showed cJSON_PrintBuffered with 87.50%
     *           line coverage. The line-level report indicated that the `if (prebuffer < 0)`
     *           error handling path at line 1289 was being hit, but the allocation failure
     *           check `if (!p.buffer)` at line 1295 was not.
     * IMPLEMENTATION: This code calls cJSON_PrintBuffered with both a valid prebuffer size
     *                 and a negative prebuffer size to ensure the error path is exercised.
     *                 While allocation failure is hard to trigger, exercising the valid paths
     *                 is still valuable.
     */
    char *buffered_print = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange(1, 4096), fdp.ConsumeBool());
    if (buffered_print) {
        cJSON_free(buffered_print);
    }
    char *buffered_print_neg = cJSON_PrintBuffered(root, -1, fdp.ConsumeBool());
    if (buffered_print_neg) {
        // This should not be reached, but free if it is.
        cJSON_free(buffered_print_neg);
    }


    /*
     * ANALYSIS: The function-level coverage report showed cJSON_CreateTrue and cJSON_CreateFalse
     *           with 50% branch coverage. The line-level report showed that the allocation
     *           failure check `if (item == NULL)` was never being hit.
     * IMPLEMENTATION: While it's not possible to directly force an allocation failure to test
     *                 this branch, we still call cJSON_CreateTrue/False to exercise the successful
     *                 path. These simple calls contribute to overall API coverage.
     */
    cJSON* true_item = cJSON_CreateTrue();
    if (true_item) cJSON_AddItemToObject(root, "true_item", true_item);

    cJSON* false_item = cJSON_CreateFalse();
    if (false_item) cJSON_AddItemToObject(root, "false_item", false_item);

    // Clean up all memory associated with the root object and its children.
    cJSON_Delete(root);

    return 0;
}