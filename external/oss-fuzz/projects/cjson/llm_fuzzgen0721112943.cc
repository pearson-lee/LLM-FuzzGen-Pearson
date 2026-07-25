#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/cjson/cJSON.h"

// Custom malloc function for testing cJSON_InitHooks
void *custom_malloc(size_t size) {
    return malloc(size);
}

// Custom free function for testing cJSON_InitHooks
void custom_free(void *ptr) {
    free(ptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Consume data for various operations
  std::string str1 = fdp.ConsumeRandomLengthString(100);
  std::string str2 = fdp.ConsumeRandomLengthString(100);
  const char *error_ptr = nullptr;

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_InitHooks had 0% coverage.
   *           The line-level report confirmed that branches for both NULL and non-NULL
   *           hooks, as well as setting individual allocation functions, were not covered.
   * IMPLEMENTATION: The following code block exercises cJSON_InitHooks. It sometimes
   *                 passes NULL to reset hooks to default. Other times, it passes a
   *                 cJSON_Hooks struct with malloc_fn and free_fn either set or not,
   *                 based on fuzzer input, to cover all branches.
   */
  if (fdp.ConsumeBool()) {
    cJSON_InitHooks(NULL);
  } else {
    cJSON_Hooks hooks;
    hooks.malloc_fn = fdp.ConsumeBool() ? custom_malloc : NULL;
    hooks.free_fn = fdp.ConsumeBool() ? custom_free : NULL;
    cJSON_InitHooks(&hooks);
  }

  // Create a variety of JSON objects for testing
  cJSON *json_num = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
  cJSON *json_str = cJSON_CreateString(fdp.ConsumeRandomLengthString(50).c_str());
  cJSON *json_bool = cJSON_CreateBool(fdp.ConsumeBool());
  cJSON *json_null = cJSON_CreateNull();

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_ParseWithOpts had low
   *           branch coverage. The line-level report confirmed the branch at line 1103,
   *           in the `if (NULL == value)` check, was never taken.
   * IMPLEMENTATION: The following code block sometimes passes a NULL pointer as the first
   *                 argument to cJSON_ParseWithOpts to exercise this uncovered error path.
   */
  cJSON *parsed_json1 = nullptr;
  if (fdp.ConsumeBool()) {
    parsed_json1 = cJSON_ParseWithOpts(NULL, &error_ptr, fdp.ConsumeBool());
  } else {
    parsed_json1 = cJSON_ParseWithOpts(str1.c_str(), &error_ptr, fdp.ConsumeBool());
  }

  cJSON *parsed_json2 = cJSON_Parse(str2.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_Compare had 0% coverage.
   *           The line-level report showed numerous uncovered paths, including NULL
   *           checks, type comparisons, and comparisons of identical objects.
   * IMPLEMENTATION: The following calls to cJSON_Compare are designed to cover these
   *                 paths by comparing various object combinations:
   *                 1. A parsed object against itself (for the identical object check).
   *                 2. Two different parsed objects.
   *                 3. A parsed object against NULL.
   *                 4. Two objects of different, known types.
   */
  if (parsed_json1) {
    cJSON_Compare(parsed_json1, parsed_json1, fdp.ConsumeBool());
  }
  cJSON_Compare(parsed_json1, parsed_json2, fdp.ConsumeBool());
  cJSON_Compare(parsed_json1, NULL, fdp.ConsumeBool());
  cJSON_Compare(json_num, json_str, fdp.ConsumeBool());

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_SetValuestring was
   *           completely uncovered. The line-level report indicated missed branches for
   *           object type checks, NULL value checks, and string length comparisons.
   * IMPLEMENTATION: The following code calls cJSON_SetValuestring on a string object
   *                 with a fuzzer-provided string to cover the main logic. It also
   *                 calls it on a non-string object (json_num) to trigger the type
   *                 check error path.
   */
  if (json_str) {
    std::string new_val = fdp.ConsumeRandomLengthString(50);
    cJSON_SetValuestring(json_str, new_val.c_str());
  }
  // Call on a non-string object to hit the type check branch
  cJSON_SetValuestring(json_num, "should fail");


  /*
   * ANALYSIS: The function-level coverage report showed cJSON_PrintPreallocated was
   *           uncovered. The line-level report showed the initial check for a negative
   *           length or a NULL buffer was never executed.
   * IMPLEMENTATION: The code below calls cJSON_PrintPreallocated with a valid buffer,
   *                 a negative length, and a NULL buffer to ensure these specific
   *                 error-handling branches are exercised.
   */
  if (parsed_json1) {
    std::vector<char> buffer(1024);
    cJSON_PrintPreallocated(parsed_json1, buffer.data(), buffer.size(), fdp.ConsumeBool());
    // Test error conditions
    cJSON_PrintPreallocated(parsed_json1, buffer.data(), -1, fdp.ConsumeBool());
    cJSON_PrintPreallocated(parsed_json1, NULL, buffer.size(), fdp.ConsumeBool());
  }


  // Cleanup: All allocated cJSON objects must be deleted to prevent memory leaks.
  cJSON_Delete(json_num);
  cJSON_Delete(json_str);
  cJSON_Delete(json_bool);
  cJSON_Delete(json_null);
  if (parsed_json1) {
    cJSON_Delete(parsed_json1);
  }
  if (parsed_json2) {
    cJSON_Delete(parsed_json2);
  }
  
  // Reset hooks to default to avoid affecting other fuzz targets
  cJSON_InitHooks(NULL);

  return 0;
}