#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Target: cJSON_CreateStringArray, cJSON_CreateDoubleArray, cJSON_PrintBuffered, cJSON_SetValuestring, cJSON_Compare

  // Create a root object to attach other items to.
  cJSON *root = cJSON_CreateObject();
  if (!root) {
    return 0;
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_CreateStringArray
   *           had low branch coverage. The line-level report confirmed this was
   *           at line 2706 (count < 0) and line 2732 (empty array case).
   * IMPLEMENTATION: The following code block calls cJSON_CreateStringArray with
   *                 a negative count, a zero count, and a valid positive count
   *                 to exercise these uncovered paths.
   */
  if (fdp.ConsumeBool()) {
    // Target the count < 0 path.
    cJSON *string_array_neg = cJSON_CreateStringArray(nullptr, -1);
    if (string_array_neg) {
      cJSON_Delete(string_array_neg);
    }
  } else if (fdp.ConsumeBool()) {
    // Target the count = 0 path.
    const char* s_arr[1];
    cJSON *string_array_zero = cJSON_CreateStringArray(s_arr, 0);
     if (string_array_zero) {
      cJSON_Delete(string_array_zero);
    }
  } else {
    // Target the normal execution path.
    int count = fdp.ConsumeIntegralInRange<int>(1, 10);
    std::vector<std::string> strings;
    for (int i = 0; i < count; ++i) {
      strings.push_back(fdp.ConsumeRandomLengthString(20));
    }
    std::vector<const char*> c_strings;
    for (const auto& s : strings) {
        c_strings.push_back(s.c_str());
    }
    cJSON *string_array = cJSON_CreateStringArray(c_strings.data(), count);
    if (string_array) {
      cJSON_AddItemToObject(root, "string_array", string_array);
    }
  }

  /*
   * ANALYSIS: Similar to cJSON_CreateStringArray, cJSON_CreateDoubleArray
   *           showed low coverage in its error handling and empty array paths.
   * IMPLEMENTATION: The following code calls cJSON_CreateDoubleArray with
   *                 a negative count and a valid positive count to improve coverage.
   */
  if (fdp.ConsumeBool()) {
      cJSON *double_array_neg = cJSON_CreateDoubleArray(nullptr, -1);
      if (double_array_neg) {
          cJSON_Delete(double_array_neg);
      }
  } else {
      int count = fdp.ConsumeIntegralInRange<int>(0, 10);
      std::vector<double> doubles;
      for (int i = 0; i < count; ++i) {
          doubles.push_back(fdp.ConsumeFloatingPoint<double>());
      }
      cJSON *double_array = cJSON_CreateDoubleArray(doubles.data(), count);
      if (double_array) {
          cJSON_AddItemToObject(root, "double_array", double_array);
      }
  }

  /*
   * ANALYSIS: The line-level coverage for cJSON_SetValuestring showed that the
   *           branch at L414 `if (object->valuestring == NULL ...)` was never taken.
   * IMPLEMENTATION: A cJSON_String object is created, and its `valuestring` is
   *                 manually set to NULL before calling cJSON_SetValuestring to
   *                 exercise this specific error-handling path.
   */
  cJSON *string_obj = cJSON_CreateString("initial");
  if (string_obj && fdp.ConsumeBool()) {
    free(string_obj->valuestring);
    string_obj->valuestring = NULL;
    std::string new_val = fdp.ConsumeRandomLengthString(20);
    cJSON_SetValuestring(string_obj, new_val.c_str());
  }
  if (string_obj) {
    cJSON_AddItemToObject(root, "string_obj", string_obj);
  }

  /*
   * ANALYSIS: The line-level coverage for cJSON_Compare showed that cJSON_Raw
   *           types were never compared (L3045, L3076).
   * IMPLEMENTATION: Two cJSON_Raw objects are created with fuzzed data and
   *                 then compared using cJSON_Compare to cover this case.
   */
  std::string raw_str1 = fdp.ConsumeRandomLengthString(10);
  std::string raw_str2 = fdp.ConsumeRandomLengthString(10);
  cJSON *raw1 = cJSON_CreateRaw(raw_str1.c_str());
  cJSON *raw2 = cJSON_CreateRaw(raw_str2.c_str());
  if (raw1 && raw2) {
    cJSON_Compare(raw1, raw2, fdp.ConsumeBool());
  }
  if (raw1) cJSON_Delete(raw1);
  if (raw2) cJSON_Delete(raw2);

  /*
   * ANALYSIS: The line-level coverage for cJSON_PrintBuffered showed that the
   *           `prebuffer < 0` check at L1289 was never hit.
   * IMPLEMENTATION: The code calls cJSON_PrintBuffered with a negative
   *                 prebuffer size to exercise this error path.
   */
  if (fdp.ConsumeBool()) {
      char *out_neg = cJSON_PrintBuffered(root, -1, fdp.ConsumeBool());
      if (out_neg) {
          free(out_neg);
      }
  }

  // Normal call to cJSON_PrintBuffered to exercise main logic.
  char *out = cJSON_PrintBuffered(root, fdp.ConsumeIntegralInRange<int>(0, 1024), fdp.ConsumeBool());
  if (out) {
    free(out);
  }

  cJSON_Delete(root);

  return 0;
}