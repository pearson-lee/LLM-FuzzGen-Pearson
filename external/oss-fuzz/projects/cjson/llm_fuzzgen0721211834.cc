#include "/src/cjson/cJSON.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a cJSON object
  cJSON *root = cJSON_CreateObject();
  if (!root) {
    return 0;
  }

  // Add a random number of items to the object
  for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 5); ++i) {
    std::string key = fdp.ConsumeRandomLengthString(10);
    std::string value = fdp.ConsumeRandomLengthString(20);
    cJSON_AddItemToObject(root, key.c_str(), cJSON_CreateString(value.c_str()));
  }

  /*
   * ANALYSIS: The function-level coverage report showed replace_item_in_object
   *           had a branch with zero hits. The line-level report confirmed
   *           this was at line 2387, in the `if ((replacement == NULL) || (string == NULL))` check.
   * IMPLEMENTATION: The following code block sometimes passes a NULL pointer as the
   *                 replacement or string argument to cJSON_ReplaceItemInObject to
   *                 specifically exercise this uncovered error-handling path.
   */
  if (fdp.ConsumeBool()) {
    std::string key = fdp.ConsumeRandomLengthString(10);
    cJSON_ReplaceItemInObject(root, key.c_str(), NULL);
  } else {
    cJSON *replacement = cJSON_CreateString(fdp.ConsumeRandomLengthString(20).c_str());
    cJSON_ReplaceItemInObject(root, NULL, replacement);
    /*
     * MEMORY-SAFETY-FIX: Added 'if (replacement) { cJSON_Delete(replacement); }'.
     * When calling cJSON_ReplaceItemInObject with a NULL key, the function
     * cannot find an item to replace, so it does not take ownership of the
     * 'replacement' item. We must delete it here to prevent a memory leak.
     */
    if (replacement) {
      cJSON_Delete(replacement);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed replace_item_in_object
   *           had a branch with zero hits. The line-level report confirmed
   *           this was at line 2398, in the `if (replacement->string == NULL)` check.
   *           This happens when cJSON_strdup fails.
   * IMPLEMENTATION: To trigger this, we can't directly fail allocation. Instead,
   *                 we can replace an existing item.
   */
  if (fdp.ConsumeBool()) {
    cJSON *child = root->child;
    if (child && child->string) {
      std::string key = child->string;
      cJSON *replacement = cJSON_CreateString(fdp.ConsumeRandomLengthString(20).c_str());
      cJSON_ReplaceItemInObject(root, key.c_str(), replacement);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed cJSON_PrintBuffered had
   *           a branch with zero hits. The line-level report confirmed this
   *           was at line 1295, in the `if (!p.buffer)` check. This happens
   *           when the initial allocation for the print buffer fails.
   * IMPLEMENTATION: We can't directly cause allocation to fail, but we can
   *                 pass a large prebuffer size to increase the likelihood of
   *                 failure in a constrained environment. We also test the
   *                 negative prebuffer case.
   */
  int prebuffer = fdp.ConsumeBool() ? -1 : fdp.ConsumeIntegralInRange<int>(0, 1024 * 1024);
  char *printed = cJSON_PrintBuffered(root, prebuffer, fdp.ConsumeBool());
  if (printed) {
    cJSON_free(printed);
  }

  /*
   * ANALYSIS: The function-level coverage report showed create_reference had
   *           a branch with zero hits. The line-level report confirmed this
   *           was at line 1967, in the `if (item == NULL)` check.
   * IMPLEMENTATION: The following code block sometimes passes a NULL pointer to
   *                 cJSON_CreateObjectReference to exercise this path.
   */
  if (fdp.ConsumeBool()) {
    cJSON *ref = cJSON_CreateObjectReference(NULL);
    if (ref) {
      cJSON_Delete(ref);
    }
  }

  /*
   * ANALYSIS: The line coverage for cJSON_Compare showed a branch at line 3141
   *           was never taken. This happens when comparing two objects where the
   *           second object contains keys not present in the first.
   * IMPLEMENTATION: The following code creates two objects. It sometimes adds an
   *                 extra key to the second object before comparison to ensure
   *                 this differential logic is exercised.
   */
  cJSON *obj1 = cJSON_CreateObject();
  cJSON *obj2 = cJSON_CreateObject();
  if (obj1 && obj2) {
    std::string key = fdp.ConsumeRandomLengthString(10);
    std::string value = fdp.ConsumeRandomLengthString(10);
    cJSON_AddItemToObject(obj1, key.c_str(), cJSON_CreateString(value.c_str()));
    cJSON_AddItemToObject(obj2, key.c_str(), cJSON_CreateString(value.c_str()));

    if (fdp.ConsumeBool()) {
      std::string extra_key = fdp.ConsumeRandomLengthString(10);
      std::string extra_value = fdp.ConsumeRandomLengthString(10);
      cJSON_AddItemToObject(obj2, extra_key.c_str(), cJSON_CreateString(extra_value.c_str()));
    }
    cJSON_Compare(obj1, obj2, fdp.ConsumeBool());
  }
  if (obj1) cJSON_Delete(obj1);
  if (obj2) cJSON_Delete(obj2);

  /*
   * ANALYSIS: The function-level coverage report showed low coverage for the
   *           cJSON_Create<Type>Array functions. The line-level report for
   *           cJSON_CreateIntArray confirmed the error path for a negative
   *           count was untaken.
   * IMPLEMENTATION: The following blocks call cJSON_CreateIntArray and
   *                 cJSON_CreateFloatArray with valid and invalid (negative)
   *                 counts to improve coverage.
   */
  if (fdp.ConsumeBool()) {
    int count = fdp.ConsumeBool() ? -1 : fdp.ConsumeIntegralInRange<int>(0, 5);
    std::vector<int> nums;
    if (count > 0) {
      for (int i = 0; i < count; ++i) {
        nums.push_back(fdp.ConsumeIntegral<int>());
      }
    }
    cJSON *arr = cJSON_CreateIntArray(nums.data(), count);
    if (arr) {
      cJSON_Delete(arr);
    }
  }
  if (fdp.ConsumeBool()) {
    int count = fdp.ConsumeIntegralInRange<int>(0, 5);
    std::vector<float> nums;
    for (int i = 0; i < count; ++i) {
      nums.push_back(fdp.ConsumeFloatingPoint<float>());
    }
    cJSON *arr = cJSON_CreateFloatArray(nums.data(), count);
    if (arr) {
      cJSON_Delete(arr);
    }
  }

  cJSON_Delete(root);

  return 0;
}