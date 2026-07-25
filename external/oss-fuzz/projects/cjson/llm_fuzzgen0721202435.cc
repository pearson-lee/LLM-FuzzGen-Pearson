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

  cJSON_Delete(root);

  return 0;
}