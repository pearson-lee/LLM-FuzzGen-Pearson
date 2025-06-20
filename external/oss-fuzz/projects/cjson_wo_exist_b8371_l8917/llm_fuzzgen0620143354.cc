#include "/src/cjson/cJSON.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

// Custom deleter for unique_ptr to automatically call cJSON_Delete
struct cJSONDeleter {
  void operator()(cJSON *ptr) const {
    if (ptr) {
      cJSON_Delete(ptr);
    }
  }
};

using cJSONUniquePtr = std::unique_ptr<cJSON, cJSONDeleter>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a cJSON object.
  cJSONUniquePtr root(cJSON_CreateObject());
  if (!root) {
    return 0;
  }

  // Create a key and a value for the initial item.
  std::string key = fdp.ConsumeRandomLengthString(10);
  std::string value = fdp.ConsumeRandomLengthString(20);

  // Add an item to the object.
  cJSON_AddItemToObject(root.get(), key.c_str(), cJSON_CreateString(value.c_str()));

  // Create a replacement item.
  cJSONUniquePtr replacement(cJSON_CreateString(fdp.ConsumeRandomLengthString(20).c_str()));
  if (!replacement) {
    return 0;
  }

  // Target the low-coverage function `replace_item_in_object`.
  // The following calls are designed to hit branches that were previously missed.
  if (fdp.ConsumeBool()) {
    // Call with a NULL string to hit the `string == NULL` branch.
    if (fdp.ConsumeBool()) {
      cJSON_ReplaceItemInObjectCaseSensitive(root.get(), nullptr, replacement.get());
    } else {
      cJSON_ReplaceItemInObject(root.get(), nullptr, replacement.get());
    }
  } else if (fdp.ConsumeBool()) {
    // Call with a NULL replacement to hit the `replacement == NULL` branch.
    if (fdp.ConsumeBool()) {
      cJSON_ReplaceItemInObjectCaseSensitive(root.get(), key.c_str(), nullptr);
    } else {
      cJSON_ReplaceItemInObject(root.get(), key.c_str(), nullptr);
    }
  } else {
    // Normal call to `replace_item_in_object`.
    // The replacement item is now owned by the object, so we release it from the unique_ptr.
    if (fdp.ConsumeBool()) {
        if (cJSON_ReplaceItemInObjectCaseSensitive(root.get(), key.c_str(), replacement.get())) {
            replacement.release();
        }
    } else {
        if (cJSON_ReplaceItemInObject(root.get(), key.c_str(), replacement.get())) {
            replacement.release();
        }
    }
  }

  // Target the low-coverage function `cJSON_SetValuestring`.
  cJSON *item = cJSON_GetObjectItem(root.get(), key.c_str());
  if (item) {
    cJSON_SetValuestring(item, fdp.ConsumeRandomLengthString(20).c_str());
  }

  // Target the low-coverage function `cJSON_PrintBuffered`.
  char *printed_json = cJSON_PrintBuffered(root.get(), fdp.ConsumeIntegralInRange<int>(256, 1024), fdp.ConsumeBool());
  if (printed_json) {
    // Free the buffer allocated by cJSON_PrintBuffered.
    cJSON_free(printed_json);
  }

  return 0;
}