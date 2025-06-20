#include "/src/cjson/cJSON.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>

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
    // Added call with NULL to hit the valuestring == NULL branch in cJSON_SetValuestring
    cJSON_SetValuestring(item, nullptr);
    cJSON_SetValuestring(item, fdp.ConsumeRandomLengthString(20).c_str());
  }

  // Added call to cJSON_SetValuestring on a non-string item to hit the type-check branch.
  cJSON* number_item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
  cJSON_AddItemToObject(root.get(), "number_key", number_item);
  cJSON_SetValuestring(number_item, "should fail");

  // Added call to cJSON_AddNumberToObject with a NULL name to hit an error-handling branch.
  cJSON_AddNumberToObject(root.get(), nullptr, fdp.ConsumeFloatingPoint<double>());


  // Target the low-coverage function `cJSON_PrintBuffered`.
  char *printed_json = cJSON_PrintBuffered(root.get(), fdp.ConsumeIntegralInRange<int>(256, 1024), fdp.ConsumeBool());
  if (printed_json) {
    // Free the buffer allocated by cJSON_PrintBuffered.
    cJSON_free(printed_json);
  }

  // Added call to cJSON_PrintBuffered with an invalid item to hit error-handling branches.
  cJSONUniquePtr invalid_item(cJSON_CreateNull());
  if (invalid_item) {
    invalid_item->type = cJSON_Invalid; // Manually make the item invalid.
    char* printed_invalid = cJSON_PrintBuffered(invalid_item.get(), 1024, true);
    if (printed_invalid) {
        cJSON_free(printed_invalid);
    }
  }

  // Added calls to cJSON_Duplicate and cJSON_Compare to increase coverage.
  cJSONUniquePtr duplicated_root(cJSON_Duplicate(root.get(), fdp.ConsumeBool()));
  if (duplicated_root) {
      cJSON_Compare(root.get(), duplicated_root.get(), fdp.ConsumeBool());
  }
  
  // Added call to cJSON_Duplicate with a string reference to hit the cJSON_StringIsConst branch.
  cJSONUniquePtr string_ref_item(cJSON_CreateStringReference("const string"));
  if(string_ref_item) {
      cJSONUniquePtr duplicated_string_ref(cJSON_Duplicate(string_ref_item.get(), fdp.ConsumeBool()));
  }


  return 0;
}